import WebSocket from 'ws'
import {
  type GatewayFrame,
  type RequestFrame,
  type ResponseFrame,
  type EventFrame,
  type HelloOk,
  type ChatEvent,
  type AgentEvent,
  type SessionInfo,
  type SessionsListParams,
  type ConnectChallengePayload,
  createConnectParams,
} from './protocol'
import {
  buildSignedDevice,
  clearStoredDeviceToken,
  getOrCreateIdentity,
  loadStoredDeviceToken,
  saveStoredDeviceToken,
} from './device'

const DEFAULT_GATEWAY_URL = process.env.CLAWDBOT_URL || 'ws://127.0.0.1:18789'
const DEFAULT_SCOPES = ['operator.read'] as const

type EventCallback = (event: EventFrame) => void
export type GatewayAuthState =
  | 'unknown'
  | 'authorized'
  | 'unpaired'
  | 'unauthorized'
  | 'degraded'

interface PairingInfo {
  requestId?: string
  message?: string
}

function normalized(value: unknown): string | undefined {
  return typeof value === 'string' ? value.trim() || undefined : undefined
}

function isTrustedLoopback(url: string): boolean {
  try {
    const u = new URL(url)
    return u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '::1'
  } catch {
    return false
  }
}

/** Inline of openclaw selectGatewayConnectAuth / buildGatewayConnectAuth (operator subset). */
function selectConnectAuth(params: {
  envToken?: string
  storedToken?: string
  storedScopes?: string[]
  pendingDeviceTokenRetry?: boolean
  trustedDeviceTokenRetry?: boolean
}) {
  const authToken = normalized(params.envToken)
  const storedToken = normalized(params.storedToken)
  const useRetryToken =
    params.pendingDeviceTokenRetry === true &&
    Boolean(authToken && storedToken && params.trustedDeviceTokenRetry)
  // Reference: resolved when retry OR (!(authToken) && stored)
  const resolvedDeviceToken =
    useRetryToken || (!authToken && storedToken) ? storedToken : undefined
  const usingStoredDeviceToken =
    Boolean(resolvedDeviceToken && storedToken) && resolvedDeviceToken === storedToken
  const selectedToken = authToken ?? resolvedDeviceToken
  return {
    authToken: selectedToken,
    // buildGatewayConnectAuth: deviceToken = authDeviceToken ?? resolvedDeviceToken
    // select sets authDeviceToken only on retry; resolved covers stored-as-primary
    authDeviceToken: (useRetryToken ? storedToken : undefined) ?? resolvedDeviceToken,
    signatureToken: selectedToken ?? null,
    usingStoredDeviceToken,
    /** Stored token is auth.token (no env) — for clear-and-retry path. */
    usingStoredAsPrimary: Boolean(!authToken && selectedToken && selectedToken === storedToken),
    storedScopes: params.storedScopes,
  }
}

function shouldRetryWithDeviceToken(params: {
  retryBudgetUsed: boolean
  currentDeviceToken?: string
  explicitToken?: string
  storedToken?: string
  trustedEndpoint: boolean
  error?: { code?: string; message?: string; details?: unknown }
}): boolean {
  if (
    params.retryBudgetUsed ||
    params.currentDeviceToken ||
    !params.explicitToken ||
    !params.storedToken ||
    !params.trustedEndpoint
  ) {
    return false
  }
  const code = params.error?.code ?? ''
  const message = (params.error?.message ?? '').toLowerCase()
  const details = JSON.stringify(params.error?.details ?? '')
  return (
    code === 'AUTH_TOKEN_MISMATCH' ||
    message.includes('auth_token_mismatch') ||
    message.includes('retry_with_device_token') ||
    details.includes('retry_with_device_token') ||
    details.includes('AUTH_TOKEN_MISMATCH')
  )
}

function shouldRetryClearStoredToken(params: {
  retryBudgetUsed: boolean
  usingStoredAsPrimary: boolean
  envToken?: string
  error?: { code?: string; message?: string; details?: unknown }
}): boolean {
  if (params.retryBudgetUsed || !params.usingStoredAsPrimary || !params.envToken) return false
  const code = params.error?.code ?? ''
  const message = (params.error?.message ?? '').toLowerCase()
  const details = JSON.stringify(params.error?.details ?? '')
  return (
    code === 'AUTH_TOKEN_MISMATCH' ||
    message.includes('auth_token_mismatch') ||
    message.includes('retry_with_device_token') ||
    details.includes('AUTH_TOKEN_MISMATCH')
  )
}

export class ClawdbotClient {
  private ws: WebSocket | null = null
  private requestId = 0
  private pendingRequests = new Map<
    string,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >()
  private eventListeners: EventCallback[] = []
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private _connected = false
  private _connecting = false
  private _authState: GatewayAuthState = 'unknown'
  private _scopes: string[] = []
  private _pairingInfo: PairingInfo | null = null
  private _connectPromiseSettled = false
  private readonly debugEnabled = process.env.CRABWALK_DEBUG_OPENCLAW === '1'
  /** One-shot AUTH_TOKEN_MISMATCH retry within a connect attempt. */
  private _authRetryUsed = false
  private _pendingDeviceTokenRetry = false
  private _lastConnectAuth: {
    authDeviceToken?: string
    usingStoredAsPrimary: boolean
  } | null = null
  private _connectResolve?: (v: HelloOk) => void
  private _connectReject?: (e: Error) => void
  private _connectTimeout?: ReturnType<typeof setTimeout>

  constructor(
    private url: string = DEFAULT_GATEWAY_URL,
    private token?: string
  ) {}

  get connected() {
    return this._connected
  }

  get authState() {
    return this._authState
  }

  get scopes() {
    return [...this._scopes]
  }

  get pairingInfo() {
    return this._pairingInfo
  }

  async connect(): Promise<HelloOk> {
    if (this._connecting || this._connected) {
      return { type: 'hello-ok', protocol: 4 } as HelloOk
    }
    this._connecting = true
    this._connectPromiseSettled = false
    this._authRetryUsed = false
    this._pendingDeviceTokenRetry = false
    this._lastConnectAuth = null
    return new Promise((resolve, reject) => {
      this._connectResolve = resolve
      this._connectReject = reject
      const timeout = setTimeout(() => {
        this._connecting = false
        this.ws?.close()
        if (!this._connectPromiseSettled) {
          this._connectPromiseSettled = true
          reject(new Error('Connection timeout - is openclaw gateway running?'))
        }
      }, 10000)
      this._connectTimeout = timeout

      try {
        this.ws = new WebSocket(this.url)
      } catch (e) {
        clearTimeout(timeout)
        reject(new Error(`Failed to create WebSocket: ${e}`))
        return
      }

      this.ws.once('open', () => {
        this.debugLog('socket open, waiting for connect.challenge')
      })

      this.ws.on('message', (data) => {
        try {
          const raw = data.toString()
          const msg = JSON.parse(raw)

          // Handle challenge-response auth
          if (msg.type === 'event' && msg.event === 'connect.challenge') {
            this.handleChallenge(msg.payload as ConnectChallengePayload)
            return
          }

          this.handleMessage(msg)
        } catch (e) {
          console.error('[openclaw] Failed to parse message:', e)
        }
      })

      this.ws.on('error', (err) => {
        clearTimeout(timeout)
        this._connecting = false
        this.debugLog('socket error before connect', err)
        if (!this._connectPromiseSettled) {
          this._connectPromiseSettled = true
          reject(err)
        }
      })

      this.ws.on('close', (code, reason) => {
        clearTimeout(timeout)
        const wasConnected = this._connected
        const wasConnecting = this._connecting
        this.debugLog('socket close', {
          code,
          reason: reason?.toString?.() ?? '',
          wasConnected,
          wasConnecting,
        })
        this._connected = false
        this._connecting = false
        if (!wasConnected && wasConnecting && !this._connectPromiseSettled) {
          this._connectPromiseSettled = true
          reject(
            new Error(
              `Gateway closed before connect (code ${code}${reason ? `, reason: ${reason.toString()}` : ''})`
            )
          )
        }
        // Only reconnect if we were previously connected and it wasn't a clean close
        if (wasConnected && code !== 1000) {
          this.scheduleReconnect()
        }
      })
    })
  }

  private handleChallenge(challenge: ConnectChallengePayload) {
    if (this.ws?.readyState !== WebSocket.OPEN) {
      return
    }

    const stored = loadStoredDeviceToken()
    const selected = selectConnectAuth({
      envToken: this.token,
      storedToken: stored?.token,
      storedScopes: stored?.scopes,
      pendingDeviceTokenRetry: this._pendingDeviceTokenRetry,
      trustedDeviceTokenRetry: isTrustedLoopback(this.url),
    })

    const scopes =
      selected.usingStoredDeviceToken && stored?.scopes?.length
        ? stored.scopes
        : [...DEFAULT_SCOPES]

    let params = createConnectParams({
      token: selected.authToken,
      deviceToken: selected.authDeviceToken,
      scopes,
    })

    // Payload platform must match client.platform after normalize (createConnectParams sets raw platform)
    try {
      const device = buildSignedDevice({
        challenge,
        token: selected.signatureToken,
        role: params.role,
        scopes: params.scopes,
        clientId: params.client.id,
        clientMode: params.client.mode,
        platform: params.client.platform,
      })
      params = createConnectParams({
        token: selected.authToken,
        deviceToken: selected.authDeviceToken,
        scopes,
        device,
      })
    } catch (error) {
      console.error('[openclaw] Failed to create signed device identity:', error)
    }

    this._lastConnectAuth = {
      authDeviceToken: selected.authDeviceToken,
      usingStoredAsPrimary: selected.usingStoredAsPrimary,
    }

    this.debugLog('sending connect', {
      hasToken: Boolean(params.auth?.token),
      hasDeviceToken: Boolean(params.auth?.deviceToken),
      hasDevice: Boolean(params.device),
      deviceId: params.device?.id,
      usingStored: selected.usingStoredDeviceToken,
      pendingRetry: this._pendingDeviceTokenRetry,
      clientMode: params.client.mode,
      clientPlatform: params.client.platform,
      scopes: params.scopes,
    })

    const response: RequestFrame = {
      type: 'req',
      id: `connect-${Date.now()}`,
      method: 'connect',
      params,
    }

    this.ws.send(JSON.stringify(response))
  }

  private handleConnectFailure(error?: { code?: string; message?: string; details?: unknown }) {
    const stored = loadStoredDeviceToken()
    const trusted = isTrustedLoopback(this.url)
    const last = this._lastConnectAuth

    // Env primary failed → retry once with cached device token
    if (
      shouldRetryWithDeviceToken({
        retryBudgetUsed: this._authRetryUsed,
        currentDeviceToken: last?.authDeviceToken,
        explicitToken: this.token,
        storedToken: stored?.token,
        trustedEndpoint: trusted,
        error,
      })
    ) {
      this._authRetryUsed = true
      this._pendingDeviceTokenRetry = true
      this.debugLog('AUTH_TOKEN_MISMATCH — retrying with device token')
      this.reopenForAuthRetry()
      return
    }

    // Stored primary failed → clear token file, retry once with env token only
    if (
      shouldRetryClearStoredToken({
        retryBudgetUsed: this._authRetryUsed,
        usingStoredAsPrimary: Boolean(last?.usingStoredAsPrimary),
        envToken: this.token,
        error,
      })
    ) {
      this._authRetryUsed = true
      this._pendingDeviceTokenRetry = false
      clearStoredDeviceToken()
      this.debugLog('AUTH_TOKEN_MISMATCH — cleared stored device token, retrying with env')
      this.reopenForAuthRetry()
      return
    }

    const message = error?.message || 'Connect failed'
    this.updateAuthStateFromError(message)
    if (this._connectTimeout) clearTimeout(this._connectTimeout)
    this._connecting = false
    if (!this._connectPromiseSettled) {
      this._connectPromiseSettled = true
      this._connectReject?.(new Error(message))
    }
  }

  /** Re-open socket for one-shot auth retry without settling the outer connect promise. */
  private reopenForAuthRetry() {
    // Detach old socket so its close handler cannot reject the connect promise.
    const old = this.ws
    this.ws = null
    if (old) {
      old.removeAllListeners()
      old.on('error', () => {})
      try {
        old.close()
      } catch {
        // ignore
      }
    }

    this._connected = false
    try {
      this.ws = new WebSocket(this.url)
    } catch (e) {
      this._connecting = false
      if (!this._connectPromiseSettled) {
        this._connectPromiseSettled = true
        this._connectReject?.(new Error(`Failed to create WebSocket for auth retry: ${e}`))
      }
      return
    }

    this.ws.once('open', () => {
      this.debugLog('auth-retry socket open, waiting for connect.challenge')
    })

    this.ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString())
        if (msg.type === 'event' && msg.event === 'connect.challenge') {
          this.handleChallenge(msg.payload as ConnectChallengePayload)
          return
        }
        this.handleMessage(msg)
      } catch (e) {
        console.error('[openclaw] Failed to parse message:', e)
      }
    })

    this.ws.on('error', (err) => {
      this.debugLog('auth-retry socket error', err)
      if (!this._connectPromiseSettled) {
        this._connectPromiseSettled = true
        this._connecting = false
        this._connectReject?.(err instanceof Error ? err : new Error(String(err)))
      }
    })

    this.ws.on('close', (code, reason) => {
      this.debugLog('auth-retry socket close', {
        code,
        reason: reason?.toString?.() ?? '',
      })
      if (this._connecting && !this._connectPromiseSettled && !this._connected) {
        this._connectPromiseSettled = true
        this._connecting = false
        this._connectReject?.(
          new Error(
            `Gateway closed during auth retry (code ${code}${reason ? `, reason: ${reason.toString()}` : ''})`
          )
        )
      }
    })
  }

  private handleMessage(msg: GatewayFrame | HelloOk) {
    if ('type' in msg) {
      switch (msg.type) {
        case 'hello-ok':
          if (this._connectTimeout) clearTimeout(this._connectTimeout)
          this.updateAuthStateFromHello(msg)
          this._connected = true
          this._connecting = false
          this._connectPromiseSettled = true
          this._connectResolve?.(msg)
          break

        case 'res':
          // Check if this is the hello-ok response to our connect request
          if (msg.ok && (msg.payload as HelloOk)?.type === 'hello-ok') {
            if (this._connectTimeout) clearTimeout(this._connectTimeout)
            this.updateAuthStateFromHello(msg.payload as HelloOk)
            this._connected = true
            this._connecting = false
            this._connectPromiseSettled = true
            this._connectResolve?.(msg.payload as HelloOk)
          } else if (!msg.ok && String(msg.id).startsWith('connect-')) {
            this.handleConnectFailure(msg.error)
          } else {
            this.handleResponse(msg)
          }
          break

        case 'event':
          this.handleEvent(msg)
          break

        case 'req':
          // Server shouldn't send requests to us
          break
      }
    }
  }

  private handleResponse(res: ResponseFrame) {
    const pending = this.pendingRequests.get(res.id)
    if (pending) {
      this.pendingRequests.delete(res.id)
      if (res.ok) {
        pending.resolve(res.payload)
      } else {
        const message = res.error?.message || 'Request failed'
        this.updateAuthStateFromError(message)
        pending.reject(new Error(message))
      }
    }
  }

  private handleEvent(event: EventFrame) {
    if (event.event.includes('pair') || event.event.includes('device')) {
      const payload = event.payload as { requestId?: string; message?: string } | undefined
      if (payload?.requestId || payload?.message) {
        this._authState = 'unpaired'
        this._pairingInfo = {
          requestId: payload.requestId,
          message: payload.message,
        }
      }
    }

    for (const listener of this.eventListeners) {
      try {
        listener(event)
      } catch (e) {
        console.error('Event listener error:', e)
      }
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) return
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.connect().catch(console.error)
    }, 5000)
  }

  async request<T>(method: string, params?: unknown): Promise<T> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('Not connected')
    }

    const id = `req-${++this.requestId}`
    const req: RequestFrame = { type: 'req', id, method, params }

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, {
        resolve: resolve as (v: unknown) => void,
        reject,
      })
      this.ws!.send(JSON.stringify(req))

      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id)
          reject(new Error('Request timeout'))
        }
      }, 30000)
    })
  }

  onEvent(callback: EventCallback): () => void {
    this.eventListeners.push(callback)
    return () => {
      const idx = this.eventListeners.indexOf(callback)
      if (idx >= 0) this.eventListeners.splice(idx, 1)
    }
  }

  async listSessions(params?: SessionsListParams): Promise<SessionInfo[]> {
    const result = await this.request<{ sessions: SessionInfo[] }>(
      'sessions.list',
      params
    )
    return result.sessions ?? []
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
    this._connected = false
    this._authState = 'unknown'
    this._scopes = []
    this._pairingInfo = null
  }

  private updateAuthStateFromHello(hello: HelloOk) {
    const scopes = hello.auth?.scopes
    this._scopes = scopes ? [...scopes] : []

    if (hello.auth?.deviceToken) {
      const identity = getOrCreateIdentity()
      saveStoredDeviceToken({
        deviceId: identity.id,
        token: hello.auth.deviceToken,
        role: hello.auth.role,
        scopes: hello.auth.scopes,
        updatedAtMs: Date.now(),
      })
      this.debugLog('persisted device token')
    }

    if (!scopes) {
      this._authState = 'authorized'
      return
    }

    if (scopes.includes('operator.read')) {
      this._authState = 'authorized'
      this._pairingInfo = null
      this.debugLog('authorized scopes', scopes)
      return
    }

    this._authState = scopes.length === 0 ? 'unpaired' : 'degraded'
    this.debugLog('non-authorized scopes', scopes)
  }

  private updateAuthStateFromError(message: string) {
    const lowered = message.toLowerCase()
    if (lowered.includes('missing scope') || lowered.includes('operator.read')) {
      this._authState = 'unpaired'
      const requestId = this.extractRequestId(message)
      this._pairingInfo = {
        requestId: requestId ?? this._pairingInfo?.requestId,
        message,
      }
      return
    }

    if (lowered.includes('unauthorized') || lowered.includes('forbidden')) {
      this._authState = 'unauthorized'
      this._pairingInfo = { message }
    }
  }

  private debugLog(message: string, payload?: unknown) {
    if (!this.debugEnabled) return
    if (payload !== undefined) {
      console.log(`[openclaw][debug] ${message}`, payload)
      return
    }
    console.log(`[openclaw][debug] ${message}`)
  }

  private extractRequestId(message: string): string | undefined {
    const explicitMatch = message.match(/request(?:\s+id)?[:=\s]+([a-zA-Z0-9_-]+)/i)
    if (explicitMatch?.[1]) {
      return explicitMatch[1]
    }

    const uuidMatch = message.match(
      /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i
    )
    return uuidMatch?.[0]
  }
}

// Singleton instance for server use
let clientInstance: ClawdbotClient | null = null

export function getClawdbotEndpoint(): string {
  return DEFAULT_GATEWAY_URL
}

export function getClawdbotClient(): ClawdbotClient {
  if (!clientInstance) {
    const token = process.env.CLAWDBOT_API_TOKEN
    clientInstance = new ClawdbotClient(DEFAULT_GATEWAY_URL, token)
  }
  return clientInstance
}

// Parsed event helpers
export function isChatEvent(
  event: EventFrame
): event is EventFrame & { payload: ChatEvent } {
  return event.event === 'chat' && event.payload != null
}

export function isAgentEvent(
  event: EventFrame
): event is EventFrame & { payload: AgentEvent } {
  return event.event === 'agent' && event.payload != null
}
