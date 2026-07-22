import fs from 'fs'
import path from 'path'
import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  sign,
} from 'crypto'
import type { ConnectChallengePayload, ConnectDevice } from './protocol'

const DATA_DIR = path.join(process.cwd(), 'data')
const DEVICE_IDENTITY_FILE = path.join(DATA_DIR, 'device-identity.json')
const DEVICE_TOKEN_FILE = path.join(DATA_DIR, 'device-token.json')

interface StoredDeviceIdentity {
  id: string
  publicKey: string
  privateKeyPem: string
  createdAt: number
  lastUsedAt: number
}

export interface StoredDeviceToken {
  deviceId: string
  token: string
  role?: string
  scopes?: string[]
  updatedAtMs: number
}

function base64UrlToBuffer(value: string): Buffer {
  const padded = value.padEnd(value.length + ((4 - (value.length % 4)) % 4), '=')
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(base64, 'base64')
}

function base64UrlEncode(value: Buffer): string {
  return value.toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/g, '')
}

function decodePublicKey(value: string): Buffer {
  try {
    const raw = base64UrlToBuffer(value)
    if (raw.length > 0) return raw
  } catch {
    // fallback below
  }
  return Buffer.from(value, 'base64')
}

function fingerprintFromPublicKey(publicKey: string): string {
  const rawPublicKey = decodePublicKey(publicKey)
  return createHash('sha256').update(rawPublicKey).digest('hex')
}

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true })
  }
}

function loadStoredIdentity(): StoredDeviceIdentity | null {
  try {
    if (!fs.existsSync(DEVICE_IDENTITY_FILE)) {
      return null
    }
    const data = JSON.parse(fs.readFileSync(DEVICE_IDENTITY_FILE, 'utf-8')) as StoredDeviceIdentity
    if (!data.publicKey || !data.privateKeyPem) {
      return null
    }
    const canonicalId = fingerprintFromPublicKey(data.publicKey)
    const normalized: StoredDeviceIdentity = {
      ...data,
      id: canonicalId,
    }
    // Auto-migrate legacy id formats to canonical fingerprint.
    if (data.id !== canonicalId) {
      saveStoredIdentity(normalized)
    }
    return normalized
  } catch {
    return null
  }
}

function saveStoredIdentity(identity: StoredDeviceIdentity) {
  ensureDataDir()
  fs.writeFileSync(DEVICE_IDENTITY_FILE, JSON.stringify(identity, null, 2), { mode: 0o600 })
  try {
    fs.chmodSync(DEVICE_IDENTITY_FILE, 0o600)
  } catch {
    // ponytail: chmod best-effort on platforms that ignore mode
  }
}

function generateStoredIdentity(): StoredDeviceIdentity {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicJwk = publicKey.export({ format: 'jwk' })
  if (!publicJwk.x) {
    throw new Error('Failed to export Ed25519 public key')
  }

  const rawPublicKey = base64UrlToBuffer(publicJwk.x)
  const fingerprint = createHash('sha256').update(rawPublicKey).digest('hex')
  const now = Date.now()

  return {
    id: fingerprint,
    publicKey: base64UrlEncode(rawPublicKey),
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    createdAt: now,
    lastUsedAt: now,
  }
}

/** Verbatim from openclaw gateway-client device-auth.ts */
export function normalizeDeviceMetadataForAuth(value?: string | null): string {
  if (typeof value !== 'string') {
    return ''
  }
  const trimmed = value.trim()
  if (!trimmed) {
    return ''
  }
  return trimmed.replace(/[A-Z]/g, (char) => String.fromCharCode(char.charCodeAt(0) + 32))
}

export function buildDeviceAuthPayloadV3(params: {
  deviceId: string
  clientId: string
  clientMode: string
  role: string
  scopes: string[]
  signedAtMs: number
  token?: string | null
  nonce: string
  platform?: string | null
  deviceFamily?: string | null
}): string {
  const scopes = params.scopes.join(',')
  const token = params.token ?? ''
  const platform = normalizeDeviceMetadataForAuth(params.platform)
  const deviceFamily = normalizeDeviceMetadataForAuth(params.deviceFamily)
  return [
    'v3',
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    scopes,
    String(params.signedAtMs),
    token,
    params.nonce,
    platform,
    deviceFamily,
  ].join('|')
}

interface BuildSignedDeviceParams {
  challenge: ConnectChallengePayload
  token: string | null
  role: string
  scopes: string[]
  clientId: string
  clientMode: string
  platform?: string | null
  deviceFamily?: string | null
}

export function getOrCreateIdentity(): StoredDeviceIdentity {
  const existing = loadStoredIdentity()
  if (existing) {
    return existing
  }
  const generated = generateStoredIdentity()
  saveStoredIdentity(generated)
  return generated
}

export function buildSignedDevice(params: BuildSignedDeviceParams): ConnectDevice {
  const nonce = params.challenge.nonce?.trim()
  if (!nonce) {
    throw new Error('connect.challenge nonce is empty — refusing to sign (would fall back to v1)')
  }

  const identity = getOrCreateIdentity()
  const privateKey = createPrivateKey(identity.privateKeyPem)
  const signedAt = Date.now()
  const payload = buildDeviceAuthPayloadV3({
    deviceId: identity.id,
    clientId: params.clientId,
    clientMode: params.clientMode,
    role: params.role,
    scopes: params.scopes,
    signedAtMs: signedAt,
    token: params.token,
    nonce,
    platform: params.platform,
    deviceFamily: params.deviceFamily ?? '',
  })
  const signature = base64UrlEncode(sign(null, Buffer.from(payload, 'utf8'), privateKey))

  identity.lastUsedAt = signedAt
  saveStoredIdentity(identity)

  return {
    id: identity.id,
    publicKey: identity.publicKey,
    signature,
    signedAt,
    nonce,
  }
}

export function loadStoredDeviceToken(): StoredDeviceToken | null {
  try {
    if (!fs.existsSync(DEVICE_TOKEN_FILE)) return null
    const data = JSON.parse(fs.readFileSync(DEVICE_TOKEN_FILE, 'utf-8')) as StoredDeviceToken
    if (!data.token || !data.deviceId) return null
    return data
  } catch {
    return null
  }
}

export function saveStoredDeviceToken(entry: StoredDeviceToken) {
  ensureDataDir()
  fs.writeFileSync(DEVICE_TOKEN_FILE, JSON.stringify(entry, null, 2), { mode: 0o600 })
  try {
    fs.chmodSync(DEVICE_TOKEN_FILE, 0o600)
  } catch {
    // ponytail: chmod best-effort
  }
}

export function clearStoredDeviceToken() {
  try {
    if (fs.existsSync(DEVICE_TOKEN_FILE)) fs.unlinkSync(DEVICE_TOKEN_FILE)
  } catch {
    // ignore
  }
}
