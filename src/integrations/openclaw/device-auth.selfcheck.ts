/**
 * Self-check for v3 device-auth payload (no test framework).
 * Run: node --experimental-strip-types src/integrations/openclaw/device-auth.selfcheck.ts
 */
import {
  buildDeviceAuthPayloadV3,
  normalizeDeviceMetadataForAuth,
} from './device.ts'

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg)
}

const platform = normalizeDeviceMetadataForAuth('Linux')
assert(platform === 'linux', `normalize DeviceMetadata: expected 'linux', got '${platform}'`)

const payload = buildDeviceAuthPayloadV3({
  deviceId: 'abc123',
  clientId: 'cli',
  clientMode: 'cli',
  role: 'operator',
  scopes: ['operator.read'],
  signedAtMs: 1700000000000,
  token: 'tok',
  nonce: 'nonce-1',
  platform: 'Linux',
  deviceFamily: '',
})

const expected =
  'v3|abc123|cli|cli|operator|operator.read|1700000000000|tok|nonce-1|linux|'

assert(payload === expected, `payload mismatch:\n  got: ${payload}\n  exp: ${expected}`)

console.log('device-auth.selfcheck: ok')
