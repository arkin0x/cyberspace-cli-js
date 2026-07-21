/**
 * cantor.ts — Cantor pairing and hashing primitives.
 *
 * All integers here are bigint since Cyberspace coordinates exceed 2^53.
 * SHA-256 is a pure-JS synchronous implementation so that this module has zero
 * runtime dependencies and works identically in Node, browsers and workers.
 * (Web Crypto's digest() is async, which would poison every call site.)
 */

/**
 * Cantor pairing function: (a, b) -> N
 */
export function cantorPair(a: bigint, b: bigint): bigint {
  const s = a + b
  return (s * (s + 1n)) / 2n + b
}

/**
 * Convert a non-negative bigint to minimal big-endian bytes.
 */
export function intToBytesBE(n: bigint): Uint8Array {
  if (n < 0n) throw new Error('expected non-negative bigint')
  if (n === 0n) return new Uint8Array([0])
  let hex = n.toString(16)
  if (hex.length % 2 !== 0) hex = '0' + hex
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) hex = '0' + hex
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

// ---------- Pure-JS SHA-256 (synchronous) ----------

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

const rotr = (n: number, x: number): number => ((x >>> n) | (x << (32 - n))) >>> 0
const ch = (x: number, y: number, z: number): number => ((x & y) ^ (~x & z)) >>> 0
const maj = (x: number, y: number, z: number): number => ((x & y) ^ (x & z) ^ (y & z)) >>> 0
const sigma0 = (x: number): number => (rotr(2, x) ^ rotr(13, x) ^ rotr(22, x)) >>> 0
const sigma1 = (x: number): number => (rotr(6, x) ^ rotr(11, x) ^ rotr(25, x)) >>> 0
const gamma0 = (x: number): number => (rotr(7, x) ^ rotr(18, x) ^ (x >>> 3)) >>> 0
const gamma1 = (x: number): number => (rotr(17, x) ^ rotr(19, x) ^ (x >>> 10)) >>> 0

const W = new Uint32Array(64)

/**
 * Synchronous SHA-256. Returns 32 bytes.
 */
export function sha256(data: Uint8Array): Uint8Array {
  const msgLen = data.length
  const bitLen = BigInt(msgLen) * 8n
  const padLen = 64 - ((msgLen + 9) % 64)
  const totalLen = msgLen + 1 + (padLen === 64 ? 0 : padLen) + 8
  const padded = new Uint8Array(totalLen)
  padded.set(data)
  padded[msgLen] = 0x80

  const view = new DataView(padded.buffer)
  view.setUint32(totalLen - 8, Number(bitLen >> 32n))
  view.setUint32(totalLen - 4, Number(bitLen & 0xffffffffn))

  let h0 = 0x6a09e667 >>> 0
  let h1 = 0xbb67ae85 >>> 0
  let h2 = 0x3c6ef372 >>> 0
  let h3 = 0xa54ff53a >>> 0
  let h4 = 0x510e527f >>> 0
  let h5 = 0x9b05688c >>> 0
  let h6 = 0x1f83d9ab >>> 0
  let h7 = 0x5be0cd19 >>> 0

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(offset + i * 4)
    }
    for (let i = 16; i < 64; i++) {
      W[i] = (gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16]) >>> 0
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7

    for (let i = 0; i < 64; i++) {
      const t1 = (h + sigma1(e) + ch(e, f, g) + K[i] + W[i]) >>> 0
      const t2 = (sigma0(a) + maj(a, b, c)) >>> 0
      h = g; g = f; f = e
      e = (d + t1) >>> 0
      d = c; c = b; b = a
      a = (t1 + t2) >>> 0
    }

    h0 = (h0 + a) >>> 0
    h1 = (h1 + b) >>> 0
    h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0
    h5 = (h5 + f) >>> 0
    h6 = (h6 + g) >>> 0
    h7 = (h7 + h) >>> 0
  }

  const result = new Uint8Array(32)
  const rv = new DataView(result.buffer)
  rv.setUint32(0, h0)
  rv.setUint32(4, h1)
  rv.setUint32(8, h2)
  rv.setUint32(12, h3)
  rv.setUint32(16, h4)
  rv.setUint32(20, h5)
  rv.setUint32(24, h6)
  rv.setUint32(28, h7)
  return result
}

export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data))
}

/**
 * SHA-256 of a bigint's minimal big-endian representation, as hex.
 */
export function sha256IntHex(n: bigint): string {
  return sha256Hex(intToBytesBE(n))
}
