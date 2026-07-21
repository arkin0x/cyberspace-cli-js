/**
 * vectors.test.ts — Golden vector tests ported from the Python test_vectors.py.
 *
 * These MUST produce identical results to the Python implementation.
 * If any test fails, the TypeScript port has a bug.
 */

import { describe, it, expect } from 'vitest'
import {
  cantorPair,
  sha256,
  sha256Hex,
  sha256IntHex,
  bytesToHex,
  hexToBytes,
} from '../src/cantor.js'
import {
  xyzToCoord,
  coordToXyz,
  hexToCoord,
  normalizeHex32,
  type Plane,
} from '../src/coords.js'
import {
  findLcaHeight,
  computeAxisCantor,
  computeMovementProof,
  computeHopProof,
  estimateHopCost,
} from '../src/movement.js'
import { terrainK } from '../src/terrain.js'
import { xyzToSectorId, sectorTag } from '../src/sector.js'

/** Discovery id derivation used throughout the golden vectors. */
const discoveryId = (encryptionKeyHex: string): string =>
  bytesToHex(sha256(hexToBytes(encryptionKeyHex)))

describe('SHA-256 sanity', () => {
  it('hashes the empty string', () => {
    expect(sha256Hex(new Uint8Array(0))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
  })

  it('hashes "abc"', () => {
    expect(sha256Hex(new TextEncoder().encode('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
  })

  it('hashes a multi-block message', () => {
    // 64 bytes exactly, exercising the block-boundary padding path.
    const msg = new TextEncoder().encode('a'.repeat(64))
    expect(sha256Hex(msg)).toBe(
      'ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb',
    )
  })
})

describe('Cantor pairing', () => {
  // pi(a, b) = (a + b)(a + b + 1) / 2 + b.
  //
  // The pre-existing test_vectors.js asserted pi(0,1) = 1 and pi(1,0) = 2,
  // which is the "+ a" convention. That is a transcription error: it never ran,
  // because the file imported from ../src/* while the sources sat at the repo
  // root. Two independent golden vectors settle the convention as "+ b":
  //   pi(100,101) = 20402 ("+ a" would give 20401)
  //   computeAxisCantor(0,3) = 228  ("+ a" would give 172)
  // and every downstream proof hash below depends on it.
  it.each([
    [0n, 0n, 0n],
    [0n, 1n, 2n],
    [1n, 0n, 1n],
    [1n, 1n, 4n],
    [100n, 101n, 20402n],
  ])('pi(%s, %s) = %s', (a, b, expected) => {
    expect(cantorPair(a, b)).toBe(expected)
  })

  it('is asymmetric in the documented direction', () => {
    expect(cantorPair(0n, 1n)).not.toBe(cantorPair(1n, 0n))
  })
})

describe('Coordinate interleave', () => {
  const cases: Array<[bigint, bigint, bigint, Plane]> = [
    [0n, 0n, 0n, 0],
    [1n, 0n, 0n, 0],
    [0n, 1n, 0n, 0],
    [0n, 0n, 1n, 0],
    [100n, 200n, 300n, 0],
    [101n, 200n, 300n, 0],
    [100n, 200n, 300n, 1],
  ]

  it.each(cases)('round-trips (%s, %s, %s) plane %s', (x, y, z, p) => {
    expect(coordToXyz(xyzToCoord(x, y, z, p))).toEqual({ x, y, z, plane: p })
  })

  it('round-trips the maximum axis value', () => {
    const max = (1n << 85n) - 1n
    expect(coordToXyz(xyzToCoord(max, max, max, 1))).toEqual({
      x: max,
      y: max,
      z: max,
      plane: 1,
    })
  })
})

describe('Golden vector: close points cantor', () => {
  const fromHex = normalizeHex32('0x2b50e80')
  const toHex = normalizeHex32('0x2b50e88')

  it('normalizes to 64-char hex', () => {
    expect(fromHex).toBe('0000000000000000000000000000000000000000000000000000000002b50e80')
    expect(toHex).toBe('0000000000000000000000000000000000000000000000000000000002b50e88')
  })

  it('decodes to the expected coordinates', () => {
    expect(coordToXyz(hexToCoord(fromHex))).toEqual({ x: 100n, y: 200n, z: 300n, plane: 0 })
    expect(coordToXyz(hexToCoord(toHex))).toEqual({ x: 101n, y: 200n, z: 300n, plane: 0 })
  })

  it('produces the expected LCA heights and cantor roots', () => {
    const r1 = coordToXyz(hexToCoord(fromHex))
    const r2 = coordToXyz(hexToCoord(toHex))

    expect(findLcaHeight(r1.x, r2.x)).toBe(1)
    expect(findLcaHeight(r1.y, r2.y)).toBe(0)
    expect(findLcaHeight(r1.z, r2.z)).toBe(0)

    const cx = computeAxisCantor(r1.x, r2.x)
    const cy = computeAxisCantor(r1.y, r2.y)
    const cz = computeAxisCantor(r1.z, r2.z)

    expect(cx).toBe(20402n)
    expect(cy).toBe(200n)
    expect(cz).toBe(300n)

    const encryptionKey = sha256IntHex(cantorPair(cantorPair(cx, cy), cz))
    expect(encryptionKey).toBe(
      '4e02171a1986de2299e3abe37a00b419d853da9bcab7139d76189f5506b138f6',
    )
    expect(discoveryId(encryptionKey)).toBe(
      'b3e3141659d48d3f7e39a684ab9f193badc11497ea6c3d0f89fefd8e9dbc85c5',
    )
  })
})

describe('Golden vector: movement proof (0,0,0) -> (3,2,1)', () => {
  const proof = computeMovementProof(0n, 0n, 0n, 3n, 2n, 1n)

  it('matches the documented cantor roots', () => {
    expect(proof.cantorX).toBe(228n)
    expect(proof.cantorY).toBe(228n)
    expect(proof.cantorZ).toBe(2n)
    expect(proof.combined).toBe(5452446953n)
  })

  it('matches the documented proof hash', () => {
    expect(proof.proofHash).toBe(
      '9306cfcf163adfa9a1f34933091a445bbbc77de02a1e504eba9d6bcd5950b414',
    )
  })

  it('round-trips location-based encryption', () => {
    const encryptionKey = sha256IntHex(proof.combined)
    expect(encryptionKey).toBe(proof.proofHash)
    expect(discoveryId(encryptionKey)).toBe(
      '1247b1caeb69145100d6adbb52943c36d72023b10a0f5f434d41311d0b0b339c',
    )
  })
})

describe('Golden vector: large cantor regression', () => {
  it('matches (0->800, 0->900, 0->1000)', () => {
    const cx = computeAxisCantor(0n, 800n)
    const cy = computeAxisCantor(0n, 900n)
    const cz = computeAxisCantor(0n, 1000n)
    const encryptionKey = sha256IntHex(cantorPair(cantorPair(cx, cy), cz))

    expect(encryptionKey).toBe(
      'd1ed6818770b37a3d68c97fd65cd07d3af24a705ef8eb681fea99172b8eadf0d',
    )
    expect(discoveryId(encryptionKey)).toBe(
      '7b67be1e49962882683bc3b3a1be728136754c9fbe9b9a75c4a3e2a629c2d97a',
    )
  })
})

describe('Golden vector: hop proof spec 5.6.1', () => {
  const proof = computeHopProof(0n, 0n, 0n, 4104n, 0n, 0n, 0, '0'.repeat(64), 20)

  it('derives terrain K = 11', () => {
    expect(proof.terrainK).toBe(11)
  })

  it('matches the documented hop proof hash', () => {
    expect(proof.proofHash).toBe(
      'ed9d09ca697b2da29c9d042207ac8ef7aab40f6dde550e6467452aa0e2e8cac6',
    )
  })

  it('reports monotonic progress ending at 1', () => {
    const seen: number[] = []
    computeHopProof(0n, 0n, 0n, 4104n, 0n, 0n, 0, '0'.repeat(64), 20, (f) => seen.push(f))

    expect(seen.length).toBeGreaterThan(0)
    expect(seen[seen.length - 1]).toBe(1)
    for (let i = 1; i < seen.length; i++) {
      expect(seen[i]).toBeGreaterThanOrEqual(seen[i - 1])
    }
    expect(Math.min(...seen)).toBeGreaterThanOrEqual(0)
    expect(Math.max(...seen)).toBeLessThanOrEqual(1)
  })

  it('produces an identical proof whether or not progress is observed', () => {
    const observed = computeHopProof(
      0n, 0n, 0n, 4104n, 0n, 0n, 0, '0'.repeat(64), 20, () => {},
    )
    expect(observed.proofHash).toBe(proof.proofHash)
    expect(observed.hopN).toBe(proof.hopN)
  })
})

describe('Safety: max compute height', () => {
  it('refuses a height above the ceiling', () => {
    expect(() => computeAxisCantor(0n, 1n << 30n, 20)).toThrow(/exceeds maxComputeHeight/)
  })

  it('rejects a malformed previous event id', () => {
    expect(() => computeHopProof(0n, 0n, 0n, 1n, 0n, 0n, 0, 'deadbeef')).toThrow(
      /64 hex chars/,
    )
  })
})

describe('Terrain K', () => {
  it('matches the hop proof vector', () => {
    expect(terrainK(4104n, 0n, 0n, 0)).toBe(11)
  })

  it('stays within [0, 16]', () => {
    for (let i = 0n; i < 128n; i++) {
      const k = terrainK(i * 7919n, i * 104729n, i * 1299709n, 0)
      expect(k).toBeGreaterThanOrEqual(0)
      expect(k).toBeLessThanOrEqual(16)
    }
  })

  it('is deterministic and plane-sensitive', () => {
    expect(terrainK(4104n, 0n, 0n, 0)).toBe(terrainK(4104n, 0n, 0n, 0))
    // Dataspace and ideaspace are independent terrains; equality would mean the
    // plane bit is not reaching the hash.
    const planes = new Set<number>()
    for (let i = 0n; i < 32n; i++) {
      planes.add(terrainK(i, 0n, 0n, 0) === terrainK(i, 0n, 0n, 1) ? 0 : 1)
    }
    expect(planes.has(1)).toBe(true)
  })
})

describe('Sector', () => {
  it('places small coordinates in the origin sector', () => {
    expect(sectorTag(xyzToSectorId(100n, 200n, 300n))).toBe('0-0-0')
  })

  it('places 2^31 in sector 2', () => {
    expect(sectorTag(xyzToSectorId(1n << 31n, 1n << 31n, 1n << 31n))).toBe('2-2-2')
  })
})

describe('Hop cost estimation', () => {
  it('agrees with the real computation on LCA heights and terrain K', () => {
    const est = estimateHopCost(0n, 0n, 0n, 4104n, 0n, 0n, 0)
    const proof = computeHopProof(0n, 0n, 0n, 4104n, 0n, 0n, 0, '0'.repeat(64), 20)

    expect(est.terrainK).toBe(proof.terrainK)
    expect(est.lcaX).toBe(findLcaHeight(0n, 4104n))
    expect(est.maxHeight).toBe(est.lcaX)
    expect(est.exceedsLimit).toBe(false)
  })

  it('flags a move that exceeds the compute ceiling', () => {
    expect(estimateHopCost(0n, 0n, 0n, 1n << 30n, 0n, 0n, 0).exceedsLimit).toBe(true)
  })

  it('captures the spec point that cost depends on the boundary, not distance', () => {
    // Spec 4.4: moving 7 -> 8 is one Gibson but costs far more than 8 -> 9,
    // because it crosses a height-4 aligned subtree boundary.
    const cheap = estimateHopCost(8n, 0n, 0n, 9n, 0n, 0n, 0)
    const costly = estimateHopCost(7n, 0n, 0n, 8n, 0n, 0n, 0)
    expect(costly.lcaX).toBe(4)
    expect(cheap.lcaX).toBe(1)
    expect(costly.lcaX).toBeGreaterThan(cheap.lcaX)
  })
})
