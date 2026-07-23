/**
 * sidestep.test.ts - Merkle sidestep proofs against Python golden vectors.
 *
 * Golden values were generated from the reference implementation
 * (cyberspace-cli movement.py, 2026-07-23) and MUST match exactly.
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '../src/cantor.js'
import { findLcaHeight } from '../src/movement.js'
import {
  computeAxisMerkleRoot,
  computeSidestepProof,
  estimateSidestepCost,
  merkleLeaf,
  merkleParent,
  sidestepLanding,
  verifyMerkleInclusion,
} from '../src/sidestep.js'

// ---------- Golden vectors (Python reference) ----------

const GOLDEN_LEAF_0 = '74ccac070cb840fdd789784f52da0aa2eb0e2d8d081e5af6d8bc75784ebb361e'
const GOLDEN_LEAF_BIG = '27801a4c7e3ef4f7ecbddea4f3158860a7182d3c9ddc54462a0ef287722b7c1b'
const GOLDEN_ROOT_B0_H3 = '55ab11a5d9c07fb864809841ec550a93e7c985f7e30a5e99d3fef209c47e6a13'
const GOLDEN_SIB_B0_H3 = [
  '2334d0fb25f25152509c72edf8d9dc159d7cd00d600fb6dd4956e38cfebf5df0',
  'd82da166b9ac79e84fb96338baa070a7482960f6173d16c8647af8d3829c4aa3',
  'd6aa7e4bdfc8ef06a9c1e7ef0bf0cd6024732a8c25df72e19dae863492d550e7',
]
const GOLDEN_ROOT_B1024_H4 = '3aef2f7145232006548c5922272494c81ead5ddec8fa201efc7b6f83ecce4a7d'

// compute_sidestep_proof(7, 100, 2^84, 8, 100, 2^84, plane=0, prev="00"*32)
const GOLDEN_PROOF_HASH = 'b59d8971d8ec5c56b0b4d0333722221f2ea2cff6a147617ae8e781ef124afeaa'
const GOLDEN_MERKLE_X = '8cf2ad679dcd272a6ecd8c0d89e57dc5f5948857e35b0d1326b095703c22bf94'
const GOLDEN_MERKLE_Y = '7bc828cd6b2489e34fc123ed44dc3dd1788d64360320d5593e5a8ea033e8692f'
const GOLDEN_MERKLE_Z = '1831f19c498b4a003da416c665926bd23817509e4a5ec30300824159367e20b0'
const GOLDEN_TERRAIN_K = 6
const GOLDEN_CANTOR_T =
  3781109404119008621727724705030782474440647636075061642599030617543756336085815098628231687603461674000385260651699027143470838144n

describe('merkleLeaf', () => {
  it('matches the Python reference, including the 0 -> single zero byte encoding', () => {
    expect(bytesToHex(merkleLeaf(0n))).toBe(GOLDEN_LEAF_0)
    expect(bytesToHex(merkleLeaf((1n << 84n) + 5n))).toBe(GOLDEN_LEAF_BIG)
  })

  it('is domain separated: different values differ', () => {
    expect(bytesToHex(merkleLeaf(1n))).not.toBe(bytesToHex(merkleLeaf(2n)))
  })
})

describe('computeAxisMerkleRoot', () => {
  it('reproduces the reference root and leaf-0 siblings for base 0 height 3', () => {
    // 0 -> 7 spans the whole height-3 subtree; destination 0 is leaf index 0,
    // which is exactly the leaf the Python streaming proof tracks.
    const r = computeAxisMerkleRoot(7n, 0n)
    expect(r.height).toBe(3)
    expect(bytesToHex(r.root)).toBe(GOLDEN_ROOT_B0_H3)
    expect(r.siblings.map(bytesToHex)).toEqual(GOLDEN_SIB_B0_H3)
  })

  it('reproduces the reference root for base 1024 height 4', () => {
    // 1024 -> 1039: LCA height 4, base 1024.
    const r = computeAxisMerkleRoot(1024n, 1039n)
    expect(r.height).toBe(4)
    expect(bytesToHex(r.root)).toBe(GOLDEN_ROOT_B1024_H4)
  })

  it('matches a hand-built height-2 tree', () => {
    const h0 = merkleLeaf(0n)
    const h1 = merkleLeaf(1n)
    const h2 = merkleLeaf(2n)
    const h3 = merkleLeaf(3n)
    const expected = merkleParent(merkleParent(h0, h1), merkleParent(h2, h3))
    const r = computeAxisMerkleRoot(0n, 3n)
    expect(bytesToHex(r.root)).toBe(bytesToHex(expected))
    // Destination is leaf 3 (right side): siblings are h2 then p01.
    expect(bytesToHex(r.siblings[0])).toBe(bytesToHex(h2))
    expect(bytesToHex(r.siblings[1])).toBe(bytesToHex(merkleParent(h0, h1)))
  })

  it('handles trivial axes as a single leaf hash', () => {
    const r = computeAxisMerkleRoot(100n, 100n)
    expect(r.height).toBe(0)
    expect(r.siblings).toEqual([])
    expect(bytesToHex(r.root)).toBe(bytesToHex(merkleLeaf(100n)))
  })

  it('root does not depend on which endpoint is source', () => {
    const a = computeAxisMerkleRoot(7n, 8n)
    const b = computeAxisMerkleRoot(8n, 7n)
    expect(bytesToHex(a.root)).toBe(bytesToHex(b.root))
    expect(a.height).toBe(4)
  })
})

describe('verifyMerkleInclusion', () => {
  it('accepts every leaf of a height-3 subtree with its own proof', () => {
    for (let leaf = 0n; leaf < 8n; leaf++) {
      // Source on the opposite height-2 half forces the LCA to height 3 for
      // every destination leaf.
      const src = leaf < 4n ? 7n : 0n
      const r = computeAxisMerkleRoot(src, leaf)
      expect(r.height).toBe(3)
      expect(verifyMerkleInclusion(leaf, r.siblings, r.root, 3, 0n)).toBe(true)
    }
  })

  it('rejects a wrong root', () => {
    const r = computeAxisMerkleRoot(0n, 5n)
    expect(verifyMerkleInclusion(5n, r.siblings, merkleLeaf(9n), 3, 0n)).toBe(false)
  })

  it('rejects tampered siblings', () => {
    const r = computeAxisMerkleRoot(0n, 5n)
    const bad = [...r.siblings]
    bad[1] = merkleLeaf(999n)
    expect(verifyMerkleInclusion(5n, bad, r.root, 3, 0n)).toBe(false)
  })

  it('verifies trivial axes', () => {
    expect(verifyMerkleInclusion(42n, [], merkleLeaf(42n), 0, 42n)).toBe(true)
  })
})

describe('computeSidestepProof', () => {
  it('matches the Python reference proof end to end', () => {
    const p = computeSidestepProof(
      7n, 100n, 1n << 84n,
      8n, 100n, 1n << 84n,
      0,
      '0'.repeat(64),
    )
    expect(bytesToHex(p.merkleX)).toBe(GOLDEN_MERKLE_X)
    expect(bytesToHex(p.merkleY)).toBe(GOLDEN_MERKLE_Y)
    expect(bytesToHex(p.merkleZ)).toBe(GOLDEN_MERKLE_Z)
    expect(p.terrainK).toBe(GOLDEN_TERRAIN_K)
    expect(p.cantorT).toBe(GOLDEN_CANTOR_T)
    expect(p.proofHash).toBe(GOLDEN_PROOF_HASH)
    expect(p.lcaHeights).toEqual([4, 0, 0])
    expect(p.inclusionProofs.x.length).toBe(4)
    expect(p.inclusionProofs.y.length).toBe(0)
    // The destination leaf verifies against the published root.
    expect(verifyMerkleInclusion(8n, p.inclusionProofs.x, p.merkleX, 4, 0n)).toBe(true)
  })

  it('reports monotonically reasonable progress', () => {
    const fractions: number[] = []
    computeSidestepProof(0n, 0n, 0n, 1023n, 0n, 0n, 0, '0'.repeat(64), (f) => fractions.push(f))
    expect(fractions.length).toBeGreaterThan(0)
    expect(fractions[fractions.length - 1]).toBe(1)
  })
})

describe('estimateSidestepCost', () => {
  it('counts leaves plus internals per axis', () => {
    // 7 -> 8 is height 4: 16 leaves + 15 internals; trivial axes cost 1 each.
    const e = estimateSidestepCost(7n, 0n, 0n, 8n, 0n, 0n)
    expect(e.lcaX).toBe(4)
    expect(e.maxHeight).toBe(4)
    expect(e.totalHashes).toBe(31 + 1 + 1)
  })
})

describe('sidestepLanding', () => {
  it('lands 1 gibson past the boundary going up', () => {
    // From 5 toward 20 the wall is at 16 (height 5); land ON 16.
    expect(sidestepLanding(5n, 20n)).toBe(16n)
    expect(findLcaHeight(5n, 16n)).toBe(5)
    // The classic spec example: 2^34 - 1 crossing to 2^34.
    expect(sidestepLanding((1n << 34n) - 1n, 1n << 34n)).toBe(1n << 34n)
  })

  it('lands 1 gibson past the boundary going down', () => {
    // From 20 toward 5 the wall is at 16; land on 15, its near side.
    expect(sidestepLanding(20n, 5n)).toBe(15n)
    expect(findLcaHeight(20n, 15n)).toBe(5)
    expect(sidestepLanding(1n << 34n, (1n << 34n) - 1n)).toBe((1n << 34n) - 1n)
  })

  it('is a no-op with no boundary to cross', () => {
    expect(sidestepLanding(9n, 9n)).toBe(9n)
  })

  it('still crosses the full wall from mid-block starts', () => {
    // Starting away from the edge changes nothing: the crossing height is
    // the wall's height, and the landing is just past the boundary.
    const from = (1n << 30n) + 12345n
    const target = (1n << 31n) + 7n
    const landing = sidestepLanding(from, target)
    expect(landing).toBe(1n << 31n)
    expect(findLcaHeight(from, landing)).toBe(32)
  })
})
