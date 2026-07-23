/**
 * sidestep.ts - Merkle sidestep proofs (spec section 6).
 *
 * A sidestep crosses an LCA boundary with a Merkle hash tree instead of a
 * Cantor pairing tree. SHA-256 is fixed-size, so there is no storage
 * bottleneck: the cost of a sidestep is purely time (2^(h+1) - 1 hashes per
 * crossing axis). It exists to cross the walls that Cantor computation
 * cannot, at heights where intermediate pairing values would not fit in any
 * machine.
 *
 * Ported against the Python reference implementation (cyberspace-cli
 * movement.py) and validated with golden vectors generated from it.
 */

import { cantorPair, intToBytesBE, sha256, hexToBytes, bytesToHex } from './cantor.js'
import { AXIS_BITS, type Plane } from './coords.js'
import {
  TEMPORAL_MAX_COMPUTE_HEIGHT,
  alignedBase,
  computeSubtreeCantor,
  findLcaHeight,
  subtreeLeafCount,
  type ProgressFn,
} from './movement.js'
import { terrainK } from './terrain.js'

/**
 * Domain separation constant for sidestep Merkle leaf hashes (spec 6.4).
 * If any aspect of leaf hashing changes, this string must be bumped.
 */
export const SIDESTEP_DOMAIN = new TextEncoder().encode('CYBERSPACE_SIDESTEP_V1')

/** Report progress roughly this many times over a full axis computation. */
const PROGRESS_TICKS = 64

/**
 * Streaming index arithmetic uses Number leaf indices, exact below 2^53.
 * Heights past this bound are centuries of hashing anyway; refuse loudly
 * rather than corrupt silently.
 */
const MAX_STREAMING_HEIGHT = 52

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n
  for (const b of bytes) n = (n << 8n) | BigInt(b)
  return n
}

/**
 * Merkle leaf hash with domain separation:
 * H = SHA256(SIDESTEP_DOMAIN || int_to_bytes_be_min(value)).
 */
export function merkleLeaf(value: bigint): Uint8Array {
  return sha256(concatBytes(SIDESTEP_DOMAIN, intToBytesBE(value)))
}

/**
 * Merkle internal node: SHA256(left || right).
 */
export function merkleParent(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(left, right))
}

export interface AxisMerkleResult {
  /** 32-byte Merkle root over the LCA subtree. */
  root: Uint8Array
  /**
   * Inclusion-proof sibling hashes for the DESTINATION leaf, leaf level
   * first (spec 6.10). Empty for trivial axes.
   */
  siblings: Uint8Array[]
  /** LCA height of the crossing; 0 when v1 === v2. */
  height: number
}

/**
 * Merkle root for the LCA subtree between two axis values, computed in
 * streaming O(h) memory (spec 6.5), plus the destination leaf's inclusion
 * proof collected on the way through.
 */
export function computeAxisMerkleRoot(
  v1: bigint,
  v2: bigint,
  onProgress?: ProgressFn,
): AxisMerkleResult {
  const height = findLcaHeight(v1, v2)
  if (height === 0) {
    onProgress?.(1)
    return { root: merkleLeaf(v1), siblings: [], height: 0 }
  }
  if (height > MAX_STREAMING_HEIGHT) {
    throw new Error(`LCA height ${height} exceeds streaming index range (2^53 leaves)`)
  }

  const base = alignedBase(v1, height)
  const destIndex = Number(v2 - base)
  const leafCount = 2 ** height
  const tickEvery = Math.max(1, Math.floor(leafCount / PROGRESS_TICKS))

  // Each entry is a pending subtree root: its hash, its level (leaf = 0), and
  // the leaf index its leftmost leaf covers.
  const stack: Array<{ hash: Uint8Array; level: number; start: number }> = []
  const siblings: Array<Uint8Array | undefined> = new Array(height).fill(undefined)

  for (let i = 0; i < leafCount; i++) {
    let hash = merkleLeaf(base + BigInt(i))
    let level = 0
    let start = i

    while (stack.length > 0 && stack[stack.length - 1].level === level) {
      const left = stack.pop()!
      // Capture the sibling on the destination leaf's path: at this level the
      // destination's ancestor is either the left node (sibling = right) or
      // the right node (sibling = left).
      if (siblings[level] === undefined) {
        const destAncestor = Math.floor(destIndex / 2 ** level)
        const leftIdx = left.start / 2 ** level
        if (destAncestor === leftIdx) siblings[level] = hash
        else if (destAncestor === leftIdx + 1) siblings[level] = left.hash
      }
      hash = merkleParent(left.hash, hash)
      level += 1
      start = left.start
    }

    stack.push({ hash, level, start })
    if (onProgress && (i + 1) % tickEvery === 0) onProgress((i + 1) / leafCount)
  }

  if (stack.length !== 1) throw new Error(`expected single root, got ${stack.length}`)
  if (siblings.some((s) => s === undefined)) {
    throw new Error('incomplete inclusion proof: destination leaf outside subtree?')
  }

  onProgress?.(1)
  return { root: stack[0].hash, siblings: siblings as Uint8Array[], height }
}

/**
 * Verify a Merkle inclusion proof for a leaf value (spec 6.10 / Level 1
 * verification, spec 6.11).
 */
export function verifyMerkleInclusion(
  leafValue: bigint,
  siblings: Uint8Array[],
  expectedRoot: Uint8Array,
  height: number,
  base: bigint,
): boolean {
  if (height === 0) {
    return siblings.length === 0 && bytesToHex(merkleLeaf(leafValue)) === bytesToHex(expectedRoot)
  }
  if (siblings.length !== height) return false

  const leafIndex = Number(leafValue - base)
  let current = merkleLeaf(leafValue)

  for (let level = 0; level < height; level++) {
    // The bit at this level of the leaf index says which child the path is.
    if ((Math.floor(leafIndex / 2 ** level) & 1) === 0) {
      current = merkleParent(current, siblings[level])
    } else {
      current = merkleParent(siblings[level], current)
    }
  }

  return bytesToHex(current) === bytesToHex(expectedRoot)
}

export interface SidestepCostEstimate {
  lcaX: number
  lcaY: number
  lcaZ: number
  maxHeight: number
  /** Total SHA-256 evaluations across all three axes (leaves + internals). */
  totalHashes: number
}

/** SHA-256 evaluations to build one axis tree: 2^h leaves + 2^h - 1 internals. */
function axisHashCount(height: number): number {
  return height === 0 ? 1 : 2 ** (height + 1) - 1
}

/**
 * Closed-form cost of a sidestep. Unlike the hop estimate there is no
 * feasibility ceiling: a sidestep is always storable, only ever slow.
 */
export function estimateSidestepCost(
  x1: bigint, y1: bigint, z1: bigint,
  x2: bigint, y2: bigint, z2: bigint,
): SidestepCostEstimate {
  const lcaX = findLcaHeight(x1, x2)
  const lcaY = findLcaHeight(y1, y2)
  const lcaZ = findLcaHeight(z1, z2)
  return {
    lcaX,
    lcaY,
    lcaZ,
    maxHeight: Math.max(lcaX, lcaY, lcaZ),
    totalHashes: axisHashCount(lcaX) + axisHashCount(lcaY) + axisHashCount(lcaZ),
  }
}

/**
 * The landing coordinate for a sidestep from v1 across the highest boundary
 * toward `target`: exactly 1 gibson past that boundary (spec 6.3).
 *
 * Upward this is the adjacent subtree's first leaf (low bits zero), which is
 * both spec readings at once. Downward, "1 gibson past the boundary" gives
 * the adjacent subtree's LAST leaf (low bits all ones), which contradicts the
 * spec's upward-phrased "all lower bits set to zero" sentence; landing on the
 * near edge is the only reading consistent with "crosses exactly 1 Gibson
 * past the boundary", so that is what this implements. Flagged upstream as a
 * spec wording defect.
 */
export function sidestepLanding(v1: bigint, target: bigint): bigint {
  const h = findLcaHeight(v1, target)
  if (h === 0) return v1
  const hb = BigInt(h - 1)
  const childBase = (v1 >> hb) << hb
  return target > v1 ? childBase + (1n << hb) : childBase - 1n
}

export interface SidestepProof {
  merkleX: Uint8Array
  merkleY: Uint8Array
  merkleZ: Uint8Array
  /** pi(pi(mx, my), mz) over the roots as big-endian integers (spec 6.6). */
  regionM: bigint
  terrainK: number
  temporalSeed: bigint
  cantorT: bigint
  /** pi(region_m, cantor_t) (spec 6.8). */
  sidestepN: bigint
  /** double-SHA256(sidestep_n), lowercase hex. */
  proofHash: string
  lcaHeights: [number, number, number]
  inclusionProofs: { x: Uint8Array[]; y: Uint8Array[]; z: Uint8Array[] }
}

/**
 * Compute a full sidestep proof: per-axis Merkle roots combined into
 * region_m, plus the temporal Cantor binding identical to hop proofs
 * (spec 6.6 - 6.8).
 */
export function computeSidestepProof(
  x1: bigint, y1: bigint, z1: bigint,
  x2: bigint, y2: bigint, z2: bigint,
  plane: Plane,
  previousEventIdHex: string,
  onProgress?: ProgressFn,
): SidestepProof {
  // Weight each stage's progress by its share of the hash work, mirroring
  // computeHopProof, so the reported fraction tracks elapsed cost.
  const hx = findLcaHeight(x1, x2)
  const hy = findLcaHeight(y1, y2)
  const hz = findLcaHeight(z1, z2)
  const tkPre = terrainK(x2, y2, z2, plane)
  const work = [axisHashCount(hx), axisHashCount(hy), axisHashCount(hz), subtreeLeafCount(tkPre)]
  const totalWork = work.reduce((a, b) => a + b, 0)

  let baseFraction = 0
  const stage = (i: number): ProgressFn | undefined => {
    if (!onProgress) return undefined
    const share = work[i] / totalWork
    const start = baseFraction
    baseFraction += share
    return (f: number) => onProgress(start + f * share)
  }

  const ax = computeAxisMerkleRoot(x1, x2, stage(0))
  const ay = computeAxisMerkleRoot(y1, y2, stage(1))
  const az = computeAxisMerkleRoot(z1, z2, stage(2))

  const regionM = cantorPair(
    cantorPair(bytesToBigInt(ax.root), bytesToBigInt(ay.root)),
    bytesToBigInt(az.root),
  )

  // Temporal component, identical to the hop proof (spec 6.7).
  const tk = tkPre
  if (previousEventIdHex.length !== 64) {
    throw new Error('previousEventIdHex must be exactly 64 hex chars')
  }
  const prevIdInt = bytesToBigInt(hexToBytes(previousEventIdHex))
  const axisMask = (1n << BigInt(AXIS_BITS)) - 1n
  const t = prevIdInt & axisMask // mod 2^85

  const cantorT = computeSubtreeCantor(alignedBase(t, tk), tk, TEMPORAL_MAX_COMPUTE_HEIGHT, stage(3))

  const sidestepN = cantorPair(regionM, cantorT)

  // Proof hash (spec 6.8): double SHA-256.
  const proofKey = sha256(intToBytesBE(sidestepN))
  const proofHash = bytesToHex(sha256(proofKey))

  onProgress?.(1)

  return {
    merkleX: ax.root,
    merkleY: ay.root,
    merkleZ: az.root,
    regionM,
    terrainK: tk,
    temporalSeed: t,
    cantorT,
    sidestepN,
    proofHash,
    lcaHeights: [ax.height, ay.height, az.height],
    inclusionProofs: { x: ax.siblings, y: ay.siblings, z: az.siblings },
  }
}
