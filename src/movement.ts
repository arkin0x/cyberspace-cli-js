/**
 * movement.ts — Movement proofs and Cantor tree computation.
 *
 * Core operations:
 * - LCA height between two axis values
 * - Subtree Cantor root computation (O(2^h))
 * - Spatial movement proof (3D: region_n)
 * - Full 4D hop proof (spatial + temporal, per spec §5.5–§5.7)
 */

import { cantorPair, intToBytesBE, sha256, sha256IntHex, hexToBytes, bytesToHex } from './cantor.js'
import { AXIS_BITS, type Plane } from './coords.js'
import { terrainK } from './terrain.js'

export const DEFAULT_MAX_COMPUTE_HEIGHT = 20
export const TEMPORAL_MAX_COMPUTE_HEIGHT = 17

/**
 * Progress reporter for long-running Cantor tree computation. Called
 * periodically with a 0..1 fraction so a worker can stream live stats without
 * blocking the UI thread. Kept optional so consensus paths stay allocation-free.
 */
export type ProgressFn = (fraction: number) => void

/** Report progress roughly this many times over a full computation. */
const PROGRESS_TICKS = 64

/**
 * Find the LCA height between two axis values.
 * Height = bit_length(v1 XOR v2).
 */
export function findLcaHeight(v1: bigint, v2: bigint): number {
  if (v1 === v2) return 0
  const xor = v1 ^ v2
  return xor.toString(2).length
}

/**
 * Number of leaves in the aligned subtree for a given LCA height.
 * This is the dominant cost term: computing the tree is O(2^h).
 */
export function subtreeLeafCount(height: number): number {
  return height === 0 ? 1 : 2 ** height
}

/**
 * Total Cantor pairings required to reduce a height-h subtree to its root.
 * A full binary tree with 2^h leaves needs 2^h - 1 internal pairings.
 */
export function subtreeCantorOps(height: number): number {
  return height === 0 ? 0 : 2 ** height - 1
}

/**
 * The aligned base of the subtree containing v at the given height.
 */
export function alignedBase(v: bigint, height: number): bigint {
  if (height <= 0) return v
  const h = BigInt(height)
  return (v >> h) << h
}

/**
 * Compute the Cantor number for a subtree rooted at (base, height).
 * O(2^h) computation.
 */
export function computeSubtreeCantor(
  base: bigint,
  height: number,
  maxComputeHeight: number = DEFAULT_MAX_COMPUTE_HEIGHT,
  onProgress?: ProgressFn,
): bigint {
  if (height < 0) throw new Error('height must be >= 0')
  if (height > maxComputeHeight) {
    throw new Error(`height ${height} exceeds maxComputeHeight ${maxComputeHeight}`)
  }
  if (height === 0) {
    onProgress?.(1)
    return base
  }

  const leafCount = 2 ** height

  // Total work units: building leafCount leaves, then leafCount-1 pairings.
  const totalWork = leafCount * 2 - 1
  const tickEvery = Math.max(1, Math.floor(totalWork / PROGRESS_TICKS))
  let done = 0

  let values: bigint[] = new Array(leafCount)
  for (let i = 0; i < leafCount; i++) {
    values[i] = base + BigInt(i)
    if (onProgress && ++done % tickEvery === 0) onProgress(done / totalWork)
  }

  for (let level = 0; level < height; level++) {
    const next: bigint[] = new Array(values.length / 2)
    for (let i = 0; i < values.length; i += 2) {
      next[i / 2] = cantorPair(values[i], values[i + 1])
      if (onProgress && ++done % tickEvery === 0) onProgress(done / totalWork)
    }
    values = next
  }

  onProgress?.(1)
  return values[0]
}

/**
 * Compute the axis Cantor root for two axis values.
 */
export function computeAxisCantor(
  v1: bigint,
  v2: bigint,
  maxComputeHeight: number = DEFAULT_MAX_COMPUTE_HEIGHT,
  onProgress?: ProgressFn,
): bigint {
  const h = findLcaHeight(v1, v2)
  return computeSubtreeCantor(alignedBase(v1, h), h, maxComputeHeight, onProgress)
}

export interface MovementProof {
  cantorX: bigint
  cantorY: bigint
  cantorZ: bigint
  combined: bigint
  proofHash: string
}

/**
 * Compute the spatial-only movement proof (region_n).
 */
export function computeMovementProof(
  x1: bigint, y1: bigint, z1: bigint,
  x2: bigint, y2: bigint, z2: bigint,
  maxComputeHeight: number = DEFAULT_MAX_COMPUTE_HEIGHT,
): MovementProof {
  const cx = computeAxisCantor(x1, x2, maxComputeHeight)
  const cy = computeAxisCantor(y1, y2, maxComputeHeight)
  const cz = computeAxisCantor(z1, z2, maxComputeHeight)
  const combined = cantorPair(cantorPair(cx, cy), cz)
  const proofHash = sha256IntHex(combined)
  return { cantorX: cx, cantorY: cy, cantorZ: cz, combined, proofHash }
}

export interface HopProof {
  cantorX: bigint
  cantorY: bigint
  cantorZ: bigint
  regionN: bigint
  terrainK: number
  temporalSeed: bigint
  cantorT: bigint
  hopN: bigint
  proofHash: string
}

/**
 * Compute the full 4D hop proof (spatial + temporal) per spec §5.5–§5.7.
 *
 * @param plane destination plane bit (0 or 1)
 * @param previousEventIdHex 64-char lowercase hex
 */
export function computeHopProof(
  x1: bigint, y1: bigint, z1: bigint,
  x2: bigint, y2: bigint, z2: bigint,
  plane: Plane,
  previousEventIdHex: string,
  maxComputeHeight: number = DEFAULT_MAX_COMPUTE_HEIGHT,
  onProgress?: ProgressFn,
): HopProof {
  // Spatial component. Weight each axis's progress by its share of the work so
  // the reported fraction tracks real elapsed cost, not axis count.
  const hx = findLcaHeight(x1, x2)
  const hy = findLcaHeight(y1, y2)
  const hz = findLcaHeight(z1, z2)
  const tkPre = terrainK(x2, y2, z2, plane)
  const work = [subtreeLeafCount(hx), subtreeLeafCount(hy), subtreeLeafCount(hz), subtreeLeafCount(tkPre)]
  const totalWork = work.reduce((a, b) => a + b, 0)

  let baseFraction = 0
  const stage = (i: number): ProgressFn | undefined => {
    if (!onProgress) return undefined
    const share = work[i] / totalWork
    const start = baseFraction
    baseFraction += share
    return (f: number) => onProgress(start + f * share)
  }

  const cx = computeAxisCantor(x1, x2, maxComputeHeight, stage(0))
  const cy = computeAxisCantor(y1, y2, maxComputeHeight, stage(1))
  const cz = computeAxisCantor(z1, z2, maxComputeHeight, stage(2))
  const regionN = cantorPair(cantorPair(cx, cy), cz)

  // Temporal component (§5.5.2)
  const tk = tkPre

  // Seed from previous event id
  if (previousEventIdHex.length !== 64) {
    throw new Error('previousEventIdHex must be exactly 64 hex chars')
  }
  const prevIdBytes = hexToBytes(previousEventIdHex)
  let prevIdInt = 0n
  for (const b of prevIdBytes) {
    prevIdInt = (prevIdInt << 8n) | BigInt(b)
  }
  const axisMask = (1n << BigInt(AXIS_BITS)) - 1n
  const t = prevIdInt & axisMask // mod 2^85

  // Temporal subtree root
  const cantorT = computeSubtreeCantor(alignedBase(t, tk), tk, TEMPORAL_MAX_COMPUTE_HEIGHT, stage(3))

  // 4D combination (§5.5.3)
  const hopN = cantorPair(regionN, cantorT)

  // Proof hash (§5.7): double SHA-256
  const movementProofKey = sha256(intToBytesBE(hopN))
  const proofHash = bytesToHex(sha256(movementProofKey))

  onProgress?.(1)

  return {
    cantorX: cx,
    cantorY: cy,
    cantorZ: cz,
    regionN,
    terrainK: tk,
    temporalSeed: t,
    cantorT,
    hopN,
    proofHash,
  }
}

export interface HopCostEstimate {
  lcaX: number
  lcaY: number
  lcaZ: number
  terrainK: number
  /** Largest single-axis LCA height; drives peak memory. */
  maxHeight: number
  /** Total Cantor pairings across all four trees. */
  totalOps: number
  /** True if any tree exceeds the configured compute ceiling. */
  exceedsLimit: boolean
}

/**
 * Estimate the cost of a hop without computing it. Used by the UI to warn
 * before a move that would take minutes, and to drive the live cost readout.
 */
export function estimateHopCost(
  x1: bigint, y1: bigint, z1: bigint,
  x2: bigint, y2: bigint, z2: bigint,
  plane: Plane,
  maxComputeHeight: number = DEFAULT_MAX_COMPUTE_HEIGHT,
): HopCostEstimate {
  const lcaX = findLcaHeight(x1, x2)
  const lcaY = findLcaHeight(y1, y2)
  const lcaZ = findLcaHeight(z1, z2)
  const tk = terrainK(x2, y2, z2, plane)
  const maxHeight = Math.max(lcaX, lcaY, lcaZ)
  const totalOps =
    subtreeCantorOps(lcaX) + subtreeCantorOps(lcaY) + subtreeCantorOps(lcaZ) + subtreeCantorOps(tk)
  return {
    lcaX,
    lcaY,
    lcaZ,
    terrainK: tk,
    maxHeight,
    totalOps,
    exceedsLimit: maxHeight > maxComputeHeight || tk > TEMPORAL_MAX_COMPUTE_HEIGHT,
  }
}
