/**
 * sidestep.ts - Merkle sidestep proofs, version 2 (spec section 6).
 *
 * A sidestep crosses an LCA boundary with a Merkle hash tree instead of a
 * Cantor pairing tree. SHA-256 is fixed-size, so there is no storage
 * bottleneck: the cost of a sidestep is purely time (2^(h+1) - 1 hashes per
 * crossing axis). It exists to cross the walls that Cantor computation
 * cannot, at heights where intermediate pairing values would not fit in any
 * machine.
 *
 * Version 2 (spec 6.15) makes the sidestep a toll. Every leaf is seeded with
 * the mover's previous event id and the axis (6.4), so the tree is unique to
 * one chain position and nobody's published proof shortens anyone else's
 * crossing. With no canonical root left to compare against, the prover also
 * publishes openings (6.10): the destination leaf's path and eight more at
 * positions drawn from the root, which a verifier recomputes from scratch.
 * The seed prefix is exactly one SHA-256 block, so its compression state is
 * taken once per axis and every leaf costs one compression, as before (6.5).
 *
 * Checked against the spec's sidestep-reference.py golden vectors.
 */

import { cantorPair, intToBytesBE, sha256, sha256FromMidstate, sha256Midstate, hexToBytes, bytesToHex } from './cantor.js'
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

/** Domain separation for the seeded leaves (spec 6.4). Bumped from V1 with the seed. */
export const SIDESTEP_DOMAIN = new TextEncoder().encode('CYBERSPACE_SIDESTEP_V2')
/** Nine zero bytes, so the seed prefix fills one 64-byte block exactly (spec 6.4, 6.5). */
export const SEED_PAD = new Uint8Array(9)
/** Domain separation for the sampled opening indices (spec 6.10). */
export const SIDESTEP_SAMPLE_DOMAIN = new TextEncoder().encode('CYBERSPACE_SIDESTEP_SAMPLE_V1')
/** Sampled openings per non-trivial axis, after the destination's (spec 6.10). */
export const SIDESTEP_SAMPLES = 8

export type AxisName = 'x' | 'y' | 'z'
/** The axis byte in the seed: X 0, Y 1, Z 2 (spec 6.4). */
export const AXIS_BYTE: Record<AxisName, number> = { x: 0, y: 1, z: 2 }

/** Report progress roughly this many times over a full axis computation. */
const PROGRESS_TICKS = 64

/**
 * Streaming index arithmetic uses Number leaf indices, exact below 2^53.
 * Heights past this bound are centuries of hashing anyway; refuse loudly
 * rather than corrupt silently.
 */
const MAX_STREAMING_HEIGHT = 52

/**
 * Nodes from this many levels below the root are kept from the main pass, so
 * the openings can be assembled afterwards by rebuilding only the small
 * subtree under each opened leaf (see computeAxisMerkleRoot). 2^17 hashes,
 * 4 MB, whatever the height.
 */
const KEPT_LEVELS = 16

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) { out.set(p, at); at += p.length }
  return out
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n
  for (const b of bytes) n = (n << 8n) | BigInt(b)
  return n
}

/**
 * The per-axis seed prefix (spec 6.4): domain, the 32 raw bytes of the
 * previous event id, the axis byte, and the pad, 64 bytes in all.
 */
export function seedPrefix(previousEventId: Uint8Array, axisByte: number): Uint8Array {
  if (previousEventId.length !== 32) throw new Error('previous_event_id must be 32 raw bytes')
  if (axisByte < 0 || axisByte > 2) throw new Error('axis byte must be 0, 1 or 2')
  const prefix = concatBytes(SIDESTEP_DOMAIN, previousEventId, new Uint8Array([axisByte]), SEED_PAD)
  if (prefix.length !== 64) throw new Error('seed prefix must be exactly one SHA-256 block')
  return prefix
}

/** A leaf hasher for one seed prefix, resuming from the prefix's midstate (spec 6.5). */
export function leafHasher(prefix: Uint8Array): (value: bigint) => Uint8Array {
  const mid = sha256Midstate(prefix)
  return (value: bigint) => sha256FromMidstate(mid, intToBytesBE(value))
}

/** Merkle leaf hash: SHA256(seed_prefix || int_to_bytes_be_min(value)). */
export function merkleLeaf(prefix: Uint8Array, value: bigint): Uint8Array {
  return sha256(concatBytes(prefix, intToBytesBE(value)))
}

/** Merkle internal node: SHA256(left || right). */
export function merkleParent(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(left, right))
}

/**
 * The sampled positions for an axis (spec 6.10): eight indices within the
 * aligned subtree drawn from its root. Collisions stand; the count is fixed.
 */
export function sampleIndices(root: Uint8Array, axisByte: number, height: number): number[] {
  if (height === 0) return []
  const out: number[] = []
  const mod = 1n << BigInt(height)
  for (let i = 0; i < SIDESTEP_SAMPLES; i++) {
    const be32 = new Uint8Array([(i >>> 24) & 0xff, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff])
    const h = sha256(concatBytes(SIDESTEP_SAMPLE_DOMAIN, root, new Uint8Array([axisByte]), be32))
    out.push(Number(bytesToBigInt(h) % mod))
  }
  return out
}

export interface AxisMerkleResult {
  /** 32-byte Merkle root over the LCA subtree. */
  root: Uint8Array
  /**
   * The openings (spec 6.10): the destination leaf's path first, then the
   * sampled paths in order, each `height` siblings leaf level first. Empty
   * for trivial axes.
   */
  openings: Uint8Array[][]
  /** LCA height of the crossing; 0 when v1 === v2. */
  height: number
}

/**
 * A streaming fold over the leaves `first .. first + 2^height - 1` (spec
 * 6.5): each leaf is pushed and merged with the pending node of its own level
 * until levels differ, so at most `height` nodes are pending at once. `keep`
 * receives every node at or above level `keepFrom`, by level and by index
 * within the level.
 */
function fold(
  leaf: (value: bigint) => Uint8Array,
  base: bigint,
  first: number,
  height: number,
  keepFrom: number,
  keep: (level: number, index: number, hash: Uint8Array) => void,
  onLeaf?: (i: number) => void,
): Uint8Array {
  const count = 2 ** height
  const stack: Array<{ hash: Uint8Array; level: number; start: number }> = []
  for (let i = 0; i < count; i++) {
    const at = first + i
    let hash = leaf(base + BigInt(at))
    let level = 0
    let start = at
    if (keepFrom === 0) keep(0, at, hash)
    while (stack.length > 0 && stack[stack.length - 1].level === level) {
      const left = stack.pop()!
      hash = merkleParent(left.hash, hash)
      level += 1
      start = left.start
      if (level >= keepFrom) keep(level, start / 2 ** level, hash)
    }
    stack.push({ hash, level, start })
    onLeaf?.(i)
  }
  if (stack.length !== 1) throw new Error(`expected single root, got ${stack.length}`)
  return stack[0].hash
}

/**
 * Merkle root for the LCA subtree between two axis values, in streaming
 * memory, plus the openings for the destination leaf and the eight sampled
 * leaves.
 *
 * The sampled positions depend on the root, so they are not known during
 * the pass that produces it. Rather than a second full pass, the top
 * KEPT_LEVELS levels of nodes are kept from the first, and each opening's
 * lower siblings come from rebuilding only the small subtree under that leaf:
 * nine subtrees of 2^(h - 16) leaves, a negligible fraction of the work.
 */
export function computeAxisMerkleRoot(
  prefix: Uint8Array,
  axisByte: number,
  v1: bigint,
  v2: bigint,
  onProgress?: ProgressFn,
): AxisMerkleResult {
  const height = findLcaHeight(v1, v2)
  const leaf = leafHasher(prefix)
  if (height === 0) {
    onProgress?.(1)
    return { root: leaf(v1), openings: [], height: 0 }
  }
  if (height > MAX_STREAMING_HEIGHT) {
    throw new Error(`LCA height ${height} exceeds streaming index range (2^53 leaves)`)
  }

  const base = alignedBase(v1, height)
  const leafCount = 2 ** height
  const keepFrom = Math.max(0, height - KEPT_LEVELS)
  const kept: Uint8Array[][] = []
  for (let level = 0; level <= height; level++) kept.push(level >= keepFrom ? new Array(2 ** (height - level)) : [])
  const tickEvery = Math.max(1, Math.floor(leafCount / PROGRESS_TICKS))

  const root = fold(leaf, base, 0, height, keepFrom, (level, index, hash) => { kept[level][index] = hash }, (i) => {
    if (onProgress && (i + 1) % tickEvery === 0) onProgress((i + 1) / leafCount)
  })

  // The path for one leaf: siblings below keepFrom from a rebuild of its
  // level-keepFrom subtree, siblings from keepFrom up from what was kept.
  const pathFor = (index: number): Uint8Array[] => {
    const siblings: Uint8Array[] = new Array(height)
    if (keepFrom > 0) {
      const size = 2 ** keepFrom
      const first = Math.floor(index / size) * size
      const local: Uint8Array[][] = []
      for (let level = 0; level < keepFrom; level++) local.push(new Array(2 ** (keepFrom - level)))
      fold(leaf, base, first, keepFrom, 0, (level, idx, hash) => { if (level < keepFrom) local[level][idx - first / 2 ** level] = hash })
      for (let level = 0; level < keepFrom; level++) {
        const at = Math.floor(index / 2 ** level) - first / 2 ** level
        siblings[level] = local[level][at ^ 1]
      }
    }
    for (let level = keepFrom; level < height; level++) {
      siblings[level] = kept[level][Math.floor(index / 2 ** level) ^ 1]
    }
    if (siblings.some((s) => s === undefined)) throw new Error('incomplete opening')
    return siblings
  }

  const destIndex = Number(v2 - base)
  const openings = [pathFor(destIndex), ...sampleIndices(root, axisByte, height).map(pathFor)]
  onProgress?.(1)
  return { root, openings, height }
}

/**
 * Whether `siblings` carry the leaf at `leafValue` up to `expectedRoot` in a
 * tree of `height` over the subtree at `base`. The leaf is recomputed from
 * the seed, never taken from the proof.
 */
export function verifyMerkleInclusion(
  prefix: Uint8Array,
  leafValue: bigint,
  siblings: Uint8Array[],
  expectedRoot: Uint8Array,
  height: number,
  base: bigint,
): boolean {
  if (height === 0) {
    return siblings.length === 0 && bytesToHex(merkleLeaf(prefix, leafValue)) === bytesToHex(expectedRoot)
  }
  if (siblings.length !== height) return false
  if (leafValue < base || leafValue - base >= (1n << BigInt(height))) return false
  const leafIndex = Number(leafValue - base)
  let current = merkleLeaf(prefix, leafValue)
  for (let level = 0; level < height; level++) {
    // The bit at this level of the leaf index says which child the path is.
    if ((Math.floor(leafIndex / 2 ** level) & 1) === 0) current = merkleParent(current, siblings[level])
    else current = merkleParent(siblings[level], current)
  }
  return bytesToHex(current) === bytesToHex(expectedRoot)
}

/**
 * Level 1 for one axis (spec 6.11, 8.7.2 step 4): the destination's path,
 * then each sampled leaf recomputed from the seed and carried to the root.
 */
export function verifyAxisOpenings(
  prefix: Uint8Array,
  axisByte: number,
  v1: bigint,
  v2: bigint,
  root: Uint8Array,
  openings: Uint8Array[][],
): boolean {
  const height = findLcaHeight(v1, v2)
  if (height === 0) return openings.length === 0 && bytesToHex(merkleLeaf(prefix, v1)) === bytesToHex(root)
  if (openings.length !== SIDESTEP_SAMPLES + 1) return false
  if (openings.some((p) => p.length !== height)) return false
  const base = alignedBase(v1, height)
  if (!verifyMerkleInclusion(prefix, v2, openings[0], root, height, base)) return false
  const samples = sampleIndices(root, axisByte, height)
  for (let i = 0; i < SIDESTEP_SAMPLES; i++) {
    if (!verifyMerkleInclusion(prefix, base + BigInt(samples[i]), openings[i + 1], root, height, base)) return false
  }
  return true
}

/** The `mp` segment for one axis (spec 8.5): every opening's siblings, leaf first, as one hex string. */
export function encodeOpenings(openings: Uint8Array[][]): string {
  let out = ''
  for (const path of openings) for (const s of path) out += bytesToHex(s)
  return out
}

/**
 * The openings from an `mp` segment for an axis of LCA height `height`
 * (spec 8.5). Null when malformed, and null for a v1 segment (one path
 * rather than nine), which spec 6.15 says must be rejected.
 */
export function decodeOpenings(segment: string, height: number): Uint8Array[][] | null {
  if (height === 0) return segment === '' ? [] : null
  if (!/^[0-9a-f]*$/.test(segment)) return null
  const per = 64 * height
  if (segment.length !== per * (SIDESTEP_SAMPLES + 1)) return null
  const out: Uint8Array[][] = []
  for (let p = 0; p < SIDESTEP_SAMPLES + 1; p++) {
    const path: Uint8Array[] = []
    for (let level = 0; level < height; level++) {
      const at = p * per + level * 64
      path.push(hexToBytes(segment.slice(at, at + 64)))
    }
    out.push(path)
  }
  return out
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
 * feasibility ceiling: a sidestep is always storable, only ever slow. The
 * openings add nine small rebuilds per axis, not counted here.
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
 * toward `target`: exactly 1 gibson past that boundary (spec 6.3). Upward
 * that is the adjacent subtree's first leaf; downward its last.
 */
export function sidestepLanding(v1: bigint, target: bigint): bigint {
  const h = findLcaHeight(v1, target)
  if (h === 0) return v1
  const hb = BigInt(h - 1)
  const childBase = (v1 >> hb) << hb
  return target > v1 ? childBase + (1n << hb) : childBase - 1n
}

/**
 * Spec 6.3 on one axis: with h the LCA height of the pair, the source touches
 * the wall on its side (base + half - 1 going up, base + half going down) and
 * the destination is exactly one gibson past it. An axis that does not move
 * is a valid trivial crossing.
 */
export function validCrossing(v1: bigint, v2: bigint): boolean {
  const h = findLcaHeight(v1, v2)
  if (h === 0) return true
  const base = alignedBase(v1, h)
  const half = 1n << BigInt(h - 1)
  return v2 > v1 ? v1 === base + half - 1n && v2 === base + half : v1 === base + half && v2 === base + half - 1n
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
  /** Per-axis openings (spec 6.10): destination path first, then the samples. */
  openings: { x: Uint8Array[][]; y: Uint8Array[][]; z: Uint8Array[][] }
}

/** The temporal seed and its Cantor root (spec 6.7), shared with hops. */
function temporal(previousEventIdHex: string, K: number, onProgress?: ProgressFn): { t: bigint; cantorT: bigint } {
  const prevIdInt = bytesToBigInt(hexToBytes(previousEventIdHex))
  const axisMask = (1n << BigInt(AXIS_BITS)) - 1n
  const t = prevIdInt & axisMask // mod 2^85
  return { t, cantorT: computeSubtreeCantor(alignedBase(t, K), K, TEMPORAL_MAX_COMPUTE_HEIGHT, onProgress) }
}

/**
 * Compute a full sidestep proof: per-axis seeded Merkle roots and openings,
 * combined into region_m, plus the temporal Cantor binding identical to hop
 * proofs (spec 6.4 - 6.10).
 */
export function computeSidestepProof(
  x1: bigint, y1: bigint, z1: bigint,
  x2: bigint, y2: bigint, z2: bigint,
  plane: Plane,
  previousEventIdHex: string,
  onProgress?: ProgressFn,
): SidestepProof {
  if (previousEventIdHex.length !== 64) throw new Error('previousEventIdHex must be exactly 64 hex chars')
  const prevId = hexToBytes(previousEventIdHex)

  // Weight each stage's progress by its share of the hash work, mirroring
  // computeHopProof, so the reported fraction tracks elapsed cost.
  const hx = findLcaHeight(x1, x2)
  const hy = findLcaHeight(y1, y2)
  const hz = findLcaHeight(z1, z2)
  const tk = terrainK(x2, y2, z2, plane)
  const work = [axisHashCount(hx), axisHashCount(hy), axisHashCount(hz), subtreeLeafCount(tk)]
  const totalWork = work.reduce((a, b) => a + b, 0)

  let baseFraction = 0
  const stage = (i: number): ProgressFn | undefined => {
    if (!onProgress) return undefined
    const share = work[i] / totalWork
    const start = baseFraction
    baseFraction += share
    return (f: number) => onProgress(start + f * share)
  }

  const ax = computeAxisMerkleRoot(seedPrefix(prevId, AXIS_BYTE.x), AXIS_BYTE.x, x1, x2, stage(0))
  const ay = computeAxisMerkleRoot(seedPrefix(prevId, AXIS_BYTE.y), AXIS_BYTE.y, y1, y2, stage(1))
  const az = computeAxisMerkleRoot(seedPrefix(prevId, AXIS_BYTE.z), AXIS_BYTE.z, z1, z2, stage(2))

  const regionM = cantorPair(
    cantorPair(bytesToBigInt(ax.root), bytesToBigInt(ay.root)),
    bytesToBigInt(az.root),
  )
  const { t, cantorT } = temporal(previousEventIdHex, tk, stage(3))
  const sidestepN = cantorPair(regionM, cantorT)

  // Proof hash (spec 6.8): double SHA-256.
  const proofHash = bytesToHex(sha256(sha256(intToBytesBE(sidestepN))))
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
    openings: { x: ax.openings, y: ay.openings, z: az.openings },
  }
}

export interface SidestepClaim {
  from: { x: bigint; y: bigint; z: bigint }
  to: { x: bigint; y: bigint; z: bigint }
  plane: Plane
  previousEventIdHex: string
  /** The `mr` tag's three segments. */
  merkleRoots: [string, string, string]
  /** The `mp` tag's three segments. */
  openings: [string, string, string]
  /** The `hx`, `hy`, `hz` tags. */
  lcaHeights: [number, number, number]
  proofHash: string
}

/**
 * Level 1 verification of a sidestep event (spec 8.7.2), everything a
 * verifier can check in seconds: geometry, heights, each axis's openings
 * against the seeded leaves, and the proof hash rebuilt from the roots and
 * the temporal root. Returns the names of what failed; empty means valid. A
 * v1 event fails on its openings, as spec 6.15 requires.
 */
export function verifySidestepLevel1(claim: SidestepClaim): string[] {
  const failed: string[] = []
  if (claim.previousEventIdHex.length !== 64 || !/^[0-9a-f]+$/.test(claim.previousEventIdHex)) return ['previous_event_id']
  const prevId = hexToBytes(claim.previousEventIdHex)
  const axes: AxisName[] = ['x', 'y', 'z']
  const roots: bigint[] = []
  axes.forEach((axis, i) => {
    const v1 = claim.from[axis], v2 = claim.to[axis]
    const h = findLcaHeight(v1, v2)
    if (claim.lcaHeights[i] !== h) failed.push(`h${axis}`)
    if (!validCrossing(v1, v2)) failed.push(`geometry:${axis}`)
    const rootHex = claim.merkleRoots[i]
    if (!/^[0-9a-f]{64}$/.test(rootHex)) { failed.push(`mr:${axis}`); roots.push(0n); return }
    const root = hexToBytes(rootHex)
    roots.push(bytesToBigInt(root))
    const openings = decodeOpenings(claim.openings[i], h)
    if (!openings) { failed.push(`mp:${axis}`); return }
    if (!verifyAxisOpenings(seedPrefix(prevId, AXIS_BYTE[axis]), AXIS_BYTE[axis], v1, v2, root, openings)) failed.push(`openings:${axis}`)
  })
  if (failed.length) return failed
  const regionM = cantorPair(cantorPair(roots[0], roots[1]), roots[2])
  const K = terrainK(claim.to.x, claim.to.y, claim.to.z, claim.plane)
  const { cantorT } = temporal(claim.previousEventIdHex, K)
  const proofHash = bytesToHex(sha256(sha256(intToBytesBE(cantorPair(regionM, cantorT)))))
  if (proofHash !== claim.proofHash) failed.push('proof')
  return failed
}
