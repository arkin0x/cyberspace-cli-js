/**
 * location_encryption.ts — Location-based encryption key derivation.
 *
 * Derives region keys from Cantor tree roots at various heights.
 * Encryption uses AES-256-GCM (not implemented here, key derivation only).
 */

import { cantorPair, intToBytesBE, sha256, bytesToHex } from './cantor.js'
import { computeSubtreeCantor, alignedBase, DEFAULT_MAX_COMPUTE_HEIGHT } from './movement.js'

export interface RegionKeys {
  locationDecryptionKey: Uint8Array
  lookupIdHex: string
}

export interface RegionKeyMaterial extends RegionKeys {
  height: number
  regionN: bigint
}

/**
 * Derive region_n for a given height from (x, y, z).
 */
export function deriveRegionN(
  x: bigint,
  y: bigint,
  z: bigint,
  height: number,
  maxComputeHeight: number = DEFAULT_MAX_COMPUTE_HEIGHT,
): bigint {
  if (height < 0) throw new Error('height must be >= 0')

  const rx = computeSubtreeCantor(alignedBase(x, height), height, maxComputeHeight)
  const ry = computeSubtreeCantor(alignedBase(y, height), height, maxComputeHeight)
  const rz = computeSubtreeCantor(alignedBase(z, height), height, maxComputeHeight)
  return cantorPair(cantorPair(rx, ry), rz)
}

/**
 * Derive encryption key and lookup ID from a region_n.
 */
export function deriveRegionKeys(regionN: bigint): RegionKeys {
  const locationDecryptionKey = sha256(intToBytesBE(regionN))
  const lookupIdHex = bytesToHex(sha256(locationDecryptionKey))
  return { locationDecryptionKey, lookupIdHex }
}

/**
 * Derive full key material for a given height.
 */
export function deriveRegionKeyMaterial(
  x: bigint,
  y: bigint,
  z: bigint,
  height: number,
  maxComputeHeight: number = DEFAULT_MAX_COMPUTE_HEIGHT,
): RegionKeyMaterial {
  const regionN = deriveRegionN(x, y, z, height, maxComputeHeight)
  return { height, regionN, ...deriveRegionKeys(regionN) }
}

/**
 * Scan a range of heights and derive key material for each.
 */
export function deriveRegionKeyMaterialScan(
  x: bigint,
  y: bigint,
  z: bigint,
  minHeight: number,
  maxHeight: number,
  maxComputeHeight: number = DEFAULT_MAX_COMPUTE_HEIGHT,
): RegionKeyMaterial[] {
  if (minHeight < 0) throw new Error('minHeight must be >= 0')
  if (maxHeight < minHeight) throw new Error('maxHeight must be >= minHeight')

  const results: RegionKeyMaterial[] = []
  for (let h = minHeight; h <= maxHeight; h++) {
    results.push(deriveRegionKeyMaterial(x, y, z, h, maxComputeHeight))
  }
  return results
}
