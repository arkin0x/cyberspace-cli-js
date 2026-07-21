/**
 * sector.ts — Sector utilities for spatial partitioning.
 *
 * Sectors are fixed-size cubic cells in the axis space.
 * Default: 2^30 axis-units per sector side.
 */

import { coordToXyz, type Plane } from './coords.js'

export const SECTOR_BITS_DEFAULT = 30

export interface SectorId {
  sx: bigint
  sy: bigint
  sz: bigint
}

export interface SectorBounds {
  xRange: [bigint, bigint]
  yRange: [bigint, bigint]
  zRange: [bigint, bigint]
}

/**
 * Compute the sector ID for (x, y, z).
 */
export function xyzToSectorId(
  x: bigint,
  y: bigint,
  z: bigint,
  sectorBits: number = SECTOR_BITS_DEFAULT,
): SectorId {
  const shift = BigInt(sectorBits)
  return { sx: x >> shift, sy: y >> shift, sz: z >> shift }
}

/**
 * Get sector tag string.
 */
export function sectorTag(sid: SectorId): string {
  return `${sid.sx}-${sid.sy}-${sid.sz}`
}

/**
 * Get sector ID and plane from a 256-bit coord.
 */
export function coordToSectorId(
  coord: bigint,
  sectorBits: number = SECTOR_BITS_DEFAULT,
): { sector: SectorId; plane: Plane } {
  const { x, y, z, plane } = coordToXyz(coord)
  return { sector: xyzToSectorId(x, y, z, sectorBits), plane }
}

/**
 * Get inclusive bounds for the sector containing (x, y, z).
 */
export function xyzToSectorBounds(
  x: bigint,
  y: bigint,
  z: bigint,
  sectorBits: number = SECTOR_BITS_DEFAULT,
): SectorBounds {
  const shift = BigInt(sectorBits)
  const size = 1n << shift

  const bx = (x >> shift) << shift
  const by = (y >> shift) << shift
  const bz = (z >> shift) << shift

  return {
    xRange: [bx, bx + size - 1n],
    yRange: [by, by + size - 1n],
    zRange: [bz, bz + size - 1n],
  }
}
