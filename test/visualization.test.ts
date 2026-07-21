/**
 * visualization.test.ts — regression against the spec's own visualization
 * vectors.
 *
 * CYBERSPACE_V2.md section 11.4 points implementations at
 * `visualization_vectors.json` for "quick regression tests and
 * cross-implementation debugging". The fixture here is a verbatim copy from the
 * spec repo (github.com/arkin0x/cyberspace); re-copy it if the spec updates.
 *
 * The vectors are centred on AXIS_CENTER (2^84) with delta 2^82, and exercise
 * each signed axis in both planes. They are the cheapest available check that
 * this port agrees with other viewers about which way is which.
 */

import { describe, it, expect } from 'vitest'
import { coordToHex, coordToXyz, hexToCoord, type Plane } from '../src/coords.js'
import vectors from './fixtures/visualization_vectors.json'

interface VizVector {
  name: string
  plane: number
  x_u85: string
  y_u85: string
  z_u85: string
  x_km_from_center: number
  y_km_from_center: number
  z_km_from_center: number
  coord_hex: string
}

const AXIS_CENTER = 1n << 84n
const DELTA = BigInt(vectors.delta_u85)

describe('spec visualization vectors', () => {
  const list = vectors.vectors as VizVector[]

  it('covers both planes across all six signed axes', () => {
    expect(list).toHaveLength(14)
  })

  it.each(list.map((v) => [v.name, v] as const))('decodes %s', (_name, v) => {
    const decoded = coordToXyz(hexToCoord(v.coord_hex))
    expect(decoded.x).toBe(BigInt(v.x_u85))
    expect(decoded.y).toBe(BigInt(v.y_u85))
    expect(decoded.z).toBe(BigInt(v.z_u85))
    expect(decoded.plane).toBe(v.plane as Plane)
  })

  it.each(list.map((v) => [v.name, v] as const))('re-encodes %s', (_name, v) => {
    const encoded = coordToHex(
      // Round-trip through the decoder so encode and decode are checked as a pair.
      hexToCoord(v.coord_hex),
    )
    expect(encoded).toBe(v.coord_hex)
  })

  it('places the axis offsets exactly delta away from centre', () => {
    for (const v of list) {
      const axis = v.name.replace(' (plane=1)', '')
      if (axis === 'center') {
        expect(BigInt(v.x_u85)).toBe(AXIS_CENTER)
        expect(BigInt(v.y_u85)).toBe(AXIS_CENTER)
        expect(BigInt(v.z_u85)).toBe(AXIS_CENTER)
        continue
      }

      const sign = axis.startsWith('+') ? 1n : -1n
      const which = axis[1] as 'x' | 'y' | 'z'
      const values = { x: BigInt(v.x_u85), y: BigInt(v.y_u85), z: BigInt(v.z_u85) }

      for (const key of ['x', 'y', 'z'] as const) {
        const expected = key === which ? AXIS_CENTER + sign * DELTA : AXIS_CENTER
        expect(values[key]).toBe(expected)
      }
    }
  })

  it('agrees on the sign of the physical km offsets', () => {
    for (const v of list) {
      const axis = v.name.replace(' (plane=1)', '')
      if (axis === 'center') continue
      const sign = axis.startsWith('+') ? 1 : -1
      const km = {
        x: v.x_km_from_center,
        y: v.y_km_from_center,
        z: v.z_km_from_center,
      }[axis[1] as 'x' | 'y' | 'z']
      expect(Math.sign(km)).toBe(sign)
    }
  })

  it('sets the plane bit without disturbing the XYZ interleave', () => {
    // Section 11.2: "The plane bit does not affect XYZ decoding; it only labels
    // the plane." The plane=0 and plane=1 vectors differ in bit 0 alone.
    const byName = new Map(list.map((v) => [v.name, v]))
    for (const v of list) {
      if (v.plane !== 1) continue
      const base = byName.get(v.name.replace(' (plane=1)', ''))
      expect(base).toBeDefined()
      expect(hexToCoord(v.coord_hex) ^ hexToCoord(base!.coord_hex)).toBe(1n)
    }
  })
})
