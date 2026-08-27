/**
 * progress.test.ts - the movement proof's progress reporting.
 *
 * These are not cosmetic properties. A bar that reaches 100% and then leaves
 * the app silent for half the wall clock is indistinguishable from a hang, and
 * that is exactly what a height-18 hop did: the bar was charged by node count,
 * so the bottom level of the tree alone read 75%, and the combination after
 * the four trees, which is over half the time, was charged nothing at all.
 */
import { describe, expect, it } from 'vitest'
import { computeHopProof, computeSubtreeCantor } from '../src/movement.js'
import { intToBytesBE } from '../src/cantor.js'

/** Every fraction a computation reported, in order. */
function record(run: (onProgress: (f: number) => void) => void): number[] {
  const seen: number[] = []
  run((f) => seen.push(f))
  return seen
}

describe('computeSubtreeCantor progress', () => {
  const base = (1n << 84n) + 12345n

  it('never goes backwards and ends at 1', () => {
    const seen = record((p) => computeSubtreeCantor(base, 8, 20, p))
    expect(seen.length).toBeGreaterThan(1)
    expect(seen.at(-1)).toBe(1)
    for (let i = 1; i < seen.length; i++) expect(seen[i]).toBeGreaterThanOrEqual(seen[i - 1])
  })

  it('charges by level, so the bottom level is not most of the bar', () => {
    // Node count would put 2^7 of 2^8 pairings, and therefore about 75% of the
    // bar, in the first level. By level it is worth one ninth of a height-8
    // tree, leaf building included.
    const seen = record((p) => computeSubtreeCantor(base, 8, 20, p))
    const afterFirstLevel = seen.find((f) => f > 1 / 9 + 1e-9)
    expect(afterFirstLevel).toBeLessThan(0.35)
  })

  it('reports at every level, however few pairings that level has', () => {
    // The top levels are one, two and four pairings. Any throttle keyed to
    // node count falls silent there, which is where each step is slowest.
    const height = 10
    const seen = record((p) => computeSubtreeCantor(base, height, 20, p))
    const distinct = new Set(seen.map((f) => f.toFixed(6)))
    expect(distinct.size).toBeGreaterThanOrEqual(height)
  })
})

describe('computeHopProof progress', () => {
  const base = (1n << 84n) + 0x5555n
  const flip = (v: bigint): bigint => v ^ (1n << 7n)
  const prevId = 'a'.repeat(64)

  it('never goes backwards', () => {
    // The combination steps are charged after the axis trees and before the
    // temporal tree in the weighting, matching the order they actually run in.
    // Handing a slice out of order runs the bar backwards, which is worse than
    // a wrong bar because it looks like a fault.
    const seen = record((p) =>
      computeHopProof(base, base + 7n, base + 13n, flip(base), flip(base + 7n), flip(base + 13n), 0, prevId, 20, p),
    )
    expect(seen.length).toBeGreaterThan(4)
    for (let i = 1; i < seen.length; i++) {
      expect(seen[i], `report ${i} went backwards`).toBeGreaterThanOrEqual(seen[i - 1])
    }
    expect(seen.at(-1)).toBeCloseTo(1, 6)
  })

  it('keeps reporting after the last tree finishes', () => {
    // Over half a height-18 hop happens after the axis trees. The bar has to
    // still be moving there or the hop reads as frozen.
    const seen = record((p) =>
      computeHopProof(base, base + 7n, base + 13n, flip(base), flip(base + 7n), flip(base + 13n), 0, prevId, 20, p),
    )
    // The four trees are weighted 8+8+8+k+1 of a total that also carries 36
    // for the combination, so the last stretch of the bar belongs to work no
    // tree is doing.
    expect(seen.filter((f) => f > 0.6).length).toBeGreaterThanOrEqual(3)
  })
})

describe('intToBytesBE', () => {
  it('round trips through the nibble table exactly', () => {
    for (const n of [0n, 1n, 255n, 256n, 65535n, (1n << 84n) + 12345n, (1n << 300n) - 7n]) {
      const bytes = intToBytesBE(n)
      let back = 0n
      for (const b of bytes) back = (back << 8n) | BigInt(b)
      expect(back).toBe(n)
    }
  })

  it('handles both hex digit cases the table covers', () => {
    // 0xabcdef exercises a..f; the table also carries A..F for safety.
    expect(Array.from(intToBytesBE(0xabcdefn))).toEqual([0xab, 0xcd, 0xef])
    expect(Array.from(intToBytesBE(0x0fn))).toEqual([0x0f])
  })
})
