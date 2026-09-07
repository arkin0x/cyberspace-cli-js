/**
 * fold.test.ts - the folded Cantor subtree is the level-by-level tree, bit
 * for bit, and holds no more than one partial root per level.
 */
import { describe, expect, it } from 'vitest'
import { cantorPair } from '../src/cantor.js'
import { computeSubtreeCantor } from '../src/movement.js'

/** The tree as it used to be built: every leaf, then a level at a time. */
function levelByLevel(base: bigint, height: number): bigint {
  let values: bigint[] = []
  for (let i = 0; i < 2 ** height; i++) values.push(base + BigInt(i))
  while (values.length > 1) {
    const next: bigint[] = []
    for (let i = 0; i < values.length; i += 2) next.push(cantorPair(values[i], values[i + 1]))
    values = next
  }
  return values[0]
}

const rnd85 = (): bigint => { let v = 0n; for (let i = 0; i < 85; i++) v = (v << 1n) | BigInt(Math.random() < 0.5 ? 0 : 1); return v }

describe('computeSubtreeCantor as a fold', () => {
  it('equals the level-by-level tree for random bases at every height to 12', () => {
    for (let h = 0; h <= 12; h++) {
      for (let k = 0; k < 8; k++) {
        const base = rnd85() & ~((1n << BigInt(h)) - 1n)
        expect(computeSubtreeCantor(base, h, 30), `h${h}`).toBe(levelByLevel(base, h))
      }
    }
  })
  it('is the pairing of its two halves', () => {
    const base = (1n << 84n) + 4096n
    for (let h = 1; h <= 10; h++) {
      const half = 1n << BigInt(h - 1)
      expect(computeSubtreeCantor(base, h, 30)).toBe(cantorPair(computeSubtreeCantor(base, h - 1, 30), computeSubtreeCantor(base + half, h - 1, 30)))
    }
  })
})
