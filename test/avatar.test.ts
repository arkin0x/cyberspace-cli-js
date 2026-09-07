/**
 * avatar.test.ts - the work an avatar owes, pinned to fixtures/avatar_work.json,
 * which the Python core shares.
 */
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { AVATAR_KIND, avatarReach, avatarWork, leadingZeroBits, verifyAvatarWork } from '../src/avatar.js'

interface Vector { name: string; payload: { unit?: number; vertices: number[][]; ticks?: Array<number[] | number>; faces?: unknown[] }; reach: number; required: number }
const VECTORS: Vector[] = JSON.parse(readFileSync(new URL('./fixtures/avatar_work.json', import.meta.url), 'utf8'))

describe('avatarWork', () => {
  for (const v of VECTORS) {
    it(`${v.name}: reach ${v.reach}, ${v.required} bits`, () => {
      expect(avatarReach(v.payload)).toBeCloseTo(v.reach, 9)
      expect(avatarWork(v.payload)).toBe(v.required)
    })
  }
  it('prices reach hardest: each doubling costs six bits, detail three, and nothing under a gibson', () => {
    const one = VECTORS.find((v) => v.name === 'one gibson, plain')!.required
    expect(VECTORS.find((v) => v.name === 'half gibson, ticks')!.required).toBe(one)
    expect(VECTORS.find((v) => v.name === 'two gibsons')!.required - one).toBe(3)
    expect(VECTORS.find((v) => v.name === 'four gibsons')!.required - one).toBe(6)
  })
})

describe('leadingZeroBits', () => {
  it('counts as NIP-13 does', () => {
    expect(leadingZeroBits('0000ffff')).toBe(16)
    expect(leadingZeroBits('000f')).toBe(12)
    expect(leadingZeroBits('00')).toBe(8)
    expect(leadingZeroBits('1abc')).toBe(3)
    expect(leadingZeroBits('ffff')).toBe(0)
    expect(leadingZeroBits('')).toBe(0)
  })
})

describe('verifyAvatarWork', () => {
  const payload = VECTORS.find((v) => v.name === 'one gibson, plain')!.payload
  const content = JSON.stringify(payload)
  const id = (zeros: number): string => '0'.repeat(zeros / 4) + 'f'.repeat(64 - zeros / 4)
  const ev = (zeros: number, committed: string | null, kind = AVATAR_KIND, body = content) => ({
    kind, id: id(zeros), content: body,
    tags: committed === null ? [['d', 'avatar']] : [['d', 'avatar'], ['nonce', '12345', committed]],
  })
  it('accepts a paid avatar: the committed target covers what the shape owes and the id carries it', () => {
    expect(verifyAvatarWork(ev(16, '16'))).toMatchObject({ ok: true, required: 16, committed: 16, zeros: 16 })
    expect(verifyAvatarWork(ev(20, '16')).ok).toBe(true)
  })
  it('refuses an id short of its commitment, a commitment short of the price, and no commitment', () => {
    expect(verifyAvatarWork(ev(16, '20')).reason).toBe('unpaid')
    expect(verifyAvatarWork(ev(20, '12')).reason).toBe('under-committed')
    expect(verifyAvatarWork(ev(20, null)).reason).toBe('no-nonce')
  })
  it('is not fooled by a lucky id claimed against a lower bar', () => {
    // 20 zeros on the id, but the miner committed to 12 while the shape owes 16.
    expect(verifyAvatarWork(ev(20, '12')).ok).toBe(false)
  })
  it('does not judge other kinds or junk', () => {
    expect(verifyAvatarWork(ev(20, '16', 1)).reason).toBe('not-an-avatar')
    expect(verifyAvatarWork(ev(20, '16', AVATAR_KIND, 'not json')).reason).toBe('not-an-avatar')
    expect(verifyAvatarWork(ev(20, '16', AVATAR_KIND, '{"vertices":"no"}')).reason).toBe('not-an-avatar')
  })
})
