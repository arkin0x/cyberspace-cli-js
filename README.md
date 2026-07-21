# cyberspace-core

TypeScript implementation of the [Cyberspace Protocol v2](https://github.com/arkin0x/cyberspace) core primitives.

Zero runtime dependencies. Runs identically in Node, browsers and web workers, which is what lets ONOSENDAI-V2 compute movement proofs off the main thread.

## What is here

| Module | Responsibility |
| --- | --- |
| `cantor.ts` | Cantor pairing, synchronous pure-JS SHA-256, byte/hex helpers |
| `coords.ts` | 256-bit interleaved coordinates (85-bit X/Y/Z + plane bit) |
| `movement.ts` | LCA height, Cantor subtree roots, spatial and 4D hop proofs |
| `terrain.ts` | Deterministic terrain-derived temporal height K, in [0, 16] |
| `sector.ts` | Sector partitioning (default 2^30 axis-units per side) |
| `location_encryption.ts` | Region key derivation from Cantor roots |

## Usage

```ts
import { computeHopProof, estimateHopCost } from 'cyberspace-core'

// Check the cost before paying it.
const cost = estimateHopCost(0n, 0n, 0n, 4104n, 0n, 0n, 0)
// => { lcaX: 13, terrainK: 11, maxHeight: 13, totalOps: 10238, exceedsLimit: false }

const proof = computeHopProof(0n, 0n, 0n, 4104n, 0n, 0n, 0, '0'.repeat(64))
// => proof.proofHash === 'ed9d09ca697b2da29c9d042207ac8ef7aab40f6dde550e6467452aa0e2e8cac6'
```

Movement cost is `O(2^h)` where `h` is the LCA height, so `computeHopProof` and
`computeSubtreeCantor` accept an optional progress callback. Use it from a
worker to stream live stats instead of freezing the UI.

## Cantor convention

`pi(a, b) = (a + b)(a + b + 1) / 2 + b`

The `+ b` term matters. The previous `test_vectors.js` asserted `pi(0,1) = 1`
and `pi(1,0) = 2`, which implies `+ a`. That was a transcription error that went
unnoticed because the file imported from `../src/*` while the sources lived at
the repo root, so the suite never ran. Two golden vectors independently settle
the convention as `+ b`:

- `pi(100, 101) = 20402` (`+ a` would give `20401`)
- `computeAxisCantor(0, 3) = 228` (`+ a` would give `172`)

Every proof hash in the suite depends on this.

## Provenance

Ported from the CommonJS `cyberspace-cli-js` sources, which were themselves
ported from the Python `cyberspace-cli`. The golden vectors in
`test/vectors.test.ts` are the cross-implementation contract: they must produce
byte-identical results to the Python implementation.

## Development

```sh
npm install
npm test        # golden vectors
npm run typecheck
npm run build   # emits dist/ with declarations
```
