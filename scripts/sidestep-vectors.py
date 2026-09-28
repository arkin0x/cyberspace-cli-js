#!/usr/bin/env python3
"""Regenerates test/fixtures/sidestep_v3.json from the spec's sidestep-reference.py.

  python3 scripts/sidestep-vectors.py [path to a cyberspace clone] [ref] > test/fixtures/sidestep_v3.json

Defaults: ../cyberspace and origin/master. The reference is read from the ref
with git show, never from the clone's working tree. Each vector is a whole
crossing (section 6.10): the three seeded roots, the attempt count A, the first
nonce meeting the price searching upward from 0, G, and every axis's sample
indices and openings, destination first.
"""
import json
import subprocess
import sys
import types

repo = sys.argv[1] if len(sys.argv) > 1 else "../cyberspace"
ref = sys.argv[2] if len(sys.argv) > 2 else "origin/master"
git = lambda *a: subprocess.run(["git", "-C", repo, *a], check=True, capture_output=True, text=True).stdout
commit = git("rev-parse", f"{ref}^{{commit}}").strip()
ref_mod = types.ModuleType("sidestep_reference")
exec(git("show", f"{commit}:sidestep-reference.py"), ref_mod.__dict__)
R = ref_mod

ZERO, RANGE, BOB = bytes(32), bytes(range(32)), bytes(range(32, 64))
BASE12 = (0x1234567 >> 12) << 12
CROSSINGS = [
    # The spec's golden crossing: z crosses the h12 wall, A = 512, nonce 175.
    ("golden-z-h12", ZERO, (5, 7, BASE12 + (1 << 11) - 1), (5, 7, BASE12 + (1 << 11))),
    ("trivial", ZERO, (0, 0, 0), (0, 0, 0)),
    ("zero-z-h5", ZERO, (0, 0, 19087360), (0, 0, 19087376)),
    ("range-y-h9", RANGE, (5, 1 << 40, 9), (5, (1 << 40) + (1 << 8), 9)),
    ("range-x-h7-down", RANGE, (1000, 3, 3), (959, 3, 3)),
    ("range-z-h1", RANGE, (8, 8, 5), (8, 8, 4)),
    # L = 2^5 + 2^9 = 544 leaves, A = 68: not a power of two.
    ("bob-xz-h5-h9", BOB, (15, 7, 255), (16, 7, 256)),
    # L = 8 + 4 + 2 = 14, A = ceil(14 / 8) = 2.
    ("bob-xyz-h3-h2-h1", BOB, (3, 1, 0), (4, 2, 1)),
]

out = []
for name, prev, src, dst in CROSSINGS:
    geo = [R.axis_geometry(a, b) for a, b in zip(src, dst)]
    roots, nonce, openings = R.prove_sidestep(prev, src, dst)
    attempts = R.reroll_attempts(h for _, h in geo)
    G = R.grind_hash(prev, roots, nonce)
    out.append({
        "name": name,
        "prev": prev.hex(),
        "src": [str(v) for v in src],
        "dst": [str(v) for v in dst],
        "heights": [h for _, h in geo],
        "prefixes": [R.seed_prefix(prev, ax).hex() for ax in R.AXES],
        "roots": [r.hex() for r in roots],
        "attempts": str(attempts),
        "nonce": str(nonce),
        "G": G.hex(),
        "samples": [R.sample_indices(G, ax, h) if h else [] for ax, (_, h) in zip(R.AXES, geo)],
        "openings": [[[s.hex() for s in path] for path in axis] for axis in openings],
    })

json.dump({"source": f"arkin0x/cyberspace {commit} sidestep-reference.py", "vectors": out}, sys.stdout, indent=1)
print()
