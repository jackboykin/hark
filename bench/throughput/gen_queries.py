#!/usr/bin/env python3
"""Query-file generator for the hark throughput bench.

Workloads:
  hit  — small fixed name set, reaches steady state as cache hits after warm-up.
  miss — 200k unique random names; with cache.entries=10000 every query churns.
  mix  — 50/50 hit-able vs miss-able; tests cache locality under load.

Output goes to stdout in dnsperf query-file format: "<name> <type>" per line.
Seed is fixed so any baseline is reproducible across re-runs.
"""

import random
import string
import sys

SEED = 42
N_QUERIES = 200_000
# Must match the warm-up loop in run.sh — names host1..hostN are primed before
# `hit` and `mix` runs, so anything beyond the warmed range would arrive cold
# and skew early samples.
HIT_SET_SIZE = 8


def random_name(rng: random.Random) -> str:
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=12))


def main(workload: str) -> int:
    rng = random.Random(SEED)
    if workload == "hit":
        # 8 stable names — enough to exercise multiple cache shards but small
        # enough to fully fit and remain hit-only after warm-up.
        for i in range(1, 9):
            print(f"host{i}.bench. A")
    elif workload == "miss":
        for _ in range(N_QUERIES):
            print(f"{random_name(rng)}.bench. A")
    elif workload == "mix":
        hits = [f"host{i}.bench. A" for i in range(1, HIT_SET_SIZE + 1)]
        for _ in range(N_QUERIES):
            if rng.random() < 0.5:
                print(rng.choice(hits))
            else:
                print(f"{random_name(rng)}.bench. A")
    else:
        print(f"unknown workload: {workload} (use hit | miss | mix)", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <hit|miss|mix>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
