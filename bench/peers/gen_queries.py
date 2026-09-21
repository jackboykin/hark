import random, string, sys

rng = random.Random(42)
hits = [f"host{i}.bench. A" for i in range(1, 9)]
miss = lambda: "".join(rng.choices(string.ascii_lowercase + string.digits, k=14)) + ".bench. A"
workload, n = sys.argv[1], 2_000_000
lines = {
    "hit": lambda: hits,
    "miss": lambda: (miss() for _ in range(n)),
    "mix": lambda: (rng.choice(hits) if rng.random() < 0.5 else miss() for _ in range(n)),
}[workload]()
sys.stdout.write("\n".join(lines) + "\n")
