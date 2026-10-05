"""an.py <tp.sh output> [side...]: each side, then each against the first.

One layout a side: the per-round ratio, its median with a bootstrap 95% CI,
and a sign test. Several (layouts.sh): the difference of per-layout means,
bootstrapped over layouts, real only if the CI excludes 0 and |Δ| > 1%,
the reach of a relink.
"""
import collections as C, math, random, statistics as st, sys

runs = []
for line in open(sys.argv[1]):
    p = line.split()
    if len(p) < 10 or not p[0].isdigit():
        continue
    kv = dict(f.split('=', 1) for f in p[10:] if '=' in f)
    num = lambda k: float(kv[k]) if kv.get(k, '').replace('.', '', 1).isdigit() else None
    runs.append(dict(r=int(p[0]), side=p[1], lay=p[2], qps=float(p[3]), done=int(p[4]), lost=int(p[5]),
                     busy=float(p[6]), ins=num('instructions'), lat=[num(k) for k in ('p50', 'p99', 'p999')]))
sides = sys.argv[2:] or list(dict.fromkeys(r['side'] for r in runs))
by = C.defaultdict(list)
for r in runs:
    by[r['side']].append(r)

cv = lambda v: 100 * st.stdev(v) / st.mean(v) if len(v) > 1 else 0.0
pct = lambda x: f"{100 * (x - 1):+.2f}%"
random.seed(1)

def ci(v, stat, n=20000):
    boot = sorted(stat(random.choices(v, k=len(v))) for _ in range(n))
    return boot[n // 40], boot[n - n // 40]

print(sys.argv[1].split('/')[-1])
w = max(len(s) for s in sides)
for s in sides:
    q = [r['qps'] for r in by[s]]
    ipq = [r['ins'] / r['done'] for r in by[s] if r['ins'] and r['done']]
    lat = [st.median(v) for v in zip(*(r['lat'] for r in by[s])) if None not in v]
    unsat = sum(r['busy'] < 97 for r in by[s])
    print(f"  {s:>{w}} median {st.median(q):9.0f} qps  cv {cv(q):.2f}%  range {min(q):.0f}-{max(q):.0f}"
          f"  {1e6 / st.median(q):.3f} µs/query  busy min {min(r['busy'] for r in by[s]):.1f}%"
          f"  lost {sum(r['lost'] for r in by[s])}" + (f"  {st.median(ipq):.0f} ins/query" if ipq else "")
          + (f"  p50 {lat[0]:.0f} p99 {lat[1]:.0f} p99.9 {lat[2]:.0f} µs" if lat else "")
          + (f"  UNSATURATED {unsat}/{len(q)} runs <97% busy" if unsat and not lat else ""))

a = sides[0]
for b in sides[1:]:
    lays = {s: C.defaultdict(list) for s in (a, b)}
    for s in (a, b):
        for r in by[s]:
            lays[s][r['lay']].append(r['qps'])
    if max(len(lays[s]) for s in (a, b)) > 1:
        mean = {s: [st.mean(v) for v in lays[s].values()] for s in (a, b)}
        for s in (a, b):
            print(f"  {s:>{w}} {len(mean[s])} layouts, means {' '.join(f'{m:.0f}' for m in sorted(mean[s]))}  cv {cv(mean[s]):.2f}%")
        ratio = lambda: st.mean(random.choices(mean[b], k=len(mean[b]))) / st.mean(random.choices(mean[a], k=len(mean[a])))
        boot = sorted(ratio() for _ in range(20000))
        d, lo, hi = st.mean(mean[b]) / st.mean(mean[a]), boot[500], boot[19500]
        real = (lo > 1 or hi < 1) and abs(d - 1) > 0.01
        print(f"  layouts {b}/{a} {pct(d)}  95% CI [{pct(lo)}, {pct(hi)}]  {'REAL' if real else 'within layout noise'}")
        continue
    rounds = C.defaultdict(dict)
    for r in runs:
        rounds[r['r']][r['side']] = r['qps']
    ratio = [d[b] / d[a] for d in rounds.values() if a in d and b in d]
    n, wins = len(ratio), sum(x > 1 for x in ratio)
    p = min(1, 2 * sum(math.comb(n, k) for k in range(min(wins, n - wins) + 1)) / 2**n)
    lo, hi = ci(ratio, st.median)
    print(f"  paired {b}/{a} median {pct(st.median(ratio))}  95% CI [{pct(lo)}, {pct(hi)}]"
          f"  {b} faster {wins}/{n}, sign p={p:.3f}")
