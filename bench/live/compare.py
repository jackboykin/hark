import collections, glob, json, os, re, statistics as st, sys

out, A, B = sys.argv[1:4]
sides = (A, B)

def pct(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(p / 100 * len(v)))] if v else 0

def failed(x):
    return x[0].startswith(("TIMEOUT", "ERROR"))

def shape(ans):
    return sorted({a.rsplit("|", 1)[0] for a in ans})

def bucket(a, b):
    if a[0] == b[0] and failed(a):
        return f"both {a[0]}"
    if a[0] != b[0]:
        return f"rcode {a[0]}/{b[0]}"
    if a[1] != b[1]:
        return f"ad {int(a[1])}/{int(b[1])}"
    if shape(a[3]) != shape(b[3]):
        return "shape"
    return "same" if a[3] == b[3] else "addresses"

passes = collections.defaultdict(list)
for f in sorted(glob.glob(f"{out}/*.jsonl")):
    passes[f.rsplit(".", 2)[-2]].append([json.loads(l) for l in open(f)])
cold = [row for rnd in passes["cold"] for row in rnd]

print(f"{'':22s} {A:>10s} {B:>10s}")
for name, rounds in passes.items():
    ms = [[r["r"][i][4] for rnd in rounds for r in rnd if not failed(r["r"][i])] for i in (0, 1)]
    for p in (50, 90, 99):
        o, n = pct(ms[0], p), pct(ms[1], p)
        print(f"{name} ms p{p:<14} {o:10.1f} {n:10.1f}  {100 * (n - o) / o if o else 0:+.1f}%")

d = [collections.defaultdict(list), collections.defaultdict(list)]
for rnd in passes["cold"]:
    for i in (0, 1):
        d[i]["cold ad"].append(sum(r["r"][i][1] for r in rnd))
        d[i]["cold servfail"].append(sum(r["r"][i][0] == "SERVFAIL" for r in rnd))
        d[i]["cold failed"].append(sum(failed(r["r"][i]) for r in rnd))
for i, side in enumerate(sides):
    for base in sorted(glob.glob(f"{out}/{side}.*.mem")):
        base = base[: -len(".mem")]
        mem = dict(l.split(":") for l in open(base + ".mem"))
        d[i]["VmHWM KiB"].append(int(mem["VmHWM"].split()[0]))
        log = open(base + ".log").read()
        m = re.findall(r"stats resolver\s+(\d+) exchanges\s+udp (\d+)\s+tcp (\d+) \| timeout (\d+)", log)
        if m:
            d[i]["exchanges"].append(int(m[-1][0]))
            d[i]["upstream tcp"].append(int(m[-1][2]))
            d[i]["upstream timeouts"].append(int(m[-1][3]))
        t = re.findall(r"stats trust\s+secure (\d+)\s+insecure (\d+)\s+bogus (\d+)", log)
        if t:
            d[i]["bogus"].append(int(t[-1][2]))
        s = re.findall(r"stats store\s+(\d+) KiB in (\d+) facts", log)
        if s:
            d[i]["store KiB"].append(int(s[-1][0]))
            d[i]["store facts"].append(int(s[-1][1]))
for k in ["cold ad", "cold servfail", "cold failed", "exchanges", "upstream tcp", "upstream timeouts", "bogus", "store KiB", "store facts", "VmHWM KiB"]:
    o, n = (f"{st.median(x[k]):10.1f}" if x.get(k) else f"{'-':>10s}" for x in d)
    print(f"{k:22s} {o} {n}")

per = collections.defaultdict(lambda: ([], []))
for r in cold:
    for i in (0, 1):
        per[r["n"]][i].append(r["r"][i][4])
moved = sorted((st.median(b) - st.median(a), n) for n, (a, b) in per.items())
print(f"{B} faster most:", [(n, round(v)) for v, n in moved[:6]])
print(f"{B} slower most:", [(n, round(v)) for v, n in moved[-6:]])
print(f"names {B} is faster on (median cold): {sum(v < 0 for v, _ in moved)}/{len(moved)}")

buckets = collections.defaultdict(list)
for r in cold:
    buckets[bucket(*r["r"])].append(r["n"])
agree = {"same", "addresses"}
print(f"cold answers, {len(cold)} over {len(passes['cold'])} rounds:")
for b, names in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
    print(f"  {len(names):8}  {b}" + ("" if b in agree else "  e.g. " + " ".join(sorted(set(names))[:4])))
ede = collections.Counter((sides[i], e) for r in cold for i in (0, 1) for e in r["r"][i][2])
print("ede:", dict(ede.most_common(12)))
with open(os.path.join(out, "disagree.tsv"), "w") as f:
    for b, names in buckets.items():
        if b not in agree:
            for n in sorted(set(names)):
                f.write(f"{b}\t{n}\n")
