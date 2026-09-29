"""cg.py <cg.sh output> [a b] [top]: compare two sides' instructions per query.

Per side, the median Ir/query over its runs and their range; then, per
function, the median Ir/query of b's runs less a's, largest first (top 20).
Functions are grouped by name across files and generic instances; a function
inlined into another is counted in its caller. Sides default to the order
they first appear in; a is the baseline.
"""
import collections as C, re, statistics as st, subprocess, sys

runs = C.defaultdict(list)
for line in open(sys.argv[1]):
    p = line.split()
    if len(p) == 5 and p[0].isdigit():
        runs[p[1]].append((int(p[2]) / int(p[3]), p[4], int(p[3])))
a, b = sys.argv[2:4] if len(sys.argv) >= 4 else list(runs)[:2]
top = int(sys.argv[4]) if len(sys.argv) >= 5 else 20

for s in (a, b):
    v = [r[0] for r in runs[s]]
    print(f"  {s:>8} {st.median(v):9.0f} Ir/query  range {min(v):.0f}-{max(v):.0f}  runs {len(v)}")
ma, mb = (st.median(r[0] for r in runs[s]) for s in (a, b))
print(f"  {b} - {a}: {mb - ma:+.0f} Ir/query ({100 * (mb / ma - 1):+.2f}%)")

line = re.compile(r'\s*([\d,]+)\s+(?:\([^)]*\)\s+)?(?:\S*:)?(.+?)(?:\s+\[.*\])?$')


def functions(path, queries):
    out = subprocess.run(['callgrind_annotate', '--auto=no', '--inclusive=no', '--threshold=100', '--show-percs=no', path],
                         capture_output=True, text=True, check=True).stdout
    per = C.Counter()
    for l in out.split('file:function', 1)[-1].splitlines()[2:]:
        if not l.strip():
            break
        if m := line.match(l):
            per[re.sub(r'__func_\d+|__anon_\d+', '', m.group(2))] += int(m.group(1).replace(',', '')) / queries
    return per


fa, fb = ([functions(f, q) for _, f, q in runs[s]] for s in (a, b))
med = lambda runs_, k: st.median(r.get(k, 0) for r in runs_)
delta = {k: med(fb, k) - med(fa, k) for k in set().union(*fa, *fb)}
print(f"  {'Δ Ir/q':>8} {a + ' Ir/q':>10}  function")
for k, d in sorted(delta.items(), key=lambda kv: -abs(kv[1]))[:top]:
    print(f"  {d:+8.1f} {med(fa, k):10.1f}  {k[:110]}")
