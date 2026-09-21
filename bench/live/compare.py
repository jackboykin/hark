import sys, json, glob, re, statistics as st, collections
def pct(v, p):
    v = sorted(v); return v[min(len(v)-1, int(p/100*len(v)))]
out, A, B = sys.argv[1:4]
res = {}
for side in (A, B):
    d = collections.defaultdict(list); per = collections.defaultdict(list); rc = collections.Counter()
    for f in sorted(glob.glob(f'{out}/{side}.*.cold.json')):
        base = f[:-len('.cold.json')]
        for phase in ('cold', 'hot'):
            rows = json.load(open(f'{base}.{phase}.json'))
            ok = [r for r in rows if r[2] != 'TIMEOUT']
            d[phase + ' ms'] += [r[1] for r in ok]
            if phase == 'cold':
                d['cold ad'].append(sum(r[3] for r in rows)); d['cold servfail'].append(sum(r[2] == 'SERVFAIL' for r in rows)); d['cold timeout'].append(sum(r[2] == 'TIMEOUT' for r in rows))
                for r in rows: per[r[0]].append(r[1]); rc[(r[0], r[2])] += 1
        log = open(base + '.log').read()
        m = re.findall(r'stats resolver\s+(\d+) exchanges\s+udp (\d+)\s+tcp (\d+) \| timeout (\d+)\s+retry (\d+) \| refresh \d+(?:\s+keys (\d+))?', log)[-1]
        d['exchanges'].append(int(m[0])); d['upstream tcp'].append(int(m[2])); d['upstream timeouts'].append(int(m[3]))
        if m[5]: d['keys roots'].append(int(m[5]))
        t = re.findall(r'stats trust\s+secure (\d+)\s+insecure (\d+)\s+bogus (\d+)', log)[-1]
        d['bogus'].append(int(t[2]))
        s = re.findall(r'stats store\s+(\d+) KiB in (\d+) facts', log)[-1]
        d['store KiB'].append(int(s[0])); d['store facts'].append(int(s[1]))
        mem = dict(l.split(':') for l in open(base + '.mem'))
        d['VmHWM KiB'].append(int(mem['VmHWM'].split()[0]))
    res[side] = (d, per, rc)
print(f"{'':22s} {A:>10s} {B:>10s}")
for k in ['cold ms', 'hot ms']:
    for p in (50, 90, 99):
        o, n = pct(res[A][0][k], p), pct(res[B][0][k], p)
        print(f'{k} p{p:<14} {o:10.1f} {n:10.1f}  {100*(n-o)/o:+.1f}%')
for k in ['cold ad', 'cold servfail', 'cold timeout', 'exchanges', 'upstream tcp', 'upstream timeouts', 'keys roots', 'bogus', 'store KiB', 'store facts', 'VmHWM KiB']:
    o = res[A][0].get(k) or [0]; n = res[B][0].get(k) or [0]
    print(f'{k:22s} {st.median(o):10.1f} {st.median(n):10.1f}  (runs {len(o)}/{len(n)})')
# per-name medians: who moved most
po, pn = res[A][1], res[B][1]
diffs = sorted(((st.median(pn[x]) - st.median(po[x]), x) for x in po if x in pn))
print('faster most:', [(x, round(v)) for v, x in diffs[:6]])
print('slower most:', [(x, round(v)) for v, x in diffs[-6:]])
names = set(po) & set(pn)
faster = sum(st.median(pn[x]) < st.median(po[x]) for x in names)
print(f'names faster (median cold): {faster}/{len(names)}')
# rcode disagreements (majority per side)
def maj(rc, side_names):
    out = {}
    for (n, r), c in rc.items():
        if n not in out or c > out[n][1]: out[n] = (r, c)
    return out
mo, mn = maj(res[A][2], po), maj(res[B][2], pn)
print('majority rcode disagreements:', [(n, mo[n][0], mn[n][0]) for n in names if mo[n][0] != mn[n][0]])
