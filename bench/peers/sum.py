import sys, glob, re, statistics as st, collections as C
rows = C.defaultdict(lambda: C.defaultdict(list))
for f in glob.glob(sys.argv[1] + '/*.txt'):
    n, l, r, _ = f.split('/')[-1].split('.')
    t = open(f).read()
    q = re.search(r'Queries per second:\s+([\d.]+)', t)
    busy = re.search(r'core_busy ([\d.]+)', t)
    lost = re.search(r'Queries lost:\s+(\d+)', t)
    noerr = re.search(r'NOERROR (\d+) \(([\d.]+)%\)', t)
    d = rows[n]
    if q: d[l+'_qps'].append(float(q.group(1)))
    if busy: d[l+'_busy'].append(float(busy.group(1)))
    if noerr: d[l+'_ok'].append(float(noerr.group(2)))
    # -O latency-histogram: "lo - hi:  count", each reply counted at its bucket's top.
    hist = [(float(hi), int(c)) for hi, c in re.findall(r'^\s+[\d.]+ - ([\d.]+):\s+(\d+)$', t, re.M)]
    if hist:
        total = sum(c for _, c in hist)
        for p in (50, 99, 99.9):
            seen = 0
            for hi, c in hist:
                seen += c
                if seen >= total * p / 100: break
            d[f'{l}_p{p}'].append(hi * 1e6)
med = lambda v: st.median(v) if v else float('nan')
print(f"{'':8}{'hit qps':>10}{'busy%':>6}{'ok%':>6}  {'miss qps':>9}{'busy%':>6}{'ok%':>6}  {'lat µs p50':>10}{'p99':>6}{'p99.9':>7}  {'70% p99':>8}{'p99.9':>7}  runs")
for n, d in sorted(rows.items(), key=lambda x: -med(x[1]['hit_qps'])):
    print(f"{n:8}{med(d['hit_qps']):>10.0f}{med(d['hit_busy']):>6.1f}{med(d['hit_ok']):>6.1f}  {med(d['miss_qps']):>9.0f}{med(d['miss_busy']):>6.1f}{med(d['miss_ok']):>6.1f}  {med(d['lat_p50']):>10.0f}{med(d['lat_p99']):>6.0f}{med(d['lat_p99.9']):>7.0f}  {med(d['load_p99']):>8.0f}{med(d['load_p99.9']):>7.0f}  {len(d['hit_qps'])}  hit={[round(x/1000) for x in d['hit_qps']]}k")
