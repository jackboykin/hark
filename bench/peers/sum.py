import sys, glob, re, statistics as st, collections as C
rows = C.defaultdict(lambda: C.defaultdict(list))
for f in glob.glob(sys.argv[1] + '/*.txt'):
    n, l, r, _ = f.split('/')[-1].split('.')
    t = open(f).read()
    q = re.search(r'Queries per second:\s+([\d.]+)', t)
    cpu = re.search(r'cpu_pct (\d+)', t)
    lost = re.search(r'Queries lost:\s+(\d+)', t)
    noerr = re.search(r'NOERROR (\d+) \(([\d.]+)%\)', t)
    d = rows[n]
    if q: d[l+'_qps'].append(float(q.group(1)))
    if cpu: d[l+'_cpu'].append(int(cpu.group(1)))
    if noerr: d[l+'_ok'].append(float(noerr.group(2)))
    if l == 'lat':
        lat = sorted(float(m) for m in re.findall(r'^> \w+ \S+ \S+ ([\d.]+)', t, re.M))
        if lat:
            for p in (50, 99, 99.9): d[f'p{p}'].append(lat[min(len(lat)-1, int(len(lat)*p/100))]*1e6)
med = lambda v: st.median(v) if v else float('nan')
print(f"{'':8}{'hit qps':>10}{'cpu%':>6}{'ok%':>6}  {'miss qps':>9}{'cpu%':>6}{'ok%':>6}  {'p50µs':>6}{'p99µs':>7}{'p99.9':>7}  runs")
for n, d in sorted(rows.items(), key=lambda x: -med(x[1]['hit_qps'])):
    print(f"{n:8}{med(d['hit_qps']):>10.0f}{med(d['hit_cpu']):>6.0f}{med(d['hit_ok']):>6.1f}  {med(d['miss_qps']):>9.0f}{med(d['miss_cpu']):>6.0f}{med(d['miss_ok']):>6.1f}  {med(d['p50']):>6.0f}{med(d['p99']):>7.0f}{med(d['p99.9']):>7.0f}  {len(d['hit_qps'])}  hit={[round(x/1000) for x in d['hit_qps']]}k")
