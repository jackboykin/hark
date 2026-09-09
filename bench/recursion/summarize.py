#!/usr/bin/env python3
"""Print answered%, rcodes and latency percentiles per shotgun run: summarize.py outputs/*/data/UDP.json"""
import json, sys, math
def pct(h, p):
    total = sum(h); k = math.ceil((100 - p) / 100 * total - 1); acc = 0
    for lat, n in reversed(list(enumerate(h))):
        acc += n
        if k < acc: return lat
    return 0
for f in sys.argv[1:]:
    d = json.load(open(f)); s = d['stats_sum']; h = s['latency']
    secs = (s['until_ms'] - s['since_ms']) / 1000
    print(f"{f.split('/')[-3]:22} req={s['requests']} ans={s['answers']} ({100*s['answers']/s['requests']:.1f}%)"
          f" qps={s['answers']/secs:.1f} noerr={s['rcode_noerror']} nx={s['rcode_nxdomain']} sf={s['rcode_servfail']}"
          f" | p50={pct(h,50)} p90={pct(h,90)} p95={pct(h,95)} p99={pct(h,99)} p99.5={pct(h,99.5)} max={max(i for i,n in enumerate(h) if n)} ms")
