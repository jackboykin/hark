"""overload.py <overload.sh OUT dir>: one row per run, pass/fail per criterion.

  loss  probe loses nothing up to 4x the ceiling
  p99   probe p99 <= P99_MS (7: 5 ms plus 2 ms slack) at every level
  good  miss goodput >= 0.95x the ceiling at every level
  acct  hark's unsent (dropped + abandoned + late + reaped) plus kernel drops
        on the listener and the generators equals offered - answered within 0.1%
  unsat the core was under 97% busy: at 1x and above the load did not reach
        hark, so the run proves nothing
A ceiling measured on an unsaturated core invalidates the whole series.
"""
import glob, os, re, sys

D = sys.argv[1]
P99 = float(os.environ.get('P99_MS', 7))
meta = dict(kv.split('=') for kv in open(f'{D}/meta').read().split())
ceiling, length = float(meta['ceiling']), float(meta['len'])
num = lambda key, text: int((re.search(key + r':\s+(\d+)', text) or [0, 0])[1])
# A counter an older build does not print counts 0.
unsent = lambda line: sum(int((re.search(k + r' (\d+)', line) or [0, 0])[1]) for k in ('dropped', 'abandoned', 'late', 'reaped'))

cbusy = float((re.search(r'busy ([\d.]+)', open(f'{D}/ceiling').read()) or [0, 0])[1])
if cbusy < 97: sys.exit(f"INVALID: the miss ceiling ({ceiling:.0f} qps) was measured at {cbusy:.1f}% core busy")
print(f"miss ceiling {ceiling:.0f} qps (closed loop, {cbusy:.1f}% busy), {length:.0f} s per run")
print(f"{'lvl':>3} {'run':>3} {'offered':>8} {'goodput':>8} {'g/ceil':>6}  {'probe':>6} {'p50ms':>6} {'p99ms':>6}"
      f"  {'rxq KB':>6} {'k.drops':>8} {'unsent':>7} {'acct':>6} {'busy':>5}  verdict")
fails = runs = 0
for f in sorted(glob.glob(f'{D}/*.probe'), key=lambda p: [int(x) for x in os.path.basename(p).split('.')[:2]]):
    b = f[:-len('.probe')]
    level, run = (int(x) for x in os.path.basename(b).split('.'))
    floods = [open(x).read() for x in sorted(glob.glob(b + '.flood*'))]
    sent = sum(num('Queries sent', t) for t in floods)
    done = sum(num('Queries completed', t) for t in floods)
    # responses/s during the constant phase, summed over instances
    good = sum(sum(v) / len(v) for v in ([float(l.split()[3]) for l in open(p) if not l.startswith('#') and float(l.split()[0]) < length]
                                         for p in glob.glob(b + '.plot*')) if v)
    probe = open(f).read()
    psent, pdone = num('Queries sent', probe), num('Queries completed', probe)
    lat = sorted(float(m) * 1e3 for m in re.findall(r'^> \w+ \S+ \S+ ([\d.]+)', probe, re.M))
    pc = lambda q: lat[min(len(lat) - 1, int(len(lat) * q))] if lat else float('nan')
    rxq, ldrop, gdrop = (int(x) for x in open(b + '.udp').read().split())
    s0, s1 = open(b + '.stats0').read(), open(b + '.stats1').read()
    hark = unsent(s1) - unsent(s0)
    offered, answered = sent + psent, done + pdone
    acct = abs(hark + ldrop + gdrop - (offered - answered)) / offered
    busy = float(open(b + '.busy').read().split()[0])
    loss = (psent - pdone) / psent
    bad = [name for name, ok in (('loss', level > 4 or pdone == psent), ('p99', pc(.99) <= P99),
                                 ('good', good >= 0.95 * ceiling), ('acct', acct <= 0.001), ('unsat', busy >= 97)) if not ok]
    notes = (['short'] if sent < 0.97 * ceiling * level * length else [])
    runs += 1; fails += bool(bad)
    print(f"{level:>2}x {run:>3} {sent / length / 1e3:>7.0f}k {good / 1e3:>7.1f}k {good / ceiling:>6.3f}  {100 * loss:>5.1f}% {pc(.5):>6.2f} {pc(.99):>6.2f}"
          f"  {rxq / 1024:>6.0f} {ldrop + gdrop:>8} {hark:>7} {100 * acct:>5.2f}% {busy:>5.1f}  {'FAIL ' + ','.join(bad) if bad else 'pass'}"
          + (f"  ({','.join(notes)})" if notes else ''))
print(f"{'FAIL' if fails else 'PASS'}: {runs - fails}/{runs} runs pass")
