"""sys.py fold <comm> < perf script -F comm,event,period,ip,sym (with -g)
   sys.py report <dir> <seconds>: sys.sh's report.

fold sums one run's samples: each cycle goes to one part (hark's own code,
the syscall its kernel stack sits under, softirq, other kernel time in
hark, or another task on the core), and hark's own code by function, in
cycles and user instructions.

report divides by the queries asked in the window and takes each side's
median over its rounds: its parts with their top kernel symbols, hark's
functions, and syscalls per query from strace. Each later side is then set
against the first, part by part and function by function, with the range
of the first side's rounds beside each figure as its noise.
"""
import collections as C, glob, json, os, re, statistics as st, sys

kernel = 0xffff800000000000
syscall = re.compile(r'(?:__x64_sys_|__se_sys_|__do_sys_)(\w+)')
softirq = ('handle_softirqs', '__do_softirq', 'net_rx_action')
generic = re.compile(r"__func_\d+|__anon_\d+|'\d+$")


def fold(comm):
    parts, syms = C.Counter(), C.defaultdict(C.Counter)
    fns = {'cycles': C.Counter(), 'instructions': C.Counter()}

    def part(task, frames):
        if task != comm:
            return 'other task: ' + task
        if int(frames[0][0], 16) < kernel:
            return 'hark'
        for _, s in frames:
            if m := syscall.match(s):
                return 'sys ' + m.group(1)
            if s.startswith(softirq):
                return 'softirq'
        return 'kernel, no syscall'

    block = []
    for line in [*sys.stdin, '\n']:
        if line.strip():
            block.append(line.rstrip('\n'))
            continue
        if block:
            task, period, event = block[0].rsplit(None, 2)
            event, period = event.rstrip(':').split(':')[0], int(period)
            frames = [(f.split(None, 1) + ['?'])[:2] for f in block[1:]] or [('0', '?')]
            p, leaf = part(task.strip(), frames), generic.sub('', frames[0][1].strip())
            if p == 'hark':
                fns[event][leaf] += period
            if event == 'cycles':
                parts[p] += period
                syms[p][leaf] += period
        block = []
    json.dump({'parts': parts, 'syms': {p: dict(s.most_common(3)) for p, s in syms.items()}, 'fns': fns}, sys.stdout)


def dnsperf(path):
    t = open(path).read()
    num = lambda k: float(re.search(k + r':\s+([\d.]+)', t).group(1))
    return num('Queries per second'), int(num('Queries completed')), int(num('Queries lost'))


def report(out, secs):
    runs = C.defaultdict(list)
    for path in sorted(glob.glob(f'{out}/*-*.json')):
        r, side = os.path.basename(path)[:-5].split('-', 1)
        qps, done, lost = dnsperf(path[:-5] + '.load')
        asked = qps * secs
        d = json.load(open(path))
        per = lambda c: {k: v / asked for k, v in c.items()}
        runs[side].append(dict(parts=per(d['parts']), syms=d['syms'], qps=qps, lost=lost,
                               cyc=per(d['fns']['cycles']), ins=per(d['fns']['instructions'])))
    sides = sorted(runs, key=lambda s: min(os.path.getmtime(p) for p in glob.glob(f'{out}/*-{s}.json')))
    med = lambda rs, f: st.median(f(r) for r in rs)
    spread = lambda rs, f: (max(f(r) for r in rs) - min(f(r) for r in rs)) / 2

    for s in sides:
        rs = runs[s]
        total = med(rs, lambda r: sum(r['parts'].values()))
        print(f"{s}: {len(rs)} runs at {med(rs, lambda r: r['qps']):.0f} qps, {sum(r['lost'] for r in rs)} lost")
        print(f"  {total:8.0f} cycles per query")
        for p in sorted(rs[0]['parts'], key=lambda p: -rs[0]['parts'][p]):
            c = med(rs, lambda r: r['parts'].get(p, 0))
            if c / total < 0.002:
                continue
            top = ', '.join(f"{k} {100 * n / sum(rs[0]['syms'][p].values()):.0f}%" for k, n in rs[0]['syms'][p].items()) if p != 'hark' else ''
            print(f"  {c:8.0f} {100 * c / total:5.1f}%  {p:<22} {top}")
        ins = med(rs, lambda r: sum(r['ins'].values()))
        print(f"  hark's own code: {ins:.0f} instructions per query; top functions, cycles and instructions per query:")
        for k in sorted(rs[0]['cyc'], key=lambda k: -rs[0]['cyc'][k])[:12]:
            print(f"  {med(rs, lambda r: r['cyc'].get(k, 0)):8.0f} {med(rs, lambda r: r['ins'].get(k, 0)):8.0f}  {k[:100]}")
        counts, trace = f'{out}/{s}.count', f'{out}/{s}.strace'
        if os.path.exists(trace):
            _, done, _ = dnsperf(counts)
            rows = []
            for line in open(trace):
                f = line.split()
                if len(f) >= 5 and f[-1] != 'total' and f[3].isdigit():
                    rows.append((int(f[3]) / done, (int(f[4]) if len(f) == 6 else 0) / done, f[-1]))
            print(f"  syscalls per query (strace -c over {done} queries): " + ', '.join(
                f"{n} {c:.2f}" + (f" ({e:.2f} failed)" if e else '') for c, e, n in sorted(rows, reverse=True) if c >= 0.01)
                + f"; {sum(r[0] for r in rows):.2f} in all")
        print()

    a = runs[sides[0]]
    for s in sides[1:]:
        b = runs[s]
        print(f"{s} - {sides[0]}, per query, ± half the range of {sides[0]}'s runs:")
        for name, f in (('cycles', lambda r: sum(r['parts'].values())), ("hark's instructions", lambda r: sum(r['ins'].values()))):
            d = med(b, f) - med(a, f)
            print(f"  {d:+8.0f} ± {spread(a, f):.0f}  {name} ({100 * d / med(a, f):+.2f}%)")
        for key, unit in (('parts', 'cycles'), ('ins', 'instructions')):
            names = set().union(*(r[key] for r in a + b))
            delta = {k: med(b, lambda r: r[key].get(k, 0)) - med(a, lambda r: r[key].get(k, 0)) for k in names}
            print(f"  by {'part' if key == 'parts' else 'function'}, {unit}:")
            for k, d in sorted(delta.items(), key=lambda kv: -abs(kv[1]))[:10]:
                print(f"  {d:+8.0f} ± {spread(a, lambda r: r[key].get(k, 0)):.0f}  {k[:100]}")
        print()


if sys.argv[1] == 'fold':
    fold(sys.argv[2])
else:
    report(sys.argv[2], float(sys.argv[3]))
