"""sys.py <comm> <dnsperf output> <seconds> <strace -c file> <its dnsperf output>
< perf script -F comm,period,ip,sym (with -g): sys.sh's report.

Each sample goes to one part: hark's user code, the syscall its kernel
stack sits under, softirq, other kernel time in hark, or another task on
the core. Cycles per query divide by the queries asked in the window.
"""
import collections as C, re, sys

comm, load, secs, trace, count = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4], sys.argv[5]
kernel = 0xffff800000000000
syscall = re.compile(r'(?:__x64_sys_|__se_sys_|__do_sys_)(\w+)')
softirq = ('handle_softirqs', '__do_softirq', 'net_rx_action')


def dnsperf(path):
    t = open(path).read()
    num = lambda k: float(re.search(k + r':\s+([\d.]+)', t).group(1))
    return num('Queries per second'), int(num('Queries completed')), int(num('Queries lost'))


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


cycles, syms = C.Counter(), C.defaultdict(C.Counter)
block = []
for line in [*sys.stdin, '\n']:
    if line.strip():
        block.append(line.rstrip('\n'))
        continue
    if block:
        task, period = block[0].rsplit(None, 1)
        frames = [(f.split(None, 1) + ['?'])[:2] for f in block[1:]] or [('0', '?')]
        p = part(task.strip(), frames)
        cycles[p] += int(period)
        syms[p][frames[0][1].strip()] += int(period)
    block = []

qps, done, lost = dnsperf(load)
asked = qps * secs
total = sum(cycles.values())
print(f"cycles on the resolver core, {qps:.0f} qps asked, {lost} lost of {done + lost}")
print(f"  {total / asked:8.0f} per query")
for p, c in cycles.most_common():
    if c / total < 0.002:
        continue
    top = ', '.join(f"{s} {100 * n / c:.0f}%" for s, n in syms[p].most_common(3)) if p != 'hark' else ''
    print(f"  {c / asked:8.0f} {100 * c / total:5.1f}%  {p:<22} {top}")

_, done, _ = dnsperf(count)
print(f"syscalls per query (strace -c over {done} queries)")
rows = []
for line in open(trace):
    f = line.split()
    if len(f) >= 5 and f[-1] != 'total' and f[3].isdigit():
        errors = int(f[4]) if len(f) == 6 else 0
        rows.append((int(f[3]) / done, errors / done, f[-1]))
for calls, errors, name in sorted(rows, reverse=True):
    if calls >= 0.01:
        print(f"  {calls:6.2f}  {name}" + (f"  ({errors:.2f} failed)" if errors else ''))
print(f"  {sum(r[0] for r in rows):6.2f}  total")
