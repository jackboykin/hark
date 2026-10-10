#!/usr/bin/env bash
# usage (in nix develop .#bench): sys.sh <bin> hit|miss [qps]
# Where a query's time goes on the resolver core, kernel included, which
# instruction counts (cg.sh) can't see: a miss spends most of it in syscalls
# and softirq. Two runs, each a fresh hark, open loop at qps (miss 40000,
# hit 150000; stay under the ceiling or the split smears):
#   1. perf samples cycles with kernel stacks on CPU_RES for W (5) s, from
#      outside the namespace (inside it perf_event_open is refused), split
#      into hark's own code, its syscalls by name, softirq, and the rest;
#   2. strace -c, attached once hark is up, counts syscalls per query at a
#      rate strace can keep (1000 qps).
# Prints cycles per query per part with its top kernel symbols, then calls
# per query per syscall (sys.py). Unstripped binaries name user symbols too.
set -uo pipefail
B=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$B/lib.sh"
bin=$(realpath "$1") wl=$2 q=${3:-$([[ $2 == hit ]] && echo 150000 || echo 40000)} W=${W:-5}

if [[ ! ${SYS_DIR:-} ]]; then
  S=$(mktemp -d); mkfifo "$S/go"
  trap 'rm -rf "$S"' EXIT
  SYS_DIR=$S "$0" "$bin" "$wl" "$q" & inner=$!
  # The inner run draws the resolver's core and names it here.
  read -r -t 60 cpu <>"$S/go" || { wait "$inner"; exit 1; }
  perf record -q -o "$S/perf.data" -e cycles -g -C "$cpu" -- sleep "$W" 2>/dev/null
  wait "$inner" || exit 1
  perf script -i "$S/perf.data" -F comm,period,ip,sym 2>/dev/null |
    python3 "$B/sys.py" "$(basename "$bin" | cut -c1-15)" "$S/load" "$W" "$S/strace" "$S/count"
  exit
fi

ns "$@"
rig_up
S=$SYS_DIR
load() { # seconds qps -> dnsperf's output
  taskset -c "$CPU_LOAD" dnsperf -s 127.0.0.1 -p "$PORT" -t 3 -d "$R/$wl.txt" -l "$1" -c 4 -T 4 -Q "$2" 2>&1
}
hark_start "$bin" || exit 1
[[ $wl == hit ]] && warm
load $((W + 3)) "$q" >"$S/load" &
sleep 1; echo "$CPU_RES" >"$S/go"
wait $!; hark_stop

hark_start "$bin" || exit 1
[[ $wl == hit ]] && warm
strace -c -f -o "$S/strace" -p "$PID" 2>/dev/null & st=$!
sleep 0.5
load 5 1000 >"$S/count"
kill -INT "$st"; wait "$st"
hark_stop
