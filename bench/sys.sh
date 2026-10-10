#!/usr/bin/env bash
# usage (in nix develop .#bench): sys.sh <rounds> hit|miss label=<bin>...
# Where a query's time goes on the resolver core, kernel included, and how
# two builds differ there. Each run is a fresh hark under open-loop load at
# Q qps (miss 40000, hit 150000; stay under the ceiling or the split smears)
# with perf sampling cycles and user instructions, kernel stacks included,
# on the resolver core for W (10) s, from outside the namespace (inside it
# perf_event_open is refused). Sides alternate by round on one core. Then
# strace -c counts each side's syscalls per query at 1000 qps.
# Results land in bench/out/sys-*; sys.py reports each side's parts and
# hark's own functions per query, then each side against the first
# (again: sys.py report <dir> <W>).
# Unstripped binaries (-Dstrip=false) name hark's functions.
set -uo pipefail
B=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$B/lib.sh"
(( $# >= 3 )) || { sed -n '2,12p' "$0"; exit 2; }
rounds=$1 wl=$2; shift 2
q=${Q:-$([[ $wl == hit ]] && echo 150000 || echo 40000)} W=${W:-10}

if [[ ! ${SYS_DIR:-} ]]; then
  OUT=$B/out/sys-$(date +%Y%m%d-%H%M%S)-$wl
  S=$(mktemp -d); mkfifo "$S/go" "$S/ack"; mkdir -p "$OUT"
  trap 'rm -rf "$S"' EXIT
  sides=()
  for s in "$@"; do sides+=("${s%%=*}=$(realpath "${s#*=}")"); done
  SYS_DIR=$S OUT=$OUT "$0" "$rounds" "$wl" "${sides[@]}" & inner=$!
  # The inner run names the resolver's core and the run, and holds its load
  # until perf has sampled it; the samples are read once every run is done.
  exec 3<>"$S/go" 4<>"$S/ack"
  tags=()
  while read -r -t 120 -u 3 cpu tag && [[ $cpu != end ]]; do
    perf record -q -o "$S/$tag.data" -F 10000 -e cycles -e instructions:u -g -C "$cpu" -- sleep "$W" 2>/dev/null
    echo >&4; tags+=("$tag")
  done
  wait "$inner" || exit 1
  for t in "${tags[@]}"; do
    perf script -i "$S/$t.data" -F comm,event,period,ip,sym --no-inline 2>/dev/null | python3 "$B/sys.py" fold hark >"$OUT/$t.json"
  done
  python3 "$B/sys.py" report "$OUT" "$W"
  exit
fi

ns "$rounds" "$wl" "$@"
rig_up
S=$SYS_DIR
load() { # seconds qps -> dnsperf's output
  taskset -c "$CPU_LOAD" dnsperf -s 127.0.0.1 -p "$PORT" -t 3 -d "$R/$wl.txt" -l "$1" -c 4 -T 4 -Q "$2" 2>&1
}
start() { hark_start "$1" || exit 1; [[ $wl == hit ]] && warm; }
for r in $(seq "$rounds"); do
  order=("$@"); ((r % 2)) || order=("${@:2}" "$1")
  for s in "${order[@]}"; do
    start "${s#*=}"
    load $((W + 3)) "$q" >"$OUT/$r-${s%%=*}.load" &
    sleep 1; echo "$CPU_RES $r-${s%%=*}" >"$S/go"; read -r _ <"$S/ack"
    wait $!; hark_stop
  done
done
for s in "$@"; do
  start "${s#*=}"
  strace -c -f -o "$OUT/${s%%=*}.strace" -p "$PID" 2>/dev/null & st=$!
  sleep 0.5
  load 5 1000 >"$OUT/${s%%=*}.count"
  kill -INT "$st"; wait "$st"
  hark_stop
done
echo end >"$S/go"
