#!/usr/bin/env bash
# usage (in nix develop .#bench): run.sh smoke|bench [rounds] [resolver...]
# resolver: hark unbound pdns kresd bind, or label=/path/to/hark for another build.
# env: HARK, OUT, LATENCY_MS, CPU_RES (2), CPU_LOAD (4-7), CPU_NSD (8-11)
set -uo pipefail
D=$(cd "$(dirname "$0")" && pwd)
[[ ${IN_NS:-} ]] || exec env IN_NS=1 unshare -Urn "$0" "$@"

MODE=${1:-smoke}; shift
[[ $MODE == bench ]] && { ROUNDS=${1:-1}; shift; }
RES=("$@"); (( ${#RES[@]} )) || RES=(hark unbound pdns kresd bind)
HARK=${HARK:-$D/../../zig-out/bin/hark}
OUT=${OUT:-$D/out/$(date +%Y%m%d-%H%M%S)}
R=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; wait; rm -rf "$R"' EXIT
mkdir -p "$OUT"

for f in nsd.conf unbound.conf recursor.yml named.conf; do sed "s|__RUN__|$R|g; s|__DIR__|$D|g" "$D/$f" >"$R/$f"; done
for w in hit miss mix; do python3 "$D/gen_queries.py" $w >"$R/$w.txt"; done
ip link set lo up
ip addr add 198.41.0.4/32 dev lo
[[ ${LATENCY_MS:-} ]] && tc qdisc add dev lo root netem delay "${LATENCY_MS}ms" limit 200000
taskset -c "${CPU_NSD:-8-11}" nsd -c "$R/nsd.conf" -d 2>"$R/nsd.err" &

ask() { dig +short +time=1 +tries=1 @127.0.0.1 -p 5354 "$@"; }
start() {
  local cmd
  case $1 in
    hark) cmd=("$HARK" serve --config "$D/hark.toml") ;;
    *=*) cmd=("${1#*=}" serve --config "$D/hark.toml") ;;
    unbound) cmd=(unbound -d -c "$R/unbound.conf") ;;
    pdns) cmd=(pdns_recursor --config-dir="$R") ;;
    kresd) rm -rf "$R/kres"; mkdir -p "$R/kres"; cmd=(kresd -n -q -c "$D/kresd.conf" "$R/kres") ;;
    bind) cmd=(named -g -n 1 -U 1 -c "$R/named.conf") ;;
  esac
  (exec taskset -c "${CPU_RES:-2}" "${cmd[@]}") >"$R/${1%%=*}.log" 2>&1 &
  PID=$!
  for _ in $(seq 50); do ask smoke.bench A >/dev/null 2>&1 && return; sleep 0.1; done
  echo "$1 did not come up"; tail "$R/${1%%=*}.log"; return 1
}
stop() { kill $PID; wait $PID 2>/dev/null; while ask smoke.bench A >/dev/null 2>&1; do sleep 0.1; done; }
warm() { for i in $(seq 8); do ask host$i.bench A >/dev/null; done; }
cpu() { awk '{print $14+$15}' /proc/$PID/stat; }
perf() { # label workload round dnsperf-args...
  local f=$OUT/$1.$2.$3.txt c0 t0; shift 3
  c0=$(cpu) t0=$(date +%s%N)
  taskset -c "${CPU_LOAD:-4-7}" dnsperf -s 127.0.0.1 -p 5354 -t 3 "$@" >"$f" 2>&1
  echo "cpu_pct $(( ($(cpu) - c0) * 1000000000 / ($(date +%s%N) - t0) ))" >>"$f"
}
round() { # resolver round
  local l=${1%%=*}
  start $1 || return
  warm
  perf $l hit $2 -d "$R/hit.txt" -c 4 -T 4 -q 400 -l 10
  perf $l lat $2 -d "$R/hit.txt" -c 1 -T 1 -Q 20000 -l 5 -v
  stop; start $1 || return
  perf $l miss $2 -d "$R/miss.txt" -c 4 -T 4 -q 2000 -l 10
  stop; start $1 || return
  warm
  perf $l mix $2 -d "$R/mix.txt" -c 4 -T 4 -q 2000 -l 10
  stop
}

sleep 0.5
if [[ $MODE == smoke ]]; then
  for n in "${RES[@]}"; do start $n && echo "${n%%=*}: $(ask smoke.bench A) $(ask zz9.bench A)" && stop; done
  exit
fi
for r in $(seq "$ROUNDS"); do
  order=$(shuf -e "${RES[@]}")
  echo "round $r:" $order
  for n in $order; do round $n $r; done
done
python3 "$D/sum.py" "$OUT"
