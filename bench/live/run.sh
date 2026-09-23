#!/usr/bin/env bash
# usage (in nix develop .#bench): run.sh <rounds> <label=side> <label=side> [names] [rate/s]
# A side is a hark binary or `unbound`. Each round starts both fresh and asks
# them every name at once, paced open-loop, cold then hot; then compare.py.
# env: OUT, PASSES (default "cold hot")
set -uo pipefail
D=$(cd "$(dirname "$0")" && pwd)
ROUNDS=$1 A=$2 B=$3 NAMES=${4:-$D/tranco-400.txt} RATE=${5:-100}
OUT=${OUT:-$D/out/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
R=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; wait; rm -rf "$R"' EXIT
up() { # label=side port round
  local log=$OUT/${1%%=*}.$3.log side=${1#*=}
  if [[ $side == unbound ]]; then
    [[ -f $R/root.key ]] || unbound-anchor -a "$R/root.key" >/dev/null 2>&1
    mkdir -p "$R/$2"
    sed "s|__PORT__|$2|g; s|__RUN__|$R/$2|g; s|__ANCHOR__|$R/root.key|g" "$D/unbound.conf" >"$R/$2/unbound.conf"
    unbound -d -c "$R/$2/unbound.conf" 2>"$log" &
  else
    sed "s|__PORT__|$2|g" "$D/hark.toml" >"$R/hark-$2.toml"
    "$side" serve --config "$R/hark-$2.toml" 2>"$log" &
  fi
  PIDS+=($!)
  for _ in $(seq 100); do dig +time=1 +tries=1 @127.0.0.1 -p "$2" . NS >/dev/null 2>&1 && return; sleep 0.05; done
  echo "${1%%=*} did not start; see $log" >&2
  exit 1
}
for r in $(seq "$ROUNDS"); do
  PIDS=()
  up "$A" 5361 "$r"
  up "$B" 5362 "$r"
  for pass in ${PASSES:-cold hot}; do python3 "$D/ask.py" "$NAMES" "$RATE" "$OUT/$r.$pass.jsonl" 5361 5362; done
  grep -E 'VmHWM|VmRSS' "/proc/${PIDS[0]}/status" >"$OUT/${A%%=*}.$r.mem"
  grep -E 'VmHWM|VmRSS' "/proc/${PIDS[1]}/status" >"$OUT/${B%%=*}.$r.mem"
  kill -TERM "${PIDS[@]}"
  wait "${PIDS[@]}" 2>/dev/null
  echo "round $r done"
done
python3 "$D/compare.py" "$OUT" "${A%%=*}" "${B%%=*}" | tee "$OUT/compare.txt"
