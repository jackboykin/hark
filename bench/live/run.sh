#!/usr/bin/env bash
# usage (in nix develop .#bench): run.sh <rounds> <label=hark> <label=hark> [names]
# Fresh process per side per round, alternating order: the names cold then hot, then compare.py.
set -uo pipefail
D=$(cd "$(dirname "$0")" && pwd)
ROUNDS=$1 A=$2 B=$3 NAMES=${4:-$D/tranco-400.txt}
OUT=${OUT:-$D/out/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
side() { # label=bin round
  local o=$OUT/${1%%=*}.$2 pid
  "${1#*=}" serve --config "$D/hark.toml" 2>"$o.log" & pid=$!
  for _ in $(seq 100); do dig +time=1 +tries=1 @127.0.0.1 -p 5361 localhost A >/dev/null 2>&1 && break; sleep 0.05; done
  python3 "$D/ab.py" 5361 "$NAMES" 16 >"$o.cold.json"
  python3 "$D/ab.py" 5361 "$NAMES" 16 >"$o.hot.json"
  grep -E "VmHWM|VmRSS" /proc/$pid/status >"$o.mem"
  kill -TERM $pid; wait $pid 2>/dev/null
}
for r in $(seq "$ROUNDS"); do
  if (( r % 2 )); then side "$A" $r; side "$B" $r; else side "$B" $r; side "$A" $r; fi
  echo "round $r done"
done
python3 "$D/compare.py" "$OUT" "${A%%=*}" "${B%%=*}"
