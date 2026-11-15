#!/usr/bin/env bash
# usage (in nix develop .#bench): run.sh <rounds> <label=side>...
# A side is a hark binary or a peer: unbound, kresd, bind, pdns. Each round
# starts every side fresh and asks them all every name at once, paced
# open-loop, cold then hot; then bench compare, each side against the first.
# Start order rotates by round and ask rotates its send order by name, so no
# side always goes first.
# env: NAMES (default tranco-400.txt), RATE (names/s, default 100), OUT,
# PASSES (default "cold hot")
set -uo pipefail
D=$(cd "$(dirname "$0")" && pwd)
ROUNDS=$1 SIDES=("${@:2}") NAMES=${NAMES:-$D/tranco-400.txt} RATE=${RATE:-100}
OUT=${OUT:-$D/../out/live-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
R=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; wait; rm -rf "$R"' EXIT
go build -C "$D/../../test" -o "$R/ask" ask.go || exit 1
unbound-anchor -a "$R/root.key" >/dev/null 2>&1
fill() { # template port
  sed "s|__PORT__|$2|g; s|__RUN__|$R/$2|g; s|__ANCHOR__|$R/root.key|g" "$D/$1" >"$R/$2/$1"
}
up() { # label=side port round
  local log=$OUT/${1%%=*}.$3.log side=${1#*=}
  # kresd keeps its cache on disk: a round starts in an empty directory.
  rm -rf "${R:?}/$2" && mkdir "$R/$2"
  case $side in
    unbound) fill unbound.conf "$2"; unbound -d -c "$R/$2/unbound.conf" 2>"$log" & ;;
    kresd) fill kresd.conf "$2"; kresd -n -q -c "$R/$2/kresd.conf" "$R/$2" >"$log" 2>&1 & ;;
    bind) fill named.conf "$2"; named -g -c "$R/$2/named.conf" 2>"$log" & ;;
    pdns) fill recursor.yml "$2"; pdns_recursor --config-dir="$R/$2" >"$log" 2>&1 & ;;
    *) fill hark.toml "$2"; "$side" serve --config "$R/$2/hark.toml" 2>"$log" & ;;
  esac
  PIDS[$2]=$!
  for _ in $(seq 100); do dig +time=1 +tries=1 @127.0.0.1 -p "$2" . NS >/dev/null 2>&1 && return; sleep 0.05; done
  echo "${1%%=*} did not start; see $log" >&2
  exit 1
}
N=${#SIDES[@]} PORTS=()
for k in "${!SIDES[@]}"; do PORTS+=($((5361 + k))); done
for r in $(seq "$ROUNDS"); do
  PIDS=()
  for i in $(seq 0 $((N - 1))); do k=$(((r + i) % N)); up "${SIDES[k]}" "${PORTS[k]}" "$r"; done
  for pass in ${PASSES:-cold hot}; do "$R/ask" "$NAMES" "$RATE" "$OUT/$r.$pass.jsonl" "${PORTS[@]}"; done
  for k in "${!SIDES[@]}"; do grep -E 'VmHWM|VmRSS' "/proc/${PIDS[${PORTS[k]}]}/status" >"$OUT/${SIDES[k]%%=*}.$r.mem"; done
  kill -TERM "${PIDS[@]}"
  wait "${PIDS[@]}" 2>/dev/null
  echo "round $r done"
done
labels=() && for s in "${SIDES[@]}"; do labels+=("${s%%=*}"); done
"$D/../run" compare "$OUT" "${labels[@]}" 2>&1 | tee "$OUT/compare.txt"
