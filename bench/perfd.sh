#!/usr/bin/env bash
# perfd.sh DIR [EVENTS]: perf stat counters per window on the cores each
# window writes to DIR/cpu, softirq included, for rigs in unshare -Urn.
#
# perf stat -C fails inside the namespace (perf_event_paranoid 2 and the
# userns lacks the perf wrapper's cap_perfmon), so this loop runs outside it,
# driven through the fifos in DIR (lib.sh perf_on/perf_off). One perf per
# window, so windows never mix.
#
# The rigs start and stop it themselves under PERF=1. By hand:
#   bench/perfd.sh /tmp/pd & PERF_DIR=/tmp/pd bench/tp.sh ...; kill %1
set -u
W=$1 EV=${2:-cycles,instructions}
perf stat -C 0 -e "$EV" -o /dev/null true || exit 1
mkdir -p "$W"
for f in cpu ctl ack stop out; do [[ -p $W/$f ]] || mkfifo "$W/$f"; done
trap ': 3<>"$W/stop"; exit' TERM INT
while read -r cpu <"$W/cpu"; do
  perf stat -C "$cpu" -e "$EV" -x, -o "$W/w" -D -1 --control "fifo:$W/ctl,$W/ack" -- cat "$W/stop" \
    >/dev/null 2> >(grep -v '^Events ' >&2) &
  wait $!
  awk -F, '!/^#/ && NF > 2 { printf "%s=%s ", $3, $1 } END { print "" }' "$W/w" >"$W/out"
done
