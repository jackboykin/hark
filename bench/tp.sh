#!/usr/bin/env bash
# usage (in nix develop .#bench):
#   tp.sh ab <rounds> hit|miss "<dnsperf args>" label=<bin|dir> ...  > out.txt; an.py out.txt
#   tp.sh probe <bin> hit|miss "<dnsperf args>"
# A directory side is every layout in it (layouts.sh).
# Each run is a fresh hark (warmed for hit) under LEN (10) s of dnsperf; two
# binaries alternate order per round, more are shuffled. One line per run:
#   round label layout qps completed lost busy usr sys si [event=value ...]
# busy/usr/sys/si are percent of the resolver core from /proc/stat; the
# counters (PERF=1) are that core's too. Closed loop: hit -c 4 -T 4 -q 400,
# miss -c 4 -T 4 -q 1000 (hark turns more away, stalling dnsperf).
# Instructions per query is a work metric only open loop at a fixed rate
# below the ceiling (add -Q); saturated, it smears by layout.
set -uo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(dirname "$0")/lib.sh"
ns "$@"
rig_up

one() { # bin workload dnsperf-args
  hark_start "$1" || exit 1
  [[ $2 == hit ]] && warm
  local s0 s1 o c
  s0=$(core_snap); perf_on
  # shellcheck disable=SC2086 # the dnsperf args split on purpose
  o=$(taskset -c "$CPU_LOAD" dnsperf -s 127.0.0.1 -p "$PORT" -t 3 -d "$R/$2.txt" -l "${LEN:-10}" $3 2>&1)
  c=$(perf_off); s1=$(core_snap)
  hark_stop
  echo "$(grep -oP 'Queries per second:\s+\K[\d.]+' <<<"$o") $(grep -oP 'Queries completed:\s+\K\d+' <<<"$o")" \
    "$(grep -oP 'Queries lost:\s+\K\d+' <<<"$o") $(core_busy "$s0" "$s1") $c"
}

case $1 in
  probe) one "$2" "$3" "$4" ;;
  ab)
    rounds=$2 wl=$3 args=$4; shift 4
    runs=()
    for s in "$@"; do
      if [[ -d ${s#*=} ]]; then for b in "${s#*=}"/*; do [[ -f $b && -x $b ]] && runs+=("${s%%=*}=$b"); done
      else runs+=("$s"); fi
    done
    for r in $(seq "$rounds"); do
      if (( ${#runs[@]} > 2 )); then mapfile -t order < <(shuf -e "${runs[@]}")
      elif (( r % 2 )); then order=("${runs[@]}")
      else order=("${runs[1]}" "${runs[0]}"); fi
      for s in "${order[@]}"; do echo "$r ${s%%=*} $(basename "${s#*=}") $(one "${s#*=}" "$wl" "$args")"; done
    done ;;
  *) sed -n '2,5p' "$0"; exit 2 ;;
esac
