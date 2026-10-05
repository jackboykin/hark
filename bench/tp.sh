#!/usr/bin/env bash
# usage (in nix develop .#bench): tp.sh <rounds> <workload> side... > out.txt; an.py out.txt
# A side is label=<hark binary|layouts dir> or a peer (unbound pdns kresd
# bind) at N threads. Every run is a fresh resolver on freshly drawn cores
# under LEN (10) s of load, closed loop with N times the queries in flight:
#   hit 64 flows, few 4 flows, miss, mix half hits, lat 70% of the ceiling open loop
# One line a run: round label layout qps completed lost busy usr sys si cpu=… [p50= p99= p999=] [event=…]
# Each run also lands in bench/out, under '#' lines saying what ran where.
# busy is /proc/stat's and true only saturated: below it ticks alias with a
# paced sender, so read cost from PERF=1's counters.
set -uo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(dirname "$0")/lib.sh"
LOAD=$(dirname "$0")/zig-out/bin/load
if [[ ! ${IN_NS:-} ]]; then
  (cd "$(dirname "$0")" && zig build -Doptimize=ReleaseFast) || exit 2
  TP_OUT=$B/out/tp-$(date +%Y%m%d-%H%M%S)-$(git -C "$B" describe --always --dirty)-${2:-}.txt
  mkdir -p "$B/out"
  {
    echo "# tp.sh $*"
    echo "# $(date -Is) N=$N LEN=${LEN:-10} PERF=${PERF:-} kernel $(uname -r)"
    echo "# $(grep -m1 -oP 'model name\s*: \K.*' /proc/cpuinfo), CCD ${CCD:-last}," \
      "$(cat /sys/devices/system/cpu/cpu"${CORES[0]%% *}"/cpufreq/{scaling_driver,scaling_governor,energy_performance_preference} 2>/dev/null | paste -sd/)"
    for s in "${@:3}"; do
      case $s in
        unbound) echo "# unbound $(unbound -V | head -1)" ;;
        pdns) echo "# pdns $(pdns_recursor --version 2>&1 | head -1)" ;;
        kresd) echo "# kresd $(kresd --version)" ;;
        bind) echo "# bind $(named -v)" ;;
        *) b=${s#*=}; [[ -d $b ]] && b=$(find "$b" -maxdepth 1 -type f -executable | sort | head -1)
           echo "# ${s%%=*} $("$b" version) sha256 $(sha256sum "$b" | cut -c1-16)" ;;
      esac
    done
  } >"$TP_OUT"
  export TP_OUT
fi
ns "$@"
rig_up

gen() { taskset -c "$CPU_LOAD" "$LOAD" -s 127.0.0.1 -p "$PORT" -l "${LEN:-10}" "$@"; }
key() { awk -v k="$1" '$1 == k { print $2 }' <<<"$2"; }

one() { # side workload
  place "$N"
  res_start "$1" || exit 1
  local t c=64 f=hit q=400 s0 s1 o k lat='' l
  t=$(tr , '\n' <<<"$CPU_LOAD" | wc -l)
  case $2 in
    hit|lat) warm ;;
    few) warm; c=4 t=$((t < 4 ? t : 4)) ;;
    miss) f=miss q=1000 ;;
    mix) warm; f=mix q=1000 ;;
    *) echo "unknown workload $2" >&2; exit 2 ;;
  esac
  local args=(-d "$R/$f.txt" -c "$c" -T "$t" -q $((q * N)))
  [[ $2 == lat ]] && args+=(-Q "$(key qps "$(LEN=5 gen "${args[@]}")" | awk '{ printf "%d", $1 * 0.7 }')")
  perf_on; s0=$(core_snap)
  o=$(gen "${args[@]}")
  s1=$(core_snap); k=$(perf_off)
  res_stop
  [[ $2 == lat ]] && for l in p50 p99 p999; do lat+="$l=$(key $l "$o") "; done
  echo "$(key qps "$o") $(key completed "$o") $(key lost "$o")" \
    "$(core_busy "$s0" "$s1") cpu=$CPU_RES $lat$k"
}

(( $# >= 3 )) || { sed -n '2,6p' "$0"; exit 2; }
rounds=$1 wl=$2; shift 2
runs=()
for s in "$@"; do
  case $s in
    unbound|pdns|kresd|bind) runs+=("$s=$s") ;;
    *) if [[ -d ${s#*=} ]]; then for b in "${s#*=}"/*; do [[ -f $b && -x $b ]] && runs+=("${s%%=*}=$b"); done
       else runs+=("$s"); fi ;;
  esac
done
for r in $(seq "$rounds"); do
  if (( ${#runs[@]} > 2 )); then mapfile -t order < <(shuf -e "${runs[@]}")
  elif (( ${#runs[@]} == 2 && r % 2 == 0 )); then order=("${runs[1]}" "${runs[0]}")
  else order=("${runs[@]}"); fi
  for s in "${order[@]}"; do echo "$r ${s%%=*} $(basename "${s#*=}") $(one "${s#*=}" "$wl")" | tee -a "$TP_OUT"; done
done
