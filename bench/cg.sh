#!/usr/bin/env bash
# usage (in nix develop .#bench):
#   cg.sh <runs> hit|miss "<dnsperf args>" label=<bin|rev|.> ... >out.txt; cg.py out.txt
# Exact instructions per query under callgrind, for differences under the
# ~1% a relink moves qps (tp.sh can't see them). A side is a binary, a git
# rev, or . for this checkout as it stands; revs and . are built unstripped
# for x86-64-v3 (valgrind can't run the AVX-512 a native build emits), revs
# once, into $CG_BUILDS (/tmp/hark-cg). Each run is a fresh hark, counted
# from after it came up (and warmed, for hit) until dnsperf ends; sides
# alternate by round. One line per run:
#   round label Ir queries callgrind-file
# The files stay in $CG_OUT (a fresh /tmp/hark-cg.*) for cg.py's per-function
# table. User space only: sys.sh shows the kernel's part. Miss totals move
# up to ±1% between runs with event batching; the per-function table is
# steadier, so take 3 runs and read it. Open loop only:
# miss -Q 400 -l 10, hit -Q 1000 -l 10 (valgrind runs hark ~50x slower).
set -uo pipefail
B=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$B/lib.sh"

build() { # rev|. -> binary
  local flags=(-Doptimize=ReleaseFast -Dstrip=false -Dcpu=x86_64_v3) root out w
  root=$(git -C "$B" rev-parse --show-toplevel)
  if [[ $1 == . ]]; then
    out=$(mktemp -d)
    (cd "$root" && zig build "${flags[@]}" -p "$out") >&2 || return 1
  else
    out=${CG_BUILDS:-/tmp/hark-cg}/$(git -C "$root" rev-parse --verify "$1^{commit}") || return 1
    if [[ ! -x $out/bin/hark ]]; then
      w=$(mktemp -d)
      git -C "$root" worktree add -q --detach "$w" "$1" >&2 &&
        (cd "$w" && zig build "${flags[@]}" -p "$out") >&2; local rc=$?
      git -C "$root" worktree remove --force "$w"
      ((rc == 0)) || return 1
    fi
  fi
  echo "$out/bin/hark"
}

if [[ ! ${IN_NS:-} ]]; then
  sides=()
  for s in "${@:4}"; do
    b=${s#*=}
    [[ -f $b && -x $b ]] || b=$(build "$b") || { echo "cannot build ${s#*=}" >&2; exit 1; }
    sides+=("${s%%=*}=$(realpath "$b")")
  done
  CG_OUT=${CG_OUT:-$(mktemp -d /tmp/hark-cg.XXXXXX)} ns "$1" "$2" "$3" "${sides[@]}"
fi

rig_up
runs=$1 wl=$2 args=$3; shift 3
one() { # round label bin
  local cg=$CG_OUT/$1-$2.cg w=$R/vg o
  printf '#!/bin/sh\nexec valgrind -q --tool=callgrind --instr-atstart=no --callgrind-out-file=%s %s "$@"\n' "$cg" "$3" >"$w"
  chmod +x "$w"
  hark_start "$w" || return 1
  [[ $wl == hit ]] && warm
  callgrind_control -i on "$PID" >/dev/null 2>&1
  # shellcheck disable=SC2086 # the dnsperf args split on purpose
  o=$(taskset -c "$CPU_LOAD" dnsperf -s 127.0.0.1 -p "$PORT" -t 3 -d "$R/$wl.txt" $args 2>&1)
  callgrind_control -i off "$PID" >/dev/null 2>&1
  hark_stop
  echo "$1 $2 $(awk '/^totals:/ { print $2 }' "$cg") $(grep -oP 'Queries completed:\s+\K\d+' <<<"$o") $cg"
}
for r in $(seq "$runs"); do
  order=("$@"); ((r % 2)) || order=("${@:2}" "$1")
  for s in "${order[@]}"; do one "$r" "${s%%=*}" "${s#*=}"; done
done
