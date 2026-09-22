#!/usr/bin/env bash
# usage: layouts.sh <dir> [n=5]
# n code layouts of this checkout's hark for tp.sh ab (pass <dir> as a side):
# one ReleaseFast compile with -Dbench-layout is <dir>/hark.0, and hark.1..
# are lld relinks of the same objects with --shuffle-sections='.text*=SEED'.
# A relink alone moves miss qps ~1%, so a/b sides are layout distributions.
set -euo pipefail
O=$(realpath -m "$1") N=${2:-5}
cd "$(dirname "$0")/.."
rm -rf "$O/.build" "$O"/hark.*; mkdir -p "$O/.build"
# A fresh private cache always links, so --verbose-link always prints the command.
zig build -Doptimize=ReleaseFast -Dbench-layout -p "$O/.build" --cache-dir "$O/.build/cache" --verbose-link 2>"$O/.build/link"
read -ra link < <(grep -oP '^error: ld\.lld \K.*' "$O/.build/link")
for k in "${!link[@]}"; do [[ ${link[k]} == -o ]] && break; done
cp "$O/.build/bin/hark" "$O/hark.0"
for i in $(seq $((N - 1))); do
  link[k + 1]=$O/hark.$i
  zig ld.lld "${link[@]}" --shuffle-sections=".text*=$i"
done
