#!/usr/bin/env bash
# Capture local DNS traffic for $DURATION seconds and turn it into a pellet
# that run.sh can replay against hark.
#
# Usage:
#   ./capture-pellet.sh [duration_s]   # default 300s, output → ./pellet.pcap
#
# Env:
#   IFACE      capture interface (default: any)
#   PORT       DNS port to capture (default: 53)
#   OUT        output pellet path (default: ./pellet.pcap)
#   CHUNK      extract-clients.lua chunk duration; 0 = single chunk (default 0)
#
# Capture requires CAP_NET_RAW. On NixOS, ensure your user is in the
# `wireshark` group OR run with sudo. Installing wireshark-cli (per the bench
# shell.nix) sets dumpcap suid by default.
#
# The output pellet contains real DNS queries from your machine. **Do not
# commit it.** .gitignore excludes *.pcap.

set -euo pipefail

DURATION="${1:-300}"
IFACE="${IFACE:-any}"
PORT="${PORT:-53}"
OUT="${OUT:-./pellet.pcap}"
CHUNK="${CHUNK:-0}"

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
SHOTGUN_DIR="$BENCH_DIR/.shotgun"
DNSJIT_DIR="$BENCH_DIR/.dnsjit"

if [[ ! -f "$DNSJIT_DIR/install/bin/dnsjit" ]] || [[ ! -d "$SHOTGUN_DIR" ]]; then
    echo "dnsjit/shotgun not built — run ./run.sh once first to bootstrap, then re-run this." >&2
    exit 1
fi

export PATH="$DNSJIT_DIR/install/bin:$PATH"
export LD_LIBRARY_PATH="$DNSJIT_DIR/install/lib:${LD_LIBRARY_PATH:-}"
export LUA_PATH="$DNSJIT_DIR/install/share/dnsjit/?.lua;${LUA_PATH:-;;}"
export LUA_CPATH="$DNSJIT_DIR/install/lib/lua/?.so;${LUA_CPATH:-;;}"

TMPDIR="$(mktemp -d -t hark-pellet-XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

RAW="$TMPDIR/raw.pcap"
FILTERED="$TMPDIR/filtered.pcap"

echo ">>> capturing port $PORT on iface=$IFACE for ${DURATION}s → $RAW"
echo "    (browse / use your machine normally to generate traffic)"
dumpcap -i "$IFACE" -f "port $PORT" -a "duration:$DURATION" -w "$RAW"

echo ">>> filter-dnsq: keep DNS queries only → $FILTERED"
"$SHOTGUN_DIR/pcap/filter-dnsq.lua" -r "$RAW" -w "$FILTERED" -p "$PORT"

echo ">>> extract-clients: build pellet"
if [[ "$CHUNK" == 0 ]]; then
    "$SHOTGUN_DIR/pcap/extract-clients.lua" -r "$FILTERED" --stdout > "$OUT"
else
    EXTRACT_OUT="$TMPDIR/clients"
    mkdir -p "$EXTRACT_OUT"
    "$SHOTGUN_DIR/pcap/extract-clients.lua" -r "$FILTERED" -O "$EXTRACT_OUT" -d "$CHUNK"
    # Take the first chunk as the pellet by default; mergecap would let users
    # build larger pellets manually.
    FIRST="$(ls "$EXTRACT_OUT" | head -1)"
    cp "$EXTRACT_OUT/$FIRST" "$OUT"
    echo "    (used first chunk: $FIRST. mergecap to combine all chunks if you want bigger.)"
fi

QUERY_COUNT="$(tshark -r "$OUT" -Y dns 2>/dev/null | wc -l)"
echo
echo ">>> pellet ready: $OUT ($QUERY_COUNT DNS queries)"
echo ">>> run with: ./run.sh udp $OUT"
