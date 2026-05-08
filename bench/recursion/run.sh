#!/usr/bin/env bash
# Realistic recursion-time bench for hark, driven by DNS Shotgun replay over
# a real-internet path. Intended to be run from inside `nix-shell shell.nix`
# (or with the build deps in PATH).
#
# Usage:
#   run.sh                           # udp, ./pellet.pcap
#   run.sh <protocol> [pellet]       # protocol ∈ {udp, tcp, dot, doh}
#
# Run duration is baked into the pellet at capture time (extract-clients.lua
# -d). Use capture-pellet.sh to set it.
#
# Env:
#   PELLET            override pellet path
#   HARK_PORT         hark UDP/TCP port (default 5354)
#   WARM=1            don't restart hark before the run (warm cache)
#   OTHER_RESOLVER    "ip:port" — bypass hark, drive replay at this resolver
#                     instead. Useful for side-by-side comparisons.
#   REBUILD=1         force-rebuild hark before running.
#
# First invocation clones+builds dnsjit and shotgun into .dnsjit/ and
# .shotgun/. Subsequent runs reuse the build.

set -euo pipefail

PROTOCOL="${1:-udp}"
PELLET_ARG="${2:-${PELLET:-./pellet.pcap}}"
# replay.py is invoked from $SHOTGUN_DIR — absolutize so relative paths resolve.
PELLET="$(realpath -m "$PELLET_ARG" 2>/dev/null || echo "$PELLET_ARG")"

HARK_PORT="${HARK_PORT:-5354}"
HARK_ADDR="127.0.0.1:${HARK_PORT}"
TARGET="${OTHER_RESOLVER:-$HARK_ADDR}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BENCH_DIR="$REPO_ROOT/bench/recursion"
HARK_BIN="$REPO_ROOT/zig-out/bin/hark"
SHOTGUN_DIR="$BENCH_DIR/.shotgun"
DNSJIT_DIR="$BENCH_DIR/.dnsjit"
DNSSIM_LIB="$SHOTGUN_DIR/replay/dnssim/build/dnssim.so"
REPLAY_PY="$SHOTGUN_DIR/replay.py"

# Pinned upstreams (release tags from CZ-NIC/shotgun and DNS-OARC/dnsjit).
SHOTGUN_REF="v20240219"
DNSJIT_REF="v1.5.0"

case "$PROTOCOL" in
    bootstrap) ;;   # build everything, then exit
    udp|tcp|dot|doh) ;;
    *) echo "unknown protocol: $PROTOCOL (expected: bootstrap|udp|tcp|dot|doh)" >&2; exit 2 ;;
esac

# ── build hark ───────────────────────────────────────────────────────────

if [[ ! -x "$HARK_BIN" ]] || [[ -n "${REBUILD:-}" ]]; then
    echo ">>> building hark (ReleaseFast)"
    (cd "$REPO_ROOT" && zig build -Doptimize=ReleaseFast)
fi

# ── build dnsjit ─────────────────────────────────────────────────────────

if [[ ! -d "$DNSJIT_DIR" ]]; then
    echo ">>> cloning dnsjit @ $DNSJIT_REF"
    git clone --depth 1 --branch "$DNSJIT_REF" \
        https://github.com/DNS-OARC/dnsjit.git "$DNSJIT_DIR"
fi

if [[ ! -f "$DNSJIT_DIR/.installed" ]]; then
    echo ">>> building dnsjit"
    (
        cd "$DNSJIT_DIR"
        ./autogen.sh
        ./configure --prefix="$DNSJIT_DIR/install"
        make -j"$(nproc)"
        make install
        touch .installed
    )
fi

export PKG_CONFIG_PATH="$DNSJIT_DIR/install/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export LD_LIBRARY_PATH="$DNSJIT_DIR/install/lib:${LD_LIBRARY_PATH:-}"
export LUA_PATH="$DNSJIT_DIR/install/share/dnsjit/?.lua;${LUA_PATH:-;;}"
export LUA_CPATH="$DNSJIT_DIR/install/lib/lua/?.so;${LUA_CPATH:-;;}"
export PATH="$DNSJIT_DIR/install/bin:$PATH"

# ── build shotgun + dnssim ───────────────────────────────────────────────

if [[ ! -d "$SHOTGUN_DIR" ]]; then
    echo ">>> cloning shotgun @ $SHOTGUN_REF"
    git clone --depth 1 --branch "$SHOTGUN_REF" \
        https://github.com/CZ-NIC/shotgun.git "$SHOTGUN_DIR"
fi

SHOTGUN_INSTALL="$SHOTGUN_DIR/install"
if [[ ! -f "$DNSSIM_LIB" ]] || [[ ! -f "$SHOTGUN_INSTALL/share/lua/5.1/shotgun/output/dnssim.lua" ]]; then
    echo ">>> building + installing dnssim → $SHOTGUN_INSTALL"
    (
        cd "$SHOTGUN_DIR/replay/dnssim"
        mkdir -p build
        cd build
        # CPATH so cmake's check_include_file finds dnsjit/version.h.
        # LIBRARY_PATH so the linker finds libdnsjit.
        export CPATH="$DNSJIT_DIR/install/include${CPATH:+:$CPATH}"
        export LIBRARY_PATH="$DNSJIT_DIR/install/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
        cmake .. \
            -DCMAKE_BUILD_TYPE=Release \
            -DDNSJIT_PATH="$DNSJIT_DIR/install" \
            -DCMAKE_INSTALL_PREFIX="$SHOTGUN_INSTALL" \
            -DUSE_SYSTEM_NGTCP2=ON \
            -G Ninja
        cmake --build .
        cmake --install .
    )
fi

# Make `require("shotgun.output.dnssim")` resolvable.
export LUA_PATH="$SHOTGUN_INSTALL/share/lua/5.1/?.lua;$SHOTGUN_INSTALL/share/lua/5.1/?/init.lua;$LUA_PATH"
export LUA_CPATH="$SHOTGUN_INSTALL/lib/lua/5.1/?.so;$LUA_CPATH"

if [[ "$PROTOCOL" == bootstrap ]]; then
    echo
    echo ">>> bootstrap done. next:"
    echo "    ./capture-pellet.sh 300         # build a pellet from local DNS"
    echo "    ./run.sh udp ./pellet.pcap      # replay it"
    exit 0
fi

if [[ ! -f "$PELLET" ]]; then
    cat >&2 <<EOF

no pellet at $PELLET

Build is ready, but you need a pellet to replay. Generate one:

    ./capture-pellet.sh 300       # capture local DNS for 5 min

or supply your own (PCAP processed through shotgun's extract-clients.lua) at
$PELLET, or set PELLET=path.
EOF
    exit 1
fi

# ── prep output dir ──────────────────────────────────────────────────────

TIMESTAMP="$(date +%Y-%m-%d-%H%M%S)"
OUT_DIR="$BENCH_DIR/outputs/$TIMESTAMP"
mkdir -p "$BENCH_DIR/outputs"
# replay.py requires its outdir to not exist (or to be wiped via -f). We let
# it create the dir; hark.log goes to a tempfile and is moved in after.
HARK_LOG="$(mktemp -t hark-recursion-XXXXXX.log)"

HARK_PID=""
cleanup() {
    [[ -n "$HARK_PID" ]] && kill "$HARK_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# ── start hark (unless OTHER_RESOLVER) ───────────────────────────────────

# Resolver-readiness probe. Returns 0 only if the port answers with an
# IPv4-shaped record — SERVFAIL, REFUSED, and connection-refused all fail.
port_is_serving() {
    [[ "$(dig +tries=1 +time=1 +short @127.0.0.1 -p "$HARK_PORT" \
            example.com. A 2>/dev/null | head -1)" =~ ^[0-9.]+$ ]]
}

if [[ -n "${OTHER_RESOLVER:-}" ]]; then
    echo ">>> bypassing hark, driving replay at $OTHER_RESOLVER"
elif port_is_serving; then
    if [[ -n "${WARM:-}" ]]; then
        echo ">>> reusing already-running hark @ $HARK_ADDR (WARM=$WARM, cache preserved)"
    else
        echo "port $HARK_PORT already serving — refusing to clobber. Set WARM=1 to reuse." >&2
        exit 1
    fi
else
    echo ">>> starting hark @ $HARK_ADDR (cold cache)"
    "$HARK_BIN" serve --config "$BENCH_DIR/hark.toml" >"$HARK_LOG" 2>&1 &
    HARK_PID=$!

    for i in $(seq 1 50); do
        if port_is_serving; then echo ">>> hark ready"; break; fi
        sleep 0.2
        if [[ "$i" == 50 ]]; then
            echo "hark failed to come up; tail of log:" >&2
            tail -20 "$HARK_LOG" >&2
            exit 1
        fi
    done
fi

# ── run shotgun replay ───────────────────────────────────────────────────
#
# `-c` accepts either a preset name (looked up in shotgun's configs/) or a
# path to a .toml. We prefer a local override at bench/recursion/configs/
# if present; otherwise fall back to the upstream preset.

CONFIG="$BENCH_DIR/configs/${PROTOCOL}.toml"
if [[ ! -f "$CONFIG" ]]; then
    CONFIG="$PROTOCOL"   # name-resolved against $SHOTGUN_DIR/configs/
fi

# Parse $TARGET as either "v4:port" or "[v6]:port". Fail loudly on anything
# else; getting this wrong silently is the kind of bug that costs a week.
if [[ "$TARGET" =~ ^\[(.+)\]:([0-9]+)$ ]]; then
    TARGET_IP="${BASH_REMATCH[1]}"
    TARGET_PORT="${BASH_REMATCH[2]}"
elif [[ "$TARGET" =~ ^([0-9.]+):([0-9]+)$ ]]; then
    TARGET_IP="${BASH_REMATCH[1]}"
    TARGET_PORT="${BASH_REMATCH[2]}"
else
    echo "TARGET '$TARGET' is not 'v4:port' or '[v6]:port'" >&2
    exit 2
fi

echo ">>> replay: protocol=$PROTOCOL pellet=$PELLET → $TARGET_IP:$TARGET_PORT"
REPLAY_LOG="$(mktemp -t hark-replay-XXXXXX.log)"
(
    cd "$SHOTGUN_DIR"
    ./replay.py \
        -c "$CONFIG" \
        -r "$PELLET" \
        -s "$TARGET_IP" \
        --dns-port "$TARGET_PORT" \
        -O "$OUT_DIR" \
        -f \
        2>&1
) | tee "$REPLAY_LOG"

# Ensure OUT_DIR exists even if replay.py crashed before creating it, so we
# don't silently lose hark.log / replay.log diagnosis.
mkdir -p "$OUT_DIR"
mv "$REPLAY_LOG" "$OUT_DIR/replay.log"
mv "$HARK_LOG"   "$OUT_DIR/hark.log" 2>/dev/null || true   # absent if OTHER_RESOLVER
cat >"$OUT_DIR/run.txt" <<EOF
protocol=$PROTOCOL
pellet=$PELLET
target=$TARGET
warm=${WARM:-0}
hark_commit=$(cd "$REPO_ROOT" && git rev-parse --short HEAD)
shotgun_ref=$SHOTGUN_REF
dnsjit_ref=$DNSJIT_REF
EOF

# ── plot ─────────────────────────────────────────────────────────────────
#
# replay.py writes per-traffic-class subdirs containing a JSON. Plotter walks
# the outdir and emits charts named after the [charts.*] sections of the
# preset toml.

if compgen -G "$OUT_DIR/*/data.json" >/dev/null 2>&1; then
    echo ">>> plotting latency histogram"
    "$SHOTGUN_DIR/tools/plot-latency.py" \
        -o "$OUT_DIR/latency.png" \
        -t "hark recursion latency ($PROTOCOL)" \
        "$OUT_DIR"/*/data.json \
        || echo "(plot-latency.py failed; raw JSON kept at $OUT_DIR)" >&2
fi

echo
echo ">>> outputs in $OUT_DIR"
ls -1 "$OUT_DIR"
