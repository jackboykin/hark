#!/usr/bin/env bash
# Throughput bench harness for hark. Runs entirely inside a user+net namespace
# so port 53 is freely bindable (uid 0 inside the user-ns) and 198.41.0.4 can
# be aliased onto lo without root on the host. NSD answers as the root + test
# TLD; hark's hardcoded root_hints work unmodified.
#
# Usage:
#   run.sh smoke
#   run.sh bench <hit|miss|mix> [duration_s] [inflight]
#   run.sh profile <hit|miss|mix> [duration_s] [inflight]
#   run.sh direct-nsd [duration_s] [inflight]
#
# Env vars:
#   LATENCY_MS        netem one-way delay on lo (each TX adds this once)
#   HARK_CONFIG       override config path (used by sweep.sh)
#   PROFILE_OUT_DIR   where `profile` writes flame.svg / perf-top.txt / .data
#
# Re-execs itself inside `unshare -Urn` if not already namespaced, signalled by
# HARK_BENCH_IN_NS=1.

set -euo pipefail

CMD="${1:-smoke}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BENCH_DIR="$REPO_ROOT/bench/throughput"
HARK_BIN="$REPO_ROOT/zig-out/bin/hark"
DEFAULT_INFLIGHT=1000

if [[ ! -x "$HARK_BIN" ]]; then
    echo "hark binary not found at $HARK_BIN — run 'zig build -Doptimize=ReleaseFast' first" >&2
    exit 1
fi

HARK_CONFIG="${HARK_CONFIG:-$BENCH_DIR/hark.toml}"

if [[ "${HARK_BENCH_IN_NS:-}" != "1" ]]; then
    echo ">>> entering user+net namespace"
    exec env HARK_BENCH_IN_NS=1 unshare -Urn -- "$0" "$@"
fi

# ── inside the namespace from here ───────────────────────────────────────

TMPDIR="$(mktemp -d -t hark-bench-XXXXXX)"
NSD_CONF="$TMPDIR/nsd.conf"
HARK_LOG="$TMPDIR/hark.log"
NSD_LOG="$TMPDIR/nsd.stderr"
NSD_PID=""
HARK_PID=""

cleanup() {
    [[ -n "$HARK_PID" ]] && kill "$HARK_PID" 2>/dev/null || true
    [[ -n "$NSD_PID" ]] && kill "$NSD_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    # Defensive: outside a netns the qdisc would persist on lo. Inside, the
    # netns evaporates so this is a no-op.
    [[ -n "${LATENCY_MS:-}" ]] && tc qdisc del dev lo root 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# Compute a dnsperf per-query timeout that scales with simulated RTT — at
# LATENCY_MS=2000 a cold-cache miss is ~12s end-to-end; default 5s wouldn't
# survive. Floor at 5s.
dnsperf_timeout() {
    if [[ -n "${LATENCY_MS:-}" ]]; then
        echo $(( LATENCY_MS * 12 / 1000 + 5 ))
    else
        echo 5
    fi
}

# dig +time= takes integer seconds. Cold-cache misses through netem cost
# ~6N × LATENCY_MS each direction; pad and floor at 2s. Used for ready-probes
# and smoke checks so they survive high-LATENCY_MS sweeps.
dig_timeout() {
    if [[ -n "${LATENCY_MS:-}" ]]; then
        local t=$(( LATENCY_MS * 6 / 1000 + 2 ))
        echo $(( t < 2 ? 2 : t ))
    else
        echo 2
    fi
}

# Poll dig until <addr>:<port> answers, or fail after ~5s (50 × 0.1s).
# Extra args are appended to the dig command line (e.g. the query name+type).
wait_for_listener() {
    local label="$1" addr="$2" port="$3"
    shift 3
    local timeout
    timeout="$(dig_timeout)"
    for i in $(seq 1 50); do
        if dig +short +time="$timeout" +tries=1 @"$addr" -p "$port" "$@" >/dev/null 2>&1; then
            echo ">>> $label ready"
            return 0
        fi
        sleep 0.1
    done
    echo "$label failed to come up in 5s" >&2
    return 1
}

generate_queries() {
    local workload="$1"
    local out="$2"
    python3 "$BENCH_DIR/gen_queries.py" "$workload" > "$out"
}

echo ">>> bringing up lo with 127.0.0.1 + 198.41.0.4 alias"
ip link set lo up
ip addr add 198.41.0.4/32 dev lo
# IPv6 ::1 lets hark's IPv6 root-hint attempts fail fast as ENETUNREACH
# rather than hanging on no-default-route inside the namespace.
ip -6 addr add ::1/128 dev lo 2>/dev/null || true

# Optional: simulate authoritative RTT via netem on lo. Each lo TX adds the
# configured one-way delay once. Per-query observed latency at dnsperf is
# 2N × LATENCY_MS where N is the number of round trips in the resolution
# (1 for cache hit, 2 for warm-root miss, 3+ for cold-root). Throughput
# numbers still measure hark's real scaling.
#
# Default netem queue is 1000 packets — at 25ms × 40kpps that's the buffer
# cap, masquerading as a hark throughput ceiling. Limit=200000 lifts that.
if [[ -n "${LATENCY_MS:-}" ]]; then
    echo ">>> applying tc netem delay ${LATENCY_MS}ms limit 200000 on lo"
    tc qdisc add dev lo root netem delay "${LATENCY_MS}ms" limit 200000
fi

echo ">>> materializing nsd.conf at $NSD_CONF"
sed -e "s|__BENCHDIR__|$BENCH_DIR|g" -e "s|__TMPDIR__|$TMPDIR|g" \
    "$BENCH_DIR/nsd.conf.template" > "$NSD_CONF"

echo ">>> starting NSD on 198.41.0.4:53 (stderr → $NSD_LOG)"
nsd -c "$NSD_CONF" -d 2>"$NSD_LOG" &
NSD_PID=$!

wait_for_listener NSD 198.41.0.4 53 . SOA

echo ">>> starting hark on 127.0.0.1:5354 (config: $HARK_CONFIG)"
"$HARK_BIN" serve --config "$HARK_CONFIG" >"$HARK_LOG" 2>&1 &
HARK_PID=$!

wait_for_listener hark 127.0.0.1 5354 smoke.test. A

case "$CMD" in
    direct-nsd)
        # Bypass hark entirely — drive dnsperf straight at NSD on 198.41.0.4:53.
        # Tells us how much of a measured ceiling is hark vs. NSD/netem.
        DURATION="${2:-15}"
        INFLIGHT="${3:-$DEFAULT_INFLIGHT}"
        QFILE="$TMPDIR/queries.txt"
        generate_queries miss "$QFILE"
        echo ">>> dnsperf direct→NSD: duration=${DURATION}s inflight=$INFLIGHT"
        dnsperf -s 198.41.0.4 -p 53 -d "$QFILE" -l "$DURATION" -c 1 -q "$INFLIGHT" -t "$(dnsperf_timeout)" \
            2>&1 | tee "$TMPDIR/dnsperf.out"
        ;;
    profile)
        # Attach perf to hark for the duration of a workload run, then collapse
        # stacks into a flamegraph. Requires ReleaseSafe (or ReleaseFast — Zig
        # emits frame-pointer prologues either way) for symbols.
        WORKLOAD="${2:-miss}"
        DURATION="${3:-15}"
        INFLIGHT="${4:-$DEFAULT_INFLIGHT}"
        OUT_DIR="${PROFILE_OUT_DIR:-$REPO_ROOT/bench/baselines}"
        TAG="${WORKLOAD}${LATENCY_MS:+-rtt${LATENCY_MS}ms}"
        QFILE="$TMPDIR/queries.txt"
        generate_queries "$WORKLOAD" "$QFILE"

        # Frame-pointer unwinding: dwarf produces empty stacks under high thread
        # count due to sample-buffer pressure, fp works because Zig keeps %rbp.
        echo ">>> perf record -F 99 --call-graph fp on hark pid=$HARK_PID for ${DURATION}s"
        perf record -F 99 -p "$HARK_PID" --call-graph fp -o "$TMPDIR/perf.data" -- \
            sleep "$DURATION" &
        PERF_PID=$!
        # Verify perf actually attached — if it died immediately, abort before
        # running the load and burning a slot in baselines/.
        sleep 0.2
        if ! kill -0 "$PERF_PID" 2>/dev/null; then
            echo "perf record exited immediately — check perf_event_paranoid" >&2
            exit 1
        fi

        echo ">>> dnsperf: workload=$WORKLOAD duration=${DURATION}s inflight=$INFLIGHT"
        dnsperf -s 127.0.0.1 -p 5354 -d "$QFILE" -l "$DURATION" -c 1 -q "$INFLIGHT" -t "$(dnsperf_timeout)" \
            2>&1 | tee "$TMPDIR/dnsperf.out"

        wait "$PERF_PID"

        today="$(date +%Y-%m-%d)"
        SVG="$OUT_DIR/flame-${TAG}-${today}.svg"
        TXT="$OUT_DIR/perf-top-${TAG}-${today}.txt"
        DATA="$OUT_DIR/perf-${TAG}-${today}.data"

        echo ">>> generating flamegraph → $SVG"
        perf script -i "$TMPDIR/perf.data" \
            | stackcollapse-perf.pl \
            | flamegraph.pl --title "hark $TAG" > "$SVG"
        perf report -i "$TMPDIR/perf.data" --stdio --no-children -n -g none 2>/dev/null \
            | head -60 > "$TXT" || true
        cp "$TMPDIR/perf.data" "$DATA"

        echo ">>> profile artifacts:"
        echo "    $SVG"
        echo "    $TXT"
        echo "    $DATA"
        ;;
    smoke)
        echo ">>> smoke test: dig smoke.test. via hark"
        ANSWER="$(dig +short @127.0.0.1 -p 5354 smoke.test. A)"
        # smoke.test. has an explicit A record at 127.0.0.42 in test.zone —
        # distinct from the wildcard's 127.0.0.1, so this verifies the explicit
        # path rather than passing by accident on wildcard fallthrough.
        if [[ "$ANSWER" == "127.0.0.42" ]]; then
            echo "PASS: smoke.test. → $ANSWER"
        else
            echo "FAIL: expected 127.0.0.42, got '$ANSWER'" >&2
            exit 1
        fi

        SMOKE_T="$(dig_timeout)"
        echo ">>> raw dig direct to NSD (RTT sanity check)"
        dig +tries=1 +time="$SMOKE_T" @198.41.0.4 . SOA | awk '/Query time/'

        echo ">>> raw dig via hark (cold-cache miss, RTT sanity check)"
        dig +tries=1 +time="$SMOKE_T" @127.0.0.1 -p 5354 "rtt-$(date +%s%N).test." A | awk '/Query time/'
        ;;
    bench)
        WORKLOAD="${2:-hit}"
        DURATION="${3:-10}"
        INFLIGHT="${4:-$DEFAULT_INFLIGHT}"

        QFILE="$TMPDIR/queries.txt"
        generate_queries "$WORKLOAD" "$QFILE"
        if [[ "$WORKLOAD" == "hit" ]]; then
            echo ">>> warming cache (8 names)"
            warm_t="$(dig_timeout)"
            for i in {1..8}; do
                dig +short +tries=1 +time="$warm_t" @127.0.0.1 -p 5354 "host${i}.test." A >/dev/null
            done
        fi

        echo ">>> dnsperf: workload=$WORKLOAD duration=${DURATION}s inflight=$INFLIGHT"
        dnsperf -s 127.0.0.1 -p 5354 -d "$QFILE" -l "$DURATION" -c 1 -q "$INFLIGHT" -t "$(dnsperf_timeout)" \
            2>&1 | tee "$TMPDIR/dnsperf.out"

        # Surface log activity. SERVFAIL lines (if logged) tell us *why* the
        # resolver is failing under load. If they're not there, log level is
        # higher than warn in this build.
        echo ">>> hark log: $(wc -l < "$HARK_LOG") lines"
        if grep -q SERVFAIL "$HARK_LOG"; then
            echo ">>> SERVFAIL error-name distribution (top 10):"
            grep SERVFAIL "$HARK_LOG" \
                | sed -nE 's/.*SERVFAIL [0-9]+ms \(([^)]+)\).*/\1/p' \
                | sort | uniq -c | sort -rn | head -10
        fi
        ;;
    *)
        echo "unknown command: $CMD" >&2
        exit 2
        ;;
esac
