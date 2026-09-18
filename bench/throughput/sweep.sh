#!/usr/bin/env bash
# Sweep workloads. Each workload spins a fresh hark process to avoid cache
# carry-over polluting later iterations. Cache settings are inherited from
# hark.toml so sweep and direct `bench` runs use identical cache geometry.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BENCH_DIR="$REPO_ROOT/bench/throughput"
TMP_PARENT="$(mktemp -d -t hark-sweep-XXXXXX)"
TMPCONF="$TMP_PARENT/hark.toml"
trap 'rm -rf "$TMP_PARENT"' EXIT

DURATION="${DURATION:-15}"
INFLIGHT="${INFLIGHT:-1000}"
# Recorded into the baseline header. ReleaseSafe vs ReleaseFast diverge by ~20%
# on hot paths (e.g. wire_buf 0xAA-init in safe mode), so capturing the build
# mode is the difference between a comparable baseline and an unverifiable one.
BUILD_MODE="${BUILD_MODE:-unset}"
WORKLOADS="${WORKLOADS:-hit miss mix}"
LATENCY_MS="${LATENCY_MS:-}"

# Inherit cache settings from hark.toml so the materialized sweep config
# matches the committed defaults — anyone editing hark.toml gets the new
# values for free.
hark_toml="$BENCH_DIR/hark.toml"
CACHE_SIZE="$(awk -F'=' '/^[[:space:]]*size[[:space:]]*=/ {gsub(/[[:space:]]/,""); print $2; exit}' "$hark_toml")"

LATENCY_TAG=""
[[ -n "$LATENCY_MS" ]] && LATENCY_TAG="-rtt${LATENCY_MS}ms"

if [[ "$BUILD_MODE" == "unset" ]]; then
    echo "WARN: BUILD_MODE not set; baseline will record build=unset" >&2
    echo "      set BUILD_MODE=ReleaseFast (or matching -Doptimize) for a recordable run" >&2
fi

OUT="$BENCH_DIR/../baselines/throughput-$(date +%Y-%m-%d)${LATENCY_TAG}.txt"

{
    echo "# hark throughput sweep — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# build=${BUILD_MODE} duration=${DURATION}s inflight=${INFLIGHT} latency_ms=${LATENCY_MS:-0}"
    echo "# cache.size=${CACHE_SIZE}"
    echo "# workload     totqps   noerrqps     servfail%   lost%"
} > "$OUT"

for workload in $WORKLOADS; do
    cat > "$TMPCONF" <<EOF
[server]
listen = ["127.0.0.1:5354"]

[resolver]
dnssec = false
qname-minimization = false

[cache]
size = $CACHE_SIZE
EOF

    echo ">>> workload=$workload latency=${LATENCY_MS:-0}ms"
    OUTPUT="$(HARK_CONFIG="$TMPCONF" LATENCY_MS="$LATENCY_MS" "$BENCH_DIR/run.sh" bench "$workload" "$DURATION" "$INFLIGHT" 2>&1 || true)"

    QPS="$(echo "$OUTPUT" | awk '/Queries per second:/ { print $4 }')"
    LOST="$(echo "$OUTPUT" | awk '/Queries lost:/ { gsub(/[()%]/,""); print $4 }')"
    # dnsperf "Response codes" line: "  Response codes:       NOERROR N (X.XX%), SERVFAIL N (X.XX%)"
    NOERR_PCT="$(echo "$OUTPUT" | awk -F'[(),%]' '/Response codes:.*NOERROR/ {
        for (i=1;i<=NF;i++) if ($i ~ /NOERROR/) { print $(i+1); exit }
    }' | tr -d ' ')"
    SERVFAIL_PCT="$(echo "$OUTPUT" | awk -F'[(),%]' '/Response codes:.*SERVFAIL/ {
        for (i=1;i<=NF;i++) if ($i ~ /SERVFAIL/) { print $(i+1); exit }
    }' | tr -d ' ')"
    # Successful (NOERROR) QPS = total QPS × NOERROR fraction.
    NOERR_QPS="$(awk -v q="${QPS:-0}" -v p="${NOERR_PCT:-0}" 'BEGIN{ printf "%.0f", q*p/100 }')"

    printf "  %-9s %10.0f %10s %12s %8s\n" \
        "$workload" "${QPS:-0}" "$NOERR_QPS" "${SERVFAIL_PCT:-0}" "${LOST:-?}" \
        | tee -a "$OUT"
done

echo ""
echo "results → $OUT"
