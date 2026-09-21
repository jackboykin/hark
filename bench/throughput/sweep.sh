#!/usr/bin/env bash
# Sweep workloads. Each workload spins a fresh hark process on bench/throughput/
# hark.toml, so no cache carries over between workloads.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BENCH_DIR="$REPO_ROOT/bench/throughput"

DURATION="${DURATION:-15}"
INFLIGHT="${INFLIGHT:-1000}"
WORKLOADS="${WORKLOADS:-hit miss mix}"
LATENCY_MS="${LATENCY_MS:-}"

echo "# duration=${DURATION}s inflight=${INFLIGHT} latency_ms=${LATENCY_MS:-0}"
echo "# workload     totqps   noerrqps     servfail%   lost%"

for workload in $WORKLOADS; do
    echo ">>> workload=$workload latency=${LATENCY_MS:-0}ms"
    OUTPUT="$(LATENCY_MS="$LATENCY_MS" "$BENCH_DIR/run.sh" bench "$workload" "$DURATION" "$INFLIGHT" 2>&1 || true)"

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
        "$workload" "${QPS:-0}" "$NOERR_QPS" "${SERVFAIL_PCT:-0}" "${LOST:-?}"
done
