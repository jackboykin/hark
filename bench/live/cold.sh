#!/usr/bin/env bash
# usage: cold.sh <label=hark>... < names: per name, a fresh primed process per side, one A+DO query: ms rcode ad
D=$(cd "$(dirname "$0")" && pwd)
up() { "$1" serve --config "$D/hark.toml" >/dev/null 2>&1 & pid=$!; for _ in $(seq 50); do dig +time=1 +tries=1 @127.0.0.1 -p 5361 . NS >/dev/null 2>&1 && return; sleep 0.05; done; }
while read -r name; do
  for s in "$@"; do
    up "${s#*=}"; kill $pid; wait $pid 2>/dev/null
    up "${s#*=}"
    out=$(dig +dnssec +time=10 +tries=1 @127.0.0.1 -p 5361 "$name" A)
    kill $pid; wait $pid 2>/dev/null
    echo "${s%%=*} $name $(sed -n 's/.*Query time: \([0-9]*\) msec.*/\1/p' <<<"$out") $(sed -n 's/.*status: \([A-Z]*\),.*/\1/p' <<<"$out") $(grep -q 'flags:.* ad' <<<"$out" && echo ad || echo -)"
  done
done
