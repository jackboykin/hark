# bench/recursion — realistic recursion-time benchmarking

Measures hark's end-to-end recursion latency under replayed client traffic,
hitting **the actual internet** (root → TLD → authoritative). Built on
[DNS Shotgun] (CZ.NIC), the load-generator ISC also uses for BIND
[resolver perf comparisons].

This rig is **not** apples-to-apples with ISC's published BIND numbers —
those use anonymized production captures at steady state against a captive
auth-tree replica (deterministic RTT). Ours uses synthesized or local
captures against the live internet (variance-dominated). Treat the output
as: *"did hark regress vs last week on this network with this pellet?"*
For publishable comparisons, run hark and a reference resolver back-to-back
on the same machine + pellet and report the **delta** (see `OTHER_RESOLVER`
below).

This is the complement to `bench/throughput/`, **not a replacement**:

| harness | answers what | environment | gates regressions? |
|---|---|---|---|
| `bench/throughput/` | per-packet cost & hot path regressions | netns + synthetic NSD | yes (CI-friendly) |
| `bench/recursion/` | real recursion latency distribution | real internet | no (network-flake) |

[DNS Shotgun]: https://github.com/CZ-NIC/shotgun
[resolver perf comparisons]: https://www.isc.org/blogs/2026-03-05-bind-resolver-performance/

## Why Shotgun

The wisdom from ISC, CZ.NIC, and the Balážik 2025 cache-policy paper:

1. **Queries are not independent.** Each one mutates cache state. Synthetic
   uniform random streams don't represent real workloads.
2. **Authoritative latency dominates.** netem on lo is a coarse approximation
   of real internet. SERVFAILs, lame delegations, IPv6 black holes,
   anycast jitter — only the real internet has them.
3. **QPS is theoretical.** Shotgun reports a latency histogram and a "load
   factor" (replay N captures into 1 instance). Means are meaningless given
   the bimodal hit/miss distribution.

The accepted shape of the answer:

| percentile | latency | what it is |
|---|---|---|
| p95 | < 1 ms | cache hits |
| p99 | < 100 ms | typical cold miss |
| p99.5 | < 1000 ms | problematic miss (slow auth, retries) |
| p99.9+ | seconds | SERVFAILs, lame delegations |

## Pipeline

```
  raw.pcap                            (your capture or a published one)
     │
     │  filter-dnsq.lua                (drop non-DNS)
     ▼
  filtered.pcap
     │
     │  extract-clients.lua            (per-client pellets, original timing)
     ▼
  pellet.pcap
     │
     │  replay.py + dnssim             (replay to hark, measure)
     ▼
  outputs/{json,charts/}
```

## Prereqs

A pellet (real or simulated) and the deps in `shell.nix`. On NixOS:

```sh
nix-shell bench/recursion/shell.nix
```

The shell brings in everything dnsjit + shotgun's dnssim need to build, plus
the Python plotting deps. First entry will compile dnsjit + dnssim from source
into `bench/recursion/.shotgun/` (gitignored) — takes a few minutes.

## Sourcing a pellet

Real PCAPs of client→resolver traffic aren't generally redistributable
(privacy). Four options, in increasing order of realism:

1. **Synthesize from a name list** *(no root, reproducible — recommended for trends)*

   ```sh
   zig build synth-pellet
   ./zig-out/bin/synth-pellet \
     --names bench/recursion/sample-names.txt \
     --qps 100 --duration 60 --clients 50 \
     --out bench/recursion/pellet.pcap \
     --unique-suffix    # forces every query to be a cold cache miss
   ```

   The synthesizer reuses hark's own DNS encoder (`src/dns.zig`), so a
   malformed query is a hark bug — useful side effect. Without
   `--unique-suffix`, queries cycle the name list as-is, hitting the cache
   after the first pass; with it, each query gets a per-query random label
   prepended (`xN.example.com`) and forces real recursion every time.
   `bench/recursion/sample-names.txt` ships ~150 popular domains; swap with
   a top-1M list (Tranco, Cisco Umbrella) for richer workloads.

2. **Capture your own** — `./capture-pellet.sh [duration_seconds]` records
   your local DNS traffic and turns it into a pellet. Needs `CAP_NET_RAW`
   (sudo or set caps on dumpcap). Biased toward whatever you happened to do
   during the capture window.
3. **Published research captures** — CZ.NIC and ISC reference anonymized
   captures in their BIND comparison work; not all are public. Check the
   Shotgun docs for current pointers.
4. **Production capture from your own resolver** — if you operate a resolver,
   capture client→resolver traffic at the edge and run it through
   `extract-clients.lua`. This is what ISC does for BIND benchmarking.

A pellet ships at `pellet.pcap` in this directory by convention. `run.sh`
expects it there unless `PELLET=` overrides.

## Running

```sh
./run.sh                       # default: udp protocol, ./pellet.pcap, 60s
./run.sh udp 120 ./big.pcap    # protocol, duration, pellet
PROTOCOL=tcp ./run.sh
```

`run.sh` will:

1. Build hark in `ReleaseFast` if missing.
2. Build dnsjit + dnssim in `.shotgun/` if missing.
3. Start hark on `127.0.0.1:5354` with `hark.toml` (recursion against real
   internet, DNSSEC + qname-min on — production-representative).
4. Run `replay.py` to drive the pellet at hark.
5. Collect JSON outputs and emit a log percentile histogram into
   `outputs/<timestamp>/`.

## Comparing to other resolvers (the publishable-numbers workflow)

Same pellet, same network, swap the resolver. Run hark, capture the JSON;
run unbound on a different port, capture again; report the **delta**:

```sh
./run.sh udp ./pellet.pcap                                 # hark run
OTHER_RESOLVER=127.0.0.1:5355 ./run.sh udp ./pellet.pcap   # unbound run
# Compare outputs/*/data/UDP.json latency arrays.
```

`OTHER_RESOLVER` accepts `IP:PORT` for v4 or `[V6]:PORT` for v6. Anything
else fails fast.

## Caveats

- **Internet weather.** Authoritative RTT, transient SERVFAILs, and your own
  upstream connectivity dominate the long tail. The same pellet on the same
  network at 3am and 3pm produces different p99s.
- **Warmup.** The first 5–10 seconds include trust-anchor fetch, root-hint
  priming, and NS RTT learning, which inflate p99/p99.5. For tight numbers,
  pre-warm hark with a throwaway pellet, then run the measurement pellet
  with `WARM=1`.
- **Scheduler jitter at the tail.** For sub-millisecond p95 stability,
  pin hark and the load generator to disjoint cores: `taskset -c 0-3` for
  hark, `-c 4-7` for `replay.py`. Not currently automated by `run.sh`.
- **Pellet bias.** Your local-capture pellet reflects whatever you browsed.
  For trends, hold the pellet constant across runs.
- **`hark.toml` is config-tunable.** `case-randomization=true` is on (raises
  upstream auth load — production-realistic, but BIND/Unbound defaults
  differ). The cache is sized so the entries cap (200k) is the binding
  constraint, not bytes — intentional for top-1M workloads.
- **Privacy.** Captured pellets contain real DNS queries from real clients
  on your machine — yours and whoever else uses it. Treat the resulting
  PCAP as PII; don't email, paste, or upload it. `.gitignore` excludes
  `*.pcap` as a backstop, not a control.

## Prereqs note

On NixOS, `wireshark-cli` from `shell.nix` does not by default give dumpcap
`CAP_NET_RAW`. Either enable system-wide
(`programs.wireshark.enable = true;`) or run `capture-pellet.sh` under sudo
and chown the resulting PCAP back. The recommended path (#1, synthesize) has
no such requirement.
