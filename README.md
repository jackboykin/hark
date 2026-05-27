# hark

A validating, recursive, caching DNS resolver built from scratch in Zig.
Runs on Linux with io_uring.

## Features

- **Concurrent resolution** — per-worker thread pool with blocking sockets; main thread stays on io_uring for client I/O
- **Staggered NS racing** — query two nameservers with adaptive delay, take first response (RFC 5452 safe)
- **DNSSEC validation** — RSA-SHA1/256/512, ECDSA P-256/P-384, Ed25519; validate-then-store; dedicated key cache
- **Aggressive NSEC negative caching** — synthesize NXDOMAIN/NODATA from cached NSEC records with wildcard synthesis (RFC 8198)
- **DNS-over-TLS** — opportunistic encryption to authoritatives (RFC 9539) with background probing and connection pooling
- **Full recursive resolution** from root hints with QNAME minimization
- **TCP connection pooling** for upstream queries (RFC 7766)
- **In-memory RRset cache** with SIEVE eviction, RFC 2308 negative caching, prefetch, A/AAAA cousin prefetch (RFC 8305), serve-stale (RFC 8767)
- **Thompson Sampling** nameserver selection (per-zone, discounted)
- **Query deduplication** across workers (singleflight)
- **Multi-threaded server** with `SO_REUSEPORT`, per-query memory cap
- UDP and TCP transport with EDNS0

## Building

Requires Zig 0.16 and Linux 6.1+ (io_uring buffer rings + DEFER_TASKRUN).

```
zig build
zig build test
zig build bench              # microbenchmarks; ReleaseFast
zig build bench -- cache_hit # filter to matching names
```

## Usage

Resolve a name recursively (the default):

```
hark query example.com AAAA
hark query example.com --dnssec
hark query example.com --opportunistic
```

Run as a server (UDP + TCP, TOML config):

```
hark serve --config /etc/hark/hark.toml
```

Dump a raw DNS packet from stdin:

```
hark dump < packet.bin
```

## Configuration

```toml
[server]
listen = ["127.0.0.1:53", "[::1]:53"]
workers = 2                   # range 1..65535; raise for high-QPS
resolution-threads = 4        # pool threads per worker (1..256)
max-udp-payload = 1232        # advertised OPT + outbound clamp (512..65535)

[resolver]
dnssec = false
qname-minimization = true     # RFC 9156
case-randomization = true     # 0x20 QNAME case (Vixie/Dagon)
opportunistic = false         # RFC 9539 encrypted to authoritatives
stagger-ms = 150              # NS racing delay; 0 disables, max 1000
query-memory-limit = 2097152  # per-query arena cap, bytes (0 disables; min 65536)

[cache]
size = 16777216               # answer cache, bytes
entries = 10000               # answer cache, max entries
key-cache-size = 4194304      # DNSKEY/DS cache, bytes
key-cache-entries = 2000      # DNSKEY/DS cache, max entries
prefetch = false              # refresh near-expiry entries
prefetch-cousin = true        # also fetch the other A/AAAA on lookup
serve-stale-ttl = 0           # serve expired up to N seconds (RFC 8767)
min-ttl = 0                   # floor for aggressive CDN TTLs

[logging]
queries = false               # per-query log lines
```

Every value shown is the default — copying the snippet verbatim is a no-op. Omit a key to get the same default.

## Design

- **Linux-first** — io_uring for client I/O, blocking sockets for upstream queries. Portability is not a goal.
- **Vendor-minimal** — stdlib first; one vendored Zig library for DoT (see [Credits](#credits)). No package manager, no fetched deps, no vendored C.
- **Tested** — fuzzed parsers, integration tests against live DNS, leak detection via `std.testing.allocator`.

## Credits

DoT uses [ianic/tls.zig](https://github.com/ianic/tls.zig) (MIT, Igor Anić),
vendored under `src/vendor/tls-ianic/`. See that directory's `PATCHES.md`
for the pinned commit, local patch, and refresh procedure.
