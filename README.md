# hark

A validating, recursive, caching DNS resolver built from scratch in Zig.
Runs on Linux with io_uring. Zero external dependencies.

## Features

- **Concurrent resolution** — per-worker thread pool with blocking sockets; main thread stays on io_uring for client I/O
- **Staggered NS racing** — query two nameservers with adaptive delay, take first response (RFC 5452 safe)
- **DNSSEC validation** — RSA-SHA1/256/512, ECDSA P-256/P-384, Ed25519; validate-then-store; dedicated key cache
- **Aggressive NSEC negative caching** — synthesize NXDOMAIN/NODATA from cached NSEC records with wildcard synthesis (RFC 8198)
- **DNS-over-TLS** — opportunistic encryption to authoritatives (RFC 9539) with background probing and connection pooling
- **Full recursive resolution** from root hints with QNAME minimization
- **TCP connection pooling** for upstream queries (RFC 7766)
- **In-memory RRset cache** with SIEVE eviction, RFC 2308 negative caching, prefetch, serve-stale (RFC 8767)
- **Thompson Sampling** nameserver selection (per-zone, discounted)
- **Query deduplication** across workers (singleflight)
- **Multi-threaded server** with `SO_REUSEPORT`, per-query memory cap
- UDP and TCP transport with EDNS0
- Forwarding mode as an alternative to recursion

## Building

Requires Zig 0.16 and a Linux kernel with io_uring support.

```
zig build
zig build test
```

## Usage

Resolve a name recursively (the default):

```
hark query example.com AAAA
hark query --dnssec example.com
hark query --opportunistic example.com
```

Forward to an upstream resolver instead:

```
hark query --forward example.com
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
workers = 4
resolution-threads = 4      # pool threads per worker for concurrent resolution

[resolver]
mode = "recursive"          # or "forward"
dnssec = true
qname-minimization = true
opportunistic = true        # RFC 9539 encrypted transport to authoritatives
stagger-ms = 150             # staggered NS racing delay (0 to disable)

[cache]
prefetch = true
serve-stale-ttl = 3600      # seconds to serve expired entries (RFC 8767)
min-ttl = 300                # floor for aggressive CDN TTLs

[logging]
queries = true
```

All fields are optional — defaults are localhost:53, recursive mode, DNSSEC off, workers = CPU count, 4 resolution threads per worker.

## Architecture

```
              ┌───────────────────────────┐
 clients ───► │  Server (io_uring accept) │
              └─────────────┬─────────────┘
                            │ work queue
              ┌─────────────▼─────────────┐
              │   Resolution Pool         │
              │   (blocking sockets)      │
              │                           │
              │   Deduplication           │
              │   Cache lookup (RwLock)   │
              │   QNAME minimization      │
              │   Staggered NS racing     │
              │   Recursive resolution    │
              │   DNSSEC validation       │
              │   Prefetch                │
              │                           │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │   Transport               │
              │   UDP (connected sockets) │
              │   TCP fallback            │
              │   DoT / RFC 9539          │
              │   TLS connection pool     │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │   Wire Format (dns.zig)   │
              └───────────────────────────┘
```

## Design

- **Linux-first** — io_uring for client I/O, blocking sockets for upstream queries. Portability is not a goal.
- **Zero dependencies** — stdlib only. No vendored C, no package manager.
- **Tested** — fuzzed parsers, integration tests against live DNS, leak detection via `std.testing.allocator`.
