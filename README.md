# hark

A validating, recursive, caching DNS resolver built from scratch in Zig.
Runs on Linux with io_uring. Zero external dependencies.

## Features

- DNS-over-TLS with opportunistic encryption to authoritatives (RFC 9539)
- Background TLS probing with connection pooling
- DNSSEC validation (RSA-SHA1/256/512, ECDSA P-256/P-384, Ed25519)
- Full recursive resolution from the root, with QNAME minimization
- In-memory RRset cache with RFC 2308 negative caching
- Cache prefetch and serve-stale (RFC 8767)
- Query deduplication across workers (singleflight)
- Multi-threaded server mode with `SO_REUSEPORT`
- Thompson Sampling nameserver selection (per-zone, discounted)
- UDP and TCP transport with EDNS0
- Forwarding mode as an alternative to recursion

## Building

Requires Zig 0.15 and a Linux kernel with io_uring support.

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

[resolver]
mode = "recursive"          # or "forward"
dnssec = true
qname-minimization = true
opportunistic = true        # RFC 9539 encrypted transport to authoritatives

[cache]
prefetch = true
serve-stale-ttl = 3600      # seconds to serve expired entries (RFC 8767)
min-ttl = 300                # floor for aggressive CDN TTLs

[logging]
queries = true
```

All fields are optional — defaults are localhost:53, recursive mode, DNSSEC off, workers = CPU count.

## Architecture

```
              ┌───────────────────────────┐
 clients ───► │   Server (UDP/TCP)        │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │   Query Pipeline          │
              │                           │
              │   Deduplication           │
              │   Cache lookup / prefetch │
              │   QNAME minimization      │
              │   Recursive resolution    │
              │   DNSSEC validation       │
              │                           │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │   Transport               │
              │   UDP / io_uring          │
              │   TCP fallback            │
              │   EDNS0 payload sizing    │
              │   DoT / RFC 9539          │
              │   TLS connection pool     │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │   Wire Format (dns.zig)   │
              └───────────────────────────┘
```

## Design

- **Linux-first** — io_uring for all network I/O. Portability is not a goal.
- **Zero dependencies** — stdlib only. No vendored C, no package manager.
- **Tested** — fuzzed parsers, integration tests against live DNS, leak detection via `std.testing.allocator`.
