# hark

A validating, recursive, caching DNS resolver built from scratch in Zig.
Runs on Linux with io_uring. Zero external dependencies.

## Features

- Full recursive resolution from the root, with QNAME minimization
- DNSSEC validation (RSA-SHA256/512, ECDSA P-256/P-384, Ed25519)
- In-memory RRset cache with RFC 2308 negative caching
- DNS-over-TLS with opportunistic encryption (RFC 9539)
- UDP and TCP transport with EDNS0
- Forwarding mode as an alternative to recursion
- Multi-threaded server mode with `SO_REUSEPORT`
- RTT-based nameserver selection

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
```

Forward to an upstream resolver instead:

```
hark query --forward example.com
```

Run as a server (UDP + TCP, TOML config):

```
hark serve --config /etc/hark/config.toml
```

Dump a raw DNS packet from stdin:

```
hark dump < packet.bin
```

## Architecture

```
              ┌───────────────────────────┐
 clients ───► │   Server (UDP/TCP)        │
              │   DoT listeners           │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │   Query Pipeline          │
              │                           │
              │   Cache lookup            │
              │   QNAME minimization      │
              │   Recursive resolution    │
              │   Forwarding fallback     │
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
