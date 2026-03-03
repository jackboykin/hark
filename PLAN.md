# hark — Recursive DNS Resolver Project Plan

## Philosophy

- **Usable tool**: Correct and robust enough to run on your own machines. Not a toy, not enterprise-grade.
- **RFC-driven**: Build directly from the RFCs. Write our own solutions. Reference unbound only when stuck.
- **Linux-first**: io_uring for I/O. Portability is not a goal.
- **Dependency-minimal**: Zig stdlib only. No external packages.
- **Test everything**: Fuzz parsers, integration-test against real DNS, use `std.testing.allocator` to catch leaks.

## Design Anti-Patterns (Lessons from Hickory)

These are concrete bugs found while contributing to Hickory DNS (hickory-dns/hickory-dns#3477)
that inform hark's design:

- **Never fabricate protocol states from application state.** Hickory's answer filter
  silently converted an empty answer set into a synthetic NXDOMAIN response code. This
  poisoned the negative cache with a 1-hour NXDOMAIN for records that actually existed
  (NOERROR). Negative caching is dangerous — be very conservative about NXDOMAIN generation.
- **Track zone cuts explicitly.** Hickory used `zone.base_name()` as the bailiwick boundary,
  but this silently drifted from the actual zone cut in flat NS structures (e.g.
  `r06.twtrdns.net`). The bailiwick filter then dropped legitimate SOA records, triggering
  a bogus RFC 8020 NXDOMAIN synthesis. Zone cut tracking must be an explicit, separate value
  from the query name being resolved.
- **Keep resolution state deterministic and traceable.** Hickory's cache poisoning bug only
  fired when the async connection pool happened to return `Ok` instead of `Err` — depending
  on which nameserver the Tokio scheduler reached first. Hiding resolution state behind an
  opaque async runtime made this non-deterministic and nearly impossible to reproduce. hark's
  io_uring event loop gives linear, inspectable control flow by design.

## Architecture Overview

```
                  ┌─────────────────────────┐
    clients ───►  │    Server (UDP/TCP)      │  M10
                  │    DoT / DoH listeners   │  M9
                  └────────────┬─────────────┘
                               │
                  ┌────────────▼─────────────┐
                  │    Query Pipeline         │
                  │  ┌─────────────────────┐  │
                  │  │ Cache lookup         │  │  M4 ✅
                  │  │ QNAME minimization   │  │  M7
                  │  │ Recursive resolution │  │  M3 ✅
                  │  │ Forwarding fallback  │  │  M3 ✅
                  │  │ DNSSEC validation    │  │  M8
                  │  └─────────────────────┘  │
                  └────────────┬──────────────┘
                               │
                  ┌────────────▼─────────────┐
                  │    Transport              │
                  │  UDP / io_uring           │  M2 ✅
                  │  TCP fallback             │  M5 ✅
                  │  EDNS0 payload sizing     │  M6
                  └──────────────────────────┘
                               │
                  ┌────────────▼─────────────┐
                  │    Wire Format (dns.zig)  │  M1 ✅
                  └──────────────────────────┘
```

## Completed

### M1: DNS Wire Format Parser + Serializer ✅
- RFC 1035 §4 wire format: Header, Name (with compression), Question, RR, RData
- Record types: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, unknown fallback
- Serializer (no compression on write)
- 17 tests including fuzz
- CLI packet dumper (`stdin | hark`)

### M2: UDP Transport + io_uring Event Loop ✅
- Thin `EventLoop` abstraction over `std.os.linux.IoUring`
  - Submit send/recv operations, get callbacks via user_data tagging
  - Timeout support (retransmit after N ms, abandon after M ms)
  - Socket pool management
- `UdpTransport` struct: send query, await response, handle retransmits
- Forwarding mode as the first working path (send to upstream like 8.8.8.8)
- Integration test: resolve a real domain via forwarding

### M3: Recursive Resolution ✅
- Root hints (hardcoded root server IPs, refreshable via priming query)
- Resolution state machine: track delegation chain, follow NS records
- Glue record handling (use additional section A/AAAA for NS targets)
- CNAME following (restart resolution for CNAME targets)
- Referral loop detection
- Bailiwick checking (ignore out-of-bailiwick glue)
- Glueless NS resolution via parent-zone bailiwick
- Forwarding fallback mode (configurable: upstream server list)
- Test: resolve a multi-delegation domain from root

### M3c: CLI Integration ✅
- Recursive resolution as default mode, `--forward` flag for forwarding

### M4: In-Memory Cache ✅
- RRset cache keyed by (name, type, class) with absolute TTL expiry
- CountingAllocator for deterministic 16MB byte cap
- Deep-copy ownership model (cache owns all memory)
- RFC 2308 negative caching (authoritative-only NXDOMAIN/NODATA)
- Six cache touchpoints in recursive resolver
- Closest cached delegation (skip root/TLD for known zones)

### M5: TCP Transport ✅
- EventLoop gains connect/tcpSend/tcpRecv io_uring operations
- TcpTransport: per-query TCP with DNS length-prefix framing, 3-phase state machine
- TC-bit fallback in both ForwardingResolver and RecursiveResolver
- Per-query TCP connections (connection reuse deferred)

## Milestone Roadmap

### M6: EDNS0
**RFCs**: 6891 (EDNS0)
**Goal**: Support larger UDP payloads and EDNS option negotiation.

- OPT pseudo-record parsing + serialization in dns.zig
- Advertise 1232-byte UDP buffer size (IPv6-safe per DNS Flag Day 2020)
- Parse EDNS options from responses
- DO bit support (prerequisite for DNSSEC)

### M7: QNAME Minimization
**RFCs**: 9156 (QNAME minimization)
**Goal**: Minimize information leaked to each nameserver.

- Send only the necessary labels (zone cut + 1) to each authoritative
- Fall back to full QNAME on NXDOMAIN (strict vs relaxed mode)
- Integrate into the resolution state machine from M3

### M8: DNSSEC Validation
**RFCs**: 4033-4035 (DNSSEC), 5155 (NSEC3)
**Goal**: Full chain-of-trust validation.

- New record types: DNSKEY, RRSIG, DS, NSEC, NSEC3
- Crypto algorithms:
  - ECDSA P-256/P-384 (algorithms 13, 14) — available in `std.crypto`
  - Ed25519 (algorithm 15) — available in `std.crypto`
  - RSA-SHA256/SHA512 (algorithms 8, 10) — **not publicly exposed** in Zig 0.15
    (`std.crypto.Certificate` has an internal implementation; Zig issue #19776
    tracks a public RSA module). Options: wrap internal impl, implement minimal
    RSA verifier (modexp + PKCS#1 v1.5 padding), or defer RSA until stdlib ships it.
- Trust anchor: hardcoded root KSK (RFC 5011 rollover as stretch)
- Validation pipeline: verify RRSIG covers RRset, walk DS→DNSKEY chain
- Authenticated denial of existence (NSEC/NSEC3 proof verification)
- NSEC3 aggressive negative caching (RFC 8198)
- Bogus vs. insecure vs. secure classification

### M9: DNS-over-TLS / DNS-over-HTTPS
**RFCs**: 7858 (DoT), 8484 (DoH)
**Goal**: Encrypted transport for client-facing and upstream connections.

*Note: As of Zig 0.15, `std.crypto.tls` has gaps — missing ALPN, incomplete
TLS 1.2, real-world compatibility issues with some servers. Community
alternatives exist (iotic/tls.zig, shiguredo/tls13-zig) but add external deps.
Revisit stdlib maturity when we reach this milestone.*

- DoT: TLS wrapper over TCP framing from M5
- DoH: HTTP/2 framing (or HTTP/1.1 with content-type application/dns-message)
- Certificate validation (system trust store or bundled roots)
- Upstream DoT/DoH (encrypted forwarding)
- TLS approach TBD — revisit when we reach this milestone

### M10: Server Mode + Configuration
**Goal**: Listen for client queries, configurable operation.

- UDP + TCP listeners on configurable port (default 53)
- Client query dispatch to resolver pipeline
- Configuration file (TOML or simple custom format)
  - Upstream servers, forwarding mode toggle, cache size, listen addresses
- Graceful shutdown
- Logging / metrics (optional)

**Concurrency architecture notes:**
- Thread-per-core with shared-nothing sharded cache (no mutexes). Each core owns
  exclusive cache shards, determined by hashing the query name.
- `SO_REUSEPORT` + eBPF packet steering: attach a small eBPF program to the socket that
  parses incoming UDP query names, hashes them, and steers packets to the io_uring instance
  on the core that owns that shard. Lock-free by construction.
- If shared cache is needed instead, use epoch-based / RCU memory reclamation: readers never
  lock, writers build new entries and atomically swap pointers, retired memory cleaned up at
  event loop epoch boundaries.

## Key Architectural Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| I/O model | io_uring via thin owned `EventLoop` | Modern, fast, no external deps. ~200-300 line abstraction. |
| Allocator strategy | Arena per query | Each query gets an arena, freed on completion. No per-struct deinit. |
| Cache | In-memory, no persistence | Cleanest approach. Not worth the complexity for a usable tool. |
| TLS | `std.crypto.tls` (stdlib), revisit at M9 | Zero deps goal, but stdlib has gaps. May need community lib or defer. |
| DNSSEC RSA | TBD at M8 | stdlib lacks public RSA. Wrap internal impl, write minimal verifier, or wait. |
| Config format | Defer decision | Not needed until M10. |
| File structure | One file per concern | `dns.zig`, `recursive.zig`, `cache.zig`, `transport.zig`, `event_loop.zig`, etc. |
| Testing | RFC test vectors + real DNS + fuzz | Fuzz all parsers. Integration test against live DNS for resolution. |

## Development Methodology

- **One milestone at a time**: Don't build ahead. Each milestone is usable + tested before moving on.
- **RFC as source of truth**: Read the relevant RFC section before implementing. Cite section numbers in code comments where non-obvious.
- **Fuzz everything that touches bytes**: Parsers, deserializers, wire format handling.
- **`std.testing.allocator` everywhere**: Catch leaks in every test.
- **Real-world validation**: After each milestone, test against live DNS infrastructure.
