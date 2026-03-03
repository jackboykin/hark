# hark — Recursive DNS Resolver Project Plan

## Philosophy

- **Usable tool**: Correct and robust enough to run on your own machines. Not a toy, not enterprise-grade.
- **RFC-driven**: Build directly from the RFCs. Write our own solutions. Reference unbound only when stuck.
- **Linux-first**: io_uring for I/O. Portability is not a goal.
- **Dependency-minimal**: Zero deps preferred. Stdlib first, local patches second, vendor third, external dep last resort.
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
    clients ───►  │    Server (UDP/TCP)      │  M10 ✅
                  │    DoT / DoH listeners   │  M9 ✅
                  └────────────┬─────────────┘
                               │
                  ┌────────────▼─────────────┐
                  │    Query Pipeline         │
                  │  ┌─────────────────────┐  │
                  │  │ Cache lookup         │  │  M4 ✅
                  │  │ QNAME minimization   │  │  M7 ✅
                  │  │ Recursive resolution │  │  M3 ✅
                  │  │ Forwarding fallback  │  │  M3 ✅
                  │  │ DNSSEC validation    │  │  M8 ✅
                  │  └─────────────────────┘  │
                  └────────────┬──────────────┘
                               │
                  ┌────────────▼─────────────┐
                  │    Transport              │
                  │  UDP / io_uring           │  M2 ✅
                  │  TCP fallback             │  M5 ✅
                  │  EDNS0 payload sizing     │  M6 ✅
                  │  DoT / RFC 9539           │  M9 ✅
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

### M6: EDNS0 ✅
- OPT pseudo-record (type 41) in Message, parse/serialize/pretty-print
- EdnsConfig in QueryOptions, 1232-byte UDP payload (IPv6-safe per DNS Flag Day 2020)
- DO bit support (prerequisite for DNSSEC)
- Both resolvers send OPT by default

### M7: QNAME Minimization ✅
- Send only the necessary labels (zone cut + 1) to each authoritative
- Relaxed NXDOMAIN mode (fall back to full QNAME on NXDOMAIN)

### M8: DNSSEC Validation ✅
- Chain-of-trust validation (DNSKEY → DS chain), negative proofs (NSEC/NSEC3)
- All 5 production algorithms: RSA-SHA256 (8), RSA-SHA512 (10), ECDSA P-256 (13),
  P-384 (14), Ed25519 (15). RSA via `std.crypto.Certificate.rsa` (internal but accessible).
- Bogus vs. insecure vs. secure classification
- Policy: unsupported algorithms (Ed448, legacy SHA1) → bogus → ServFail (safe default)

### M9: DNS-over-TLS + RFC 9539 ✅
- RFCs 7858 (DoT), 9539 (opportunistic recursive-to-authoritative encryption)
- Connection pooling with ALPN negotiation (`"dot"` token)
- Per-IP encrypted-capability state (3-day success cache, 1-day failure damping)
- Graceful fallback to cleartext Do53 on failure (RFC 9539)
- Stdlib TLS 1.3 client with cherry-picked ALPN from Zig PR #24983

### M10: Server Mode + Configuration ✅
- UDP + TCP listeners on configurable port (default 53)
- TOML configuration file (upstream servers, forwarding mode, cache size, listen addresses)
- Thread pool with `SO_REUSEPORT` and shared mutex-protected cache
- `signalfd`-based graceful shutdown
- RFC 1035/6891 compliant response truncation with EDNS support

## Milestone Roadmap

### M11: DNSSEC Positive-Answer Validation
**RFCs**: 4035 §5, 6840 (clarifications)
**Goal**: Validate RRSIG chains on positive answers (A, AAAA, MX, etc.), not just negative proofs.

- Full chain-of-trust: root DNSKEY → DS → zone DNSKEY → RRSIG → RRset
- Call `validateDnskeyRrset` (already implemented, never called) on delegation trust path
- Validate RRSIGs on answer RRsets using the authenticated zone DNSKEY
- Wildcard answer validation (NSEC/NSEC3 proof of non-existence for the exact name)
- CNAME chain validation (each CNAME target's zone must be validated)
- Secure/insecure/bogus classification on positive answers (currently only on negatives)
- SERVFAIL on bogus positive answers when DNSSEC is enabled
- Update `--dnssec` flag to cover both positive and negative validation

## Key Architectural Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| I/O model | io_uring via thin owned `EventLoop` | Modern, fast, no external deps. ~200-300 line abstraction. |
| Allocator strategy | Arena per query | Each query gets an arena, freed on completion. No per-struct deinit. |
| Cache | In-memory, no persistence | Cleanest approach. Not worth the complexity for a usable tool. |
| TLS | Stdlib first, ALPN patch, vendor iotic as fallback | Zero deps preferred. Stdlib TLS 1.3 works; ALPN needed for RFC 9539. |
| DNSSEC RSA | `std.crypto.Certificate.rsa` (internal) | Works. All 5 production algorithms implemented. |
| Config format | TOML | Minimal subset parser, one file per concern. |
| Concurrency | Thread pool + `SO_REUSEPORT` + shared mutex cache | Simple and correct. Sharded/lock-free deferred. |
| File structure | One file per concern | `dns.zig`, `recursive.zig`, `cache.zig`, `transport.zig`, `event_loop.zig`, etc. |
| Testing | RFC test vectors + real DNS + fuzz | Fuzz all parsers. Integration test against live DNS for resolution. |

## Development Methodology

- **One milestone at a time**: Don't build ahead. Each milestone is usable + tested before moving on.
- **RFC as source of truth**: Read the relevant RFC section before implementing. Cite section numbers in code comments where non-obvious.
- **Fuzz everything that touches bytes**: Parsers, deserializers, wire format handling.
- **`std.testing.allocator` everywhere**: Catch leaks in every test.
- **Real-world validation**: After each milestone, test against live DNS infrastructure.
