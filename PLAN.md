# hark — Recursive DNS Resolver Project Plan

## Philosophy

- **Usable tool**: Correct and robust enough to run on your own machines. Not a toy, not enterprise-grade.
- **RFC-driven**: Build directly from the RFCs. Write our own solutions. Reference unbound only when stuck.
- **Linux-first**: io_uring for I/O. Portability is not a goal.
- **Dependency-minimal**: Zig stdlib only. No external packages.
- **Test everything**: Fuzz parsers, integration-test against real DNS, use `std.testing.allocator` to catch leaks.

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
                  │  │ Cache lookup         │  │  M4
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
                  │  TCP fallback             │  M5
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

## Milestone Roadmap

### M3c: CLI Integration
**Goal**: Wire up RecursiveResolver as the default resolution mode.

- `hark query <domain>` uses recursive resolution by default
- `--forward` flag falls back to forwarding resolver
- First moment hark is a genuinely usable tool

### M4: In-Memory Cache
**RFCs**: 1035 §7 (caching), 2308 (negative caching)
**Goal**: Cache responses, respect TTLs, serve from cache.

- Cache keyed by (name, type, class) → RRset
- TTL countdown (store absolute expiry time, not raw TTL)
- Negative caching (NXDOMAIN, NODATA per RFC 2308)
- Cache eviction: simple LRU or random eviction when at capacity
- Serve stale with background refresh (optional, RFC 8767)
- No disk persistence — in-memory only, clean restart

### M5: TCP Transport
**RFCs**: 7766 (DNS over TCP), 5966
**Goal**: TCP fallback for truncated and large responses.

*Rationale for moving ahead of EDNS0/DNSSEC: Research shows 3-7% of real UDP
responses are truncated (SIDN Labs/APNIC 2020-2024). DNS Flag Day 2025 and
RFC 9609 treat TCP as non-optional. EDNS0 and DNSSEC both produce responses
that frequently exceed UDP limits, so TCP is a prerequisite for both.*

- TCP connection management in the event loop (io_uring connect/read/write)
- Automatic fallback when TC bit is set in UDP response
- Length-prefixed framing (2-byte length + message)
- Connection reuse / pooling to authoritative servers
- Idle timeout handling

### M6: EDNS0
**RFCs**: 6891 (EDNS0)
**Goal**: Support larger UDP payloads and EDNS option negotiation.

*Rationale for placing after TCP: EDNS0 advertises larger buffer sizes but
truncation still occurs. TCP fallback (M5) must exist before EDNS0 can work
correctly. EDNS0's DO bit is also required to request DNSSEC records.*

- OPT pseudo-record parsing + serialization in dns.zig
- Advertise 1232-byte UDP buffer size (IPv6-safe per RFC 8085 guidance)
- Parse EDNS options from responses
- TC fallback to TCP (leverages M5)

### M7: QNAME Minimization
**RFCs**: 9156 (QNAME minimization)
**Goal**: Minimize information leaked to each nameserver.

*Rationale for placing before DNSSEC: Much simpler to implement, provides
immediate privacy benefit, and integrates cleanly into the existing resolution
state machine. No dependency on EDNS0 or TCP.*

- Send only the necessary labels (zone cut + 1) to each authoritative
- Fall back to full QNAME on NXDOMAIN (strict vs relaxed mode)
- Integrate into the resolution state machine from M3

### M8: DNSSEC Validation
**RFCs**: 4033-4035 (DNSSEC), 5155 (NSEC3)
**Goal**: Full chain-of-trust validation.

*Now sits on solid foundations: TCP (M5) handles large signed responses,
EDNS0 (M6) provides the DO bit to request signatures.*

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
alternatives exist (ianic/tls.zig, shiguredo/tls13-zig) but add external deps.
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
