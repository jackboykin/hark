# hark

[![Zig](https://img.shields.io/badge/Zig-0.17_nightly-f7a41d?logo=zig&logoColor=white)](https://ziglang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-333)

hark is a validating, recursive, caching DNS resolver written in Zig.
The core is small and Linux-first: io_uring drives client I/O while a per-worker
thread pool fans out upstream queries on blocking sockets, behind a multi-threaded
`SO_REUSEPORT` server.

Queries use QNAME minimization and 0x20 case randomization. DNSSEC answers are
validated before they reach the cache, and queries to authoritative servers can
be encrypted opportunistically via DNS-over-TLS with pooled connections. Answers
from public zones are scrubbed of private, loopback, and link-local addresses —
DNS rebinding protection, on by default.

The cache does aggressive NSEC negative caching, prefetch, and serve-stale.
Nameserver selection races candidates and learns per-zone with Thompson sampling,
and identical in-flight queries are deduplicated across workers.

## Building

Requires a Zig 0.17 nightly and Linux 6.1+ (io_uring buffer rings + DEFER_TASKRUN).

```console
zig build
zig build test
zig build bench                                # microbenchmarks; ReleaseFast
zig build bench -- cache_hit                   # filter to matching names
zig build -Doptimize=ReleaseSafe -Dcpu=native  # host-tuned release
```

The binary is written to `zig-out/bin/hark`. `zig build test` covers the Zig
unit and fuzz tests. The Python integration
harness (scripted responder, RPL replay) lives under `test/`; a provided
`shell.nix` supplies the toolchain: `cd test && nix-shell --run pytest`.

## Running

hark runs as a server over UDP and TCP. With no config it listens on
`127.0.0.1:53` and `[::1]:53`; pass `--config` to change ports, cache sizes, or
anything else (see [Configuration](#configuration)):

```console
sudo hark serve                            # built-in defaults
hark serve --config /etc/hark/hark.toml    # custom config
```

Point a stub resolver at it with `nameserver 127.0.0.1` in `/etc/resolv.conf`.

Binding a non-loopback address requires an explicit `allow-from` allowlist — hark
refuses to start as an open resolver otherwise (BCP 140) — and can drop to a
configured `user`/`group` (numeric uid/gid) after binding privileged ports.

For debugging, `hark query` resolves a single name from the command line and
`hark dump` decodes a raw packet on stdin:

```console
hark query example.com AAAA --dnssec
hark dump < packet.bin
```

## Configuration

Every key is optional, and every value shown *is* its default, so this snippet
is a no-op — set only what you want to change.

```toml
[server]
listen = ["127.0.0.1:53", "[::1]:53"]
allow-from = []               # client CIDR allowlist; empty = allow all
workers = 2                   # raise for high QPS
resolution-threads = 4        # upstream query threads per worker
max-udp-payload = 1232        # advertised EDNS0 buffer size
minimal-responses = true      # strip non-load-bearing authority/additional RRs

[resolver]
dnssec = true
qname-minimization = true
case-randomization = true     # 0x20 query-name casing
opportunistic = false         # encrypt to authoritatives when possible
stagger-ms = 150              # nameserver racing delay; 0 disables
query-memory-limit = 1048576  # per-resolution memory cap, bytes

[rebinding]
enabled = true                # scrub private addresses from public-zone answers
allow-zones = []              # owner names exempt from scrubbing (split-horizon)
extra-block = []              # additional CIDRs to scrub
extra-allow = []              # CIDRs to exempt from scrubbing

[cache]
size = 16777216               # answer cache, bytes
entries = 10000               # answer cache, max entries
key-cache-size = 4194304      # DNSSEC key cache, bytes
key-cache-entries = 2000      # DNSSEC key cache, max entries
prefetch = false              # refresh entries before they expire
prefetch-cousin = true        # fetch the matching A/AAAA alongside
serve-stale-ttl = 0           # serve expired answers for N seconds
min-ttl = 0                   # floor for very short TTLs

[logging]
queries = false               # log every query
```

## Design

- **Linux-first** — io_uring for client I/O, blocking sockets for upstream queries. Bad portability.
- **Vendor-minimal** — stdlib first; one vendored Zig library for DoT (see [Credits](#credits)). No package manager, no fetched deps, no vendored C.
- **Tested** — a fuzzed message parser, a hermetic integration harness (scripted responder, RPL scenario replay over Unbound's iterator corpus with every divergence documented), and leak detection via `std.testing.allocator`.

## Credits

DoT uses [ianic/tls.zig](https://github.com/ianic/tls.zig) (MIT, Igor Anić),
vendored under `src/vendor/tls-ianic/`. See that directory's `PATCHES.md`
for the pinned commit, local patch, and refresh procedure.
