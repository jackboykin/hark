# hark

hark is a fast, validating, recursive DNS resolver

Things:
- Opportunistic encryption over TLS and QUIC
- Extreme memory efficiency and discipline
- Post-quantum DNSSEC with downgrade refusal
- One-shot TCP for zones signed with large algorithms
- Hedged queries across nameservers
- Deterministic simulation testing under seeded chaos
- Zero dependencies

## Building

Requires Zig 0.17 and Linux 6.1+. `nix develop` gives Zig 0.17 and the Go the live harness runs on.

```console
zig build
zig build test
zig build -Doptimize=ReleaseSafe
```

Binary at `zig-out/bin/hark`. Live harness under `test/`: `nix develop -c sh -c 'cd test && go test ./...'`.

## Running

```console
sudo hark serve                            # built-in defaults
hark serve --config /etc/hark/hark.toml    # custom config
```

hark primarily runs as a server. By default it listens on `127.0.0.1:53` and `[::1]:53`. Only `clients` are answered, loopback by default. See the example config [`hark.toml.example`](hark.toml.example) to tune any value yourself.
