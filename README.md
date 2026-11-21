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

## Running

- **systemd**: `zig build` installs [`hark.service`](systemd/hark.service), which runs hark sandboxed.
- **NixOS**: the flake provides a module that runs the systemd unit. Import it and enable `services.hark`.

hark runs as a server. By default it listens on `127.0.0.1:53` and `[::1]:53`. Only `clients` are answered. See the example config [`hark.toml.example`](hark.toml.example) to tune any value yourself.

```console
hark serve                                 # built-in defaults
hark serve --config /etc/hark/hark.toml    # serve with a custom config
hark check --config /etc/hark/hark.toml    # check that a config is valid
```

## Building

Requires Zig 0.17 and Linux 6.1+. `nix develop` gives Zig 0.17 and the Go the live harness runs on.

```console
zig build -Doptimize=ReleaseSafe
zig build test                                    # unit tests and every scenario replayed
nix develop -c sh -c 'cd test && go test ./...'   # the live harness
```

Binary at `zig-out/bin/hark`.

The bench in `bench/` sets resolvers against each other on loopback. Run it in `nix develop .#bench` on an idle machine, against a release build.
