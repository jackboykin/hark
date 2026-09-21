# hark

hark is a modern recursive resolver.

Distinctive features:
- Post-quantum DNSSEC with downgrade refusal (ML-DSA-44)
- One-shot TCP for zones signed with large algorithms
- Hedged queries across nameservers

## Building

Requires Zig 0.17 nightly and Linux 6.1+. The flake packages master as `packages.default`, and `nix develop` gives the pinned Zig nightly and the test harness's Python.

```console
zig build
zig build test
zig build -Doptimize=ReleaseSafe
```

Binary at `zig-out/bin/hark`. Python test harness under `test/`: `nix develop -c sh -c 'cd test && pytest'`.

## Running

```console
sudo hark serve                            # built-in defaults
hark serve --config /etc/hark/hark.toml    # custom config
```

hark primarily runs as a server. By default it listens on `127.0.0.1:53` and `[::1]:53`. Binding a non-loopback address requires an explicit `allow-from` allowlist in the config. See the example config [`hark.toml.example`](hark.toml.example) to tune any value yourself.
