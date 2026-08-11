# hark

hark is a recursive DNS resolver. Small and Linux-first. io_uring for client I/O.

Many standard DNS features are present, like QNAME minimization, 0x20 case randomization, DNSSEC, and negative caching. hark also has less common features such as opportunistic encryption to authoritatives over TLS and rebind protection.

## Building

Requires Zig 0.17 nightly and Linux 6.1+.

```console
zig build
zig build test
zig build -Doptimize=ReleaseSafe
```

Binary at `zig-out/bin/hark`. Python test harness under `test/` alongside a `shell.nix`: `cd test && nix-shell --run pytest`.

## Running

```console
sudo hark serve                            # built-in defaults
hark serve --config /etc/hark/hark.toml    # custom config
```

hark primarily runs as a server. By default it listens on `127.0.0.1:53` and `[::1]:53`. Binding a non-loopback address requires an explicit `allow-from` allowlist in the config. See the example config [`hark.toml.example`](hark.toml.example) to tune any value yourself.

For debugging:

```console
hark query example.com AAAA --dnssec       # resolve one name
hark dump < packet.bin                     # decode a raw packet
```

## Credits

DoT uses [ianic/tls.zig](https://github.com/ianic/tls.zig) (MIT, Igor Anić),
vendored under `src/vendor/tls-ianic/`.
