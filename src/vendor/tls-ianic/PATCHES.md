# Local patches against ianic/tls.zig

Upstream: https://github.com/ianic/tls.zig
Pinned commit: `d633a0f276294f84836ab9a81ba79b805790b2c8`

The SNI guard below is the **only** semantic delta against this pin. The tree
is additionally `zig fmt`-normalized for our nightly (mechanical builtin
renames, e.g. `@enumFromInt`→`@fromBackingInt`); to verify the delta, run the
same `zig fmt` over the upstream clone first, then
`diff -ru <upstream-src> src/vendor/tls-ianic` must show exactly one hunk.

## SNI: skip extension when host is empty

`handshake_client.zig` writes the SNI extension unconditionally, producing a
malformed zero-length `server_name` on the wire when `opt.host = ""`. RFC 6066
§3 requires a non-empty `HostName`, and RFC 9539 §4.6.3.3 says clients
SHOULD NOT send SNI in opportunistic mode (which is exactly the case where we
need an empty host).

Patch: guard the call.

```diff
-        try w.serverName(opt.host);
+        // hark patch: skip SNI when host is empty (RFC 9539 opportunistic mode).
+        // Upstream writes a malformed zero-length SNI extension otherwise.
+        if (opt.host.len > 0) try w.serverName(opt.host);
```

Upstream tracking: TODO file an issue/PR.

## Refresh procedure

```
git clone https://github.com/ianic/tls.zig /tmp/tls-ianic
rsync -a --delete --exclude LICENSE.tls-ianic --exclude PATCHES.md \
    /tmp/tls-ianic/src/ src/vendor/tls-ianic/
cp /tmp/tls-ianic/LICENSE src/vendor/tls-ianic/LICENSE.tls-ianic
# positive control: `zig build test` here must fail EXACTLY the SNI guard test
# re-apply the patches above (and update the pinned commit at the top)
zig fmt src/vendor/tls-ianic/
zig build test          # quiet on success; run the test binary directly to
                        # confirm the live 1.1.1.1:853 tests RAN (build runner
                        # may skip them; direct run should show 1 skip max)
```

Note: `testdata/` (and `rsa/testdata/`) is included even though it only feeds
upstream's own test blocks. Zig eagerly resolves top-level `@import`
declarations regardless of whether they're referenced, so dropping the
directory breaks compilation. At ~60 KB it isn't worth patching out.

## Refresh checklist (security properties hark relies on)

When pulling a newer upstream, confirm each item still holds before merging.
"Confirm" usually means a one-line grep or running the named test.

- **Hostname verification fires when `host.len > 0` and `insecure_skip_verify
  = false`.** Currently at `handshake_common.zig:358-359`. Dormant property:
  hark runs opportunistic-only today (`8613210` dropped authenticated DoT and
  its mismatch test), but this must hold before any ADoT revival. Confirm by
  grep — no in-tree test covers it.
- **SNI extension is elided when `host.len == 0`.** This is our patch above.
  Test: `ianic SNI patch: host="" elides server_name extension`.
- **ALPN echo can be inspected post-handshake via `Connection.alpn_protocol`.**
  hark rejects non-`"dot"` echoes; if upstream changes the field name or
  semantics, the ALPN-mismatch guard at `tls_transport.zig` silently no-ops.
  Since upstream `47c402a` the slice aliases the caller's `alpn_protocols`
  entry (before that it dangled into the handshake's stack frame — one of the
  two fixes that motivated the `d633a0f` refresh, along with `106d10b`'s CBC
  padding `u8` overflow, remotely reachable via a delegation-chosen DoT peer).
- **`Connection.close()` writes a `close_notify` alert and flushes.** Pool
  cleanup in `connection_pool.zig` calls this; if upstream makes `close` a
  no-op or removes the flush, we leak un-acked plaintext on tear-down.
- **`Connection.writeAll` writes one TLS record per call.** `queryOnConnection`
  stages length+query into one buffer expecting a single record + syscall;
  if upstream introduces internal chunking the perf assumption breaks but
  correctness holds.
- **Client cert auth is not required.** hark passes `auth = null`; if upstream
  ever makes that mandatory, all DoT handshakes break.
- **Cipher-suite / named-group defaults still include TLS 1.3 AEAD suites
  (AES-128/256-GCM, ChaCha20-Poly1305) and X25519 / secp256r1.** hark relies
  on ianic's defaults; downgrade by upstream would silently weaken security.

`zig build test` covers the regression-testable items (1, 2). The rest are
contract checks — read the relevant lines or run a real DoT query against
1.1.1.1 with `--dot --dot-host one.one.one.one` to confirm end-to-end.
