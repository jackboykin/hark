# Local patches against ianic/tls.zig

Upstream: https://github.com/ianic/tls.zig
Pinned commit: `5452bafc98d23e304209cb24d81fd2d19434e52d`

The SNI guard below is the **only** local delta against this pin — confirm with
`diff -ru <upstream-src> src/vendor/tls-ianic` after a refresh. Zig 0.17
compatibility (`**`→`@splat`) is upstream-native as of this pin, so no local
0.17 port is carried.

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
rsync -a /tmp/tls-ianic/src/ src/vendor/tls-ianic/
cp /tmp/tls-ianic/LICENSE src/vendor/tls-ianic/LICENSE.tls-ianic
# re-apply the patches above (and update the pinned commit at the top)
zig build test
```

Note: `testdata/` (and `rsa/testdata/`) is included even though it only feeds
upstream's own test blocks. Zig eagerly resolves top-level `@import`
declarations regardless of whether they're referenced, so dropping the
directory breaks compilation. At ~60 KB it isn't worth patching out.

## Refresh checklist (security properties hark relies on)

When pulling a newer upstream, confirm each item still holds before merging.
"Confirm" usually means a one-line grep or running the named test.

- **Hostname verification fires when `host.len > 0` and `insecure_skip_verify
  = false`.** Currently at `handshake_common.zig:342-343`. Without this, a
  cert from any trusted CA would be accepted regardless of the SNI name.
  Test: `TlsTransport authenticated mode rejects hostname mismatch`.
- **SNI extension is elided when `host.len == 0`.** This is our patch above.
  Test: `ianic SNI patch: host="" elides server_name extension`.
- **ALPN echo can be inspected post-handshake via `Connection.alpn_protocol`.**
  hark rejects non-`"dot"` echoes; if upstream changes the field name or
  semantics, the ALPN-mismatch guard at `tls_transport.zig` silently no-ops.
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
