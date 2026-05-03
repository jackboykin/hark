# Local patches against ianic/tls.zig

Upstream: https://github.com/ianic/tls.zig
Pinned commit: `561cd3e5a88ec430d2021e2da19b6bee667e020d`

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

Note: `testdata/` is included even though it only feeds upstream's own test
blocks. Zig 0.16 eagerly resolves top-level `@import` declarations regardless
of whether they're referenced, so dropping the directory breaks compilation.
At ~60 KB it isn't worth patching out.
