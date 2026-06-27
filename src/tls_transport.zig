const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Io = std.Io;
const File = Io.File;
const Allocator = mem.Allocator;
const testing = std.testing;
const dns = @import("dns.zig");
const pool_mod = @import("connection_pool.zig");
const ConnectionPool = pool_mod.ConnectionPool(pool_mod.PooledConnection);
const PooledConnection = pool_mod.PooledConnection;
const tls = @import("tls");
const encrypted_ns_mod = @import("encrypted_ns.zig");
const EncryptedNsCache = encrypted_ns_mod.EncryptedNsCache;
const na = @import("net_address.zig");
const AddressKey = na.AddressKey;
const sys = @import("sys.zig");
const monotonic = @import("monotonic.zig");
const log = std.log.scoped(.tls_transport);

/// RFC 9539 §4.4: DoT ALPN identifier ("dot").
const alpn_dot = "dot";

/// RFC 9539 opportunistic DoT transport: encrypts queries to authoritative
/// servers over TLS (ALPN "dot", no SNI, no certificate verification),
/// falling back to Do53 on any failure. Opportunistic is the only mode, so
/// the query methods carry no qualifier.
pub const TlsTransport = struct {
    pub const port: u16 = 853;

    allocator: Allocator,
    io: Io,
    pool: ?*ConnectionPool = null,

    pub fn init(allocator: Allocator, io: Io) TlsTransport {
        return .{ .allocator = allocator, .io = io };
    }

    /// Try a query on a pooled connection for `key`. Returns null if no pool,
    /// no pooled conn available, or the pooled conn failed (and was released).
    fn tryPooledQuery(self: *TlsTransport, key: AddressKey, wire_query: []const u8, response_buf: []u8, deadline_ns: i128) ?[]const u8 {
        const pool = self.pool orelse return null;
        const conn = pool.acquire(key) orelse return null;
        if (queryOnConnection(conn, wire_query, response_buf, deadline_ns)) |data| {
            pool_mod.applyKeepaliveHint(conn, data);
            pool.release(key, conn, true);
            return data;
        } else |_| {
            pool.release(key, conn, false);
            return null;
        }
    }

    /// Allocate a PooledConnection wired to `stream`. Caller must free via
    /// `destroyBroken` / `closeAndDestroy` on any subsequent error.
    ///
    /// `File.Reader`/`File.Writer` (not `Stream.Reader`/`Stream.Writer`)
    /// drive the TLS layer because the File path's `fileReadStreamingPosix`
    /// returns `error.WouldBlock` on `SO_RCVTIMEO`-induced `EAGAIN`, while
    /// `netReadPosix` treats it as a programmer bug. Until stdlib grows
    /// per-call read timeouts on `Stream.Reader`, the File wrapper is the
    /// path that lets the existing kernel-side timeout shape keep working.
    fn newPooledConnection(self: *TlsTransport, stream: Io.net.Stream) !*PooledConnection {
        const conn = try self.allocator.create(PooledConnection);
        const file = File{ .handle = stream.socket.handle, .flags = .{ .nonblocking = false } };
        conn.stream = stream;
        conn.io = self.io;
        conn.last_used = 0;
        conn.query_count = 0;
        conn.max_queries = 200;
        conn.idle_timeout_sec = null;
        conn.net_reader = File.Reader.initStreaming(file, self.io, &conn.net_read_buf);
        conn.net_writer = File.Writer.initStreaming(file, self.io, &conn.net_write_buf);
        return conn;
    }

    /// Run the TLS handshake on `conn` (RFC 9539): no SNI (the
    /// vendored ianic patch elides the extension for host=""), no cert
    /// verification. ALPN advertises "dot" per §4.4. A peer omitting the echo
    /// is tolerated (Cloudflare / Google do this in violation of RFC 7301
    /// §3.2); a non-"dot" echo is rejected — sending a length-prefixed DNS
    /// frame to e.g. an h2 endpoint would corrupt state.
    fn handshake(self: *TlsTransport, conn: *PooledConnection) !void {
        const rng_impl: std.Random.IoSource = .{ .io = self.io };
        conn.tls = tls.client(&conn.net_reader.interface, &conn.net_writer.interface, .{
            .rng = rng_impl.interface(),
            .now = monotonic.wallclockTimestamp(self.io),
            .host = "",
            .root_ca = .empty,
            .insecure_skip_verify = true,
            .alpn_protocols = &.{alpn_dot},
        }) catch |err| {
            log.debug("TLS handshake failed: {s}", .{@errorName(err)});
            return error.TlsHandshakeFailed;
        };
        if (conn.tls.alpn_protocol) |proto| {
            if (!std.mem.eql(u8, proto, alpn_dot)) {
                log.warn("TLS ALPN mismatch: peer echoed {s}", .{proto});
                return error.TlsHandshakeFailed;
            }
        }
    }

    /// Encrypted DoT query. Tries a pooled connection first, pools new
    /// connections on success. `deadline_ns` is an absolute monotonic deadline
    /// bounding both connect and query.
    pub fn query(self: *TlsTransport, wire_query: []const u8, server: na.Address, response_buf: []u8, deadline_ns: i128) ![]const u8 {
        const tls_server = toPort(server, TlsTransport.port);
        const addr_key = AddressKey.fromAddress(tls_server);

        if (self.tryPooledQuery(addr_key, wire_query, response_buf, deadline_ns)) |data| return data;

        // ── New connection ──
        const remaining_ns = deadline_ns - monotonic.nowNs();
        if (remaining_ns <= 0) return error.Timeout;
        const connect_ms: u32 = @intCast(@min(@divFloor(remaining_ns, std.time.ns_per_ms), std.math.maxInt(u32)));
        const stream = try connectTcpBlocking(self.io, tls_server, connect_ms);
        const conn = try self.initConnection(stream);

        const data = queryOnConnection(conn, wire_query, response_buf, deadline_ns) catch |err| {
            conn.destroyBroken(self.allocator);
            return err;
        };

        if (self.pool) |pool| {
            pool_mod.applyKeepaliveHint(conn, data);
            pool.store(addr_key, conn);
        } else {
            conn.closeAndDestroy(self.allocator);
        }

        return data;
    }

    /// Allocate a PooledConnection from a connected stream and perform the
    /// TLS handshake. Takes ownership of `stream`: closes it on any failure.
    fn initConnection(self: *TlsTransport, stream: Io.net.Stream) !*PooledConnection {
        errdefer stream.close(self.io);
        const conn = try self.newPooledConnection(stream);
        errdefer self.allocator.destroy(conn);

        // RFC 9539 §4.6.3.3/4: no SNI, accept any cert.
        try self.handshake(conn);
        return conn;
    }

    /// Open a connected TCP stream for TLS. Same connect-timeout workaround
    /// as `blocking_transport.connectTcp`: open the fd via raw posix to
    /// apply `SO_SNDTIMEO`, then wrap as `Io.net.Stream`. Leaves SNDTIMEO
    /// set because the caller overwrites both directions with the
    /// per-handshake / per-query deadline immediately after. `.address`
    /// follows the same CONTRACT as `blocking_transport.connectTcp`:
    /// zero-init, do not read on client-side streams. `io` is reserved
    /// for the eventual `IpAddress.connect` collapse.
    fn connectTcpBlocking(io: Io, tls_server: na.Address, timeout_ms: u32) !Io.net.Stream {
        _ = io;
        const af: u32 = na.afU32(tls_server);
        const sock_fd = try sys.socket(af, posix.SOCK.STREAM, 0);
        errdefer sys.close(sock_fd);
        sys.setSocketTimeouts(sock_fd, timeout_ms);
        sys.setNoDelay(sock_fd);
        na.connectTo(sock_fd, &tls_server) catch return error.ConnectFailed;
        return .{ .socket = .{ .handle = sock_fd, .address = na.initIp4(.{ 0, 0, 0, 0 }, 0) } };
    }

    /// Fire a background probe for a nameserver. The spawned task does
    /// blocking TCP connect + TLS handshake. On success, the connection
    /// is pooled.
    pub fn probeInBackground(self: *TlsTransport, server: na.Address, enc_ns_cache: *EncryptedNsCache) void {
        const tls_server = toPort(server, TlsTransport.port);
        const addr_key = AddressKey.fromAddress(tls_server);

        if (!enc_ns_cache.probes.tryClaim()) {
            enc_ns_cache.revertProbing(addr_key);
            return;
        }
        // Pass TlsTransport by value: the probe outlives the spawning
        // stack frame (pool / bg-prefetch) that holds the original
        // `*TlsTransport`. Copying snaps the small handle (allocator / io /
        // pool ptr) into the spawned task's args.
        enc_ns_cache.probes.spawn(self.io, probeThread, .{ self.*, tls_server, addr_key, enc_ns_cache }) catch {
            // ConcurrencyUnavailable is transient (spawn pressure), not a
            // protocol failure — revert the .probing claim so the next
            // query can probe again instead of poisoning the entry with
            // `.failed` and skipping DoT for the full damping window.
            enc_ns_cache.revertProbing(addr_key);
            enc_ns_cache.probes.release();
            return;
        };
    }

    fn probeThread(transport: TlsTransport, tls_server: na.Address, addr_key: AddressKey, enc_ns_cache: *EncryptedNsCache) void {
        defer enc_ns_cache.probes.release();
        if (enc_ns_cache.probes.shutting_down.load(.acquire)) {
            enc_ns_cache.revertProbing(addr_key);
            return;
        }

        var self = transport; // value copy owned by this task

        // RFC 9539 §4.3: TCP connect failure is "soft" — could be a
        // transient network blip; retry sooner. TLS handshake failure is
        // "hard" — server reached us but rejected the protocol; damp longer.
        const stream = connectTcpBlocking(self.io, tls_server, 4000) catch {
            enc_ns_cache.setStatus(addr_key, .soft_failed);
            return;
        };

        // ── TLS handshake ──
        const conn = self.initConnection(stream) catch {
            enc_ns_cache.setStatus(addr_key, .failed);
            return;
        };

        // Success — mark capable and pool the connection
        enc_ns_cache.setStatus(addr_key, .capable);
        var addr_buf: [64]u8 = undefined;
        log.info("server {s} supports DoT (RFC 9539)", .{na.format(tls_server, &addr_buf)});
        if (self.pool) |pool| {
            pool.store(addr_key, conn);
        } else {
            conn.closeAndDestroy(self.allocator);
        }
    }
};

/// Return a copy of `addr` with the port overridden.
fn toPort(addr: na.Address, port: u16) na.Address {
    return switch (addr) {
        .ip4 => |v4| na.initIp4(v4.bytes, port),
        .ip6 => |v6| na.initIp6(v6.bytes, port, v6.flow, v6.interface.index),
    };
}

/// Send a length-prefixed DNS query over an established TLS connection
/// and read the length-prefixed response.
///
/// `deadline_ns` tightens the kernel SO_SNDTIMEO/SO_RCVTIMEO once before each
/// direction. SO timeouts are per-syscall, so a slow-trickle peer that drips
/// data in tiny chunks could in principle exceed the deadline; the bound
/// achieved here is "no indefinite stall." Acceptable because upstream TLS
/// peers are chosen authoritative/recursive servers — not arbitrary peers.
/// True per-payload bounding would require restructuring TLS-layer I/O to
/// expose hooks for per-syscall deadline checks (the TLS layer buffers
/// records, not raw syscalls).
fn queryOnConnection(conn: *PooledConnection, wire_query: []const u8, response_buf: []u8, deadline_ns: i128) ![]const u8 {
    // Stage into a single buffer so the TLS layer emits one record + one
    // syscall per query — two writeAll calls would flush twice (ianic
    // flushes per record).
    var staging: [2 + dns.edns_udp_payload]u8 = undefined;
    const framed = try dns.stageLengthPrefixed(&staging, wire_query);

    const handle = conn.stream.socket.handle;
    try sys.updateTimeout(handle, posix.SO.SNDTIMEO, deadline_ns);
    conn.tls.writeAll(framed) catch return error.TlsSendFailed;

    try sys.updateTimeout(handle, posix.SO.RCVTIMEO, deadline_ns);
    var resp_len_buf: [2]u8 = undefined;
    const n_len = conn.tls.readAtLeast(&resp_len_buf, 2) catch return error.TlsRecvFailed;
    if (n_len < 2) return error.TlsRecvFailed;
    const resp_len = mem.readInt(u16, &resp_len_buf, .big);

    if (resp_len == 0 or resp_len > response_buf.len) return error.InvalidLength;

    const n_body = conn.tls.readAtLeast(response_buf[0..resp_len], resp_len) catch return error.TlsRecvFailed;
    if (n_body < resp_len) return error.TlsRecvFailed;

    sys.setQuickAck(handle);
    return response_buf[0..resp_len];
}

// ── Tests ───────────────────────────────────────────────────────────────

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

/// Drive a single ClientHello from `tls.nonblock.Client` with the given host
/// and return its raw bytes (writes into `out`). Used by the SNI patch tests.
fn captureClientHello(io: Io, host: []const u8, out: []u8) !usize {
    const rng_impl: std.Random.IoSource = .{ .io = io };
    var sc_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var cli = tls.nonblock.Client.init(.{
        .rng = rng_impl.interface(),
        .now = monotonic.wallclockTimestamp(io),
        .root_ca = .empty,
        .host = host,
        .insecure_skip_verify = true,
        .alpn_protocols = &.{alpn_dot},
    });
    const cr = try cli.run(&sc_buf, out);
    return cr.send_pos;
}

test "TlsTransport query against 1.1.1.1:853" {
    try skipIfNotLinux();
    const io = testing.io;

    var tls_t = TlsTransport.init(testing.allocator, io);

    const msg = try dns.buildQuery(testing.allocator, 0xC0DE, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = na.initIp4(.{ 1, 1, 1, 1 }, 53);
    var response_buf: [dns.max_message_len]u8 = undefined;
    const deadline = monotonic.nowNs() + 10 * std.time.ns_per_s;

    const response_data = tls_t.query(wire_query, server, &response_buf, deadline) catch |err| switch (err) {
        error.ConnectFailed, error.TlsHandshakeFailed, error.Timeout => return error.SkipZigTest,
        else => return err,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const response = try dns.parseMessage(arena.allocator(), response_data);

    try testing.expect(response.header.flags.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.flags.rcode);
    try testing.expect(response.answers.len > 0);
}

test "TlsTransport connection pooling reuses connection" {
    try skipIfNotLinux();
    const io = testing.io;

    var pool = ConnectionPool.init(testing.allocator, io);
    defer pool.deinit();

    var tls_t = TlsTransport.init(testing.allocator, io);
    tls_t.pool = &pool;

    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = na.initIp4(.{ 1, 1, 1, 1 }, 53);
    var response_buf: [dns.max_message_len]u8 = undefined;

    // First query — establishes connection, stores in pool
    const deadline1 = monotonic.nowNs() + 10 * std.time.ns_per_s;
    _ = tls_t.query(wire_query, server, &response_buf, deadline1) catch |err| switch (err) {
        error.ConnectFailed, error.TlsHandshakeFailed, error.Timeout => return error.SkipZigTest,
        else => return err,
    };

    // Pool should have one entry
    try testing.expectEqual(@as(usize, 1), pool.entries.count());

    // Second query — should reuse pooled connection
    const deadline2 = monotonic.nowNs() + 10 * std.time.ns_per_s;
    const response_data = tls_t.query(wire_query, server, &response_buf, deadline2) catch |err| switch (err) {
        error.ConnectFailed, error.TlsHandshakeFailed, error.TlsSendFailed, error.TlsRecvFailed, error.Timeout => return error.SkipZigTest,
        else => return err,
    };

    // Pool should still have one entry (returned after reuse)
    try testing.expectEqual(@as(usize, 1), pool.entries.count());

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const response = try dns.parseMessage(arena.allocator(), response_data);
    try testing.expect(response.header.flags.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.flags.rcode);
    try testing.expect(response.answers.len > 0);
}

/// Walk a captured ClientHello and return true if it contains a
/// `server_name` (SNI) extension. Used by the SNI-patch regression tests.
fn clientHelloHasSni(ch: []const u8) bool {
    // record header (5) + handshake header (4) + legacy_version (2) + random (32)
    var p: usize = 5 + 4 + 2 + 32;
    if (p >= ch.len) return false;
    p += 1 + ch[p]; // session_id
    if (p + 2 > ch.len) return false;
    p += 2 + mem.readInt(u16, ch[p..][0..2], .big); // cipher_suites
    if (p >= ch.len) return false;
    p += 1 + ch[p]; // compression_methods
    if (p + 2 > ch.len) return false;
    const ext_end = p + 2 + mem.readInt(u16, ch[p..][0..2], .big);
    p += 2;
    while (p + 4 <= ext_end and p + 4 <= ch.len) {
        const ext_type = mem.readInt(u16, ch[p..][0..2], .big);
        const ext_len = mem.readInt(u16, ch[p + 2 ..][0..2], .big);
        if (ext_type == 0x0000) return true;
        p += 4 + ext_len;
    }
    return false;
}

// Catches a refresh of src/vendor/tls-ianic/ that drops PATCHES.md's SNI guard:
// without the patch, host="" produces a malformed zero-length SNI extension on
// the wire, violating RFC 6066 §3 and our RFC 9539 §4.6.3.3 obligation.
test "ianic SNI patch: host=\"\" elides server_name extension" {
    var buf: [tls.max_ciphertext_record_len]u8 = undefined;
    const n = try captureClientHello(testing.io, "", &buf);
    try testing.expect(n > 0);
    try testing.expect(!clientHelloHasSni(buf[0..n]));
}

// Positive control: confirms clientHelloHasSni actually detects the extension
// when present, so a parser bug cannot silently mask the patch test above.
test "ianic SNI sanity: host=\"example.com\" includes server_name" {
    var buf: [tls.max_ciphertext_record_len]u8 = undefined;
    const n = try captureClientHello(testing.io, "example.com", &buf);
    try testing.expect(clientHelloHasSni(buf[0..n]));
}

test "probeInBackground reverts .probing when max_probes hit" {
    const io = testing.io;
    var enc_ns_cache = EncryptedNsCache.init(testing.allocator, io);
    defer enc_ns_cache.deinit();

    const server = na.initIp4(.{ 10, 0, 0, 1 }, 53);
    const tls_server = toPort(server, 853);
    const addr_key = AddressKey.fromAddress(tls_server);

    // Claim the probe slot (sets .probing)
    try testing.expect(enc_ns_cache.claimProbe(addr_key));
    try testing.expectEqual(encrypted_ns_mod.ServerStatus.probing, enc_ns_cache.getStatus(addr_key));

    // Saturate the probe-cap counter so the guard triggers
    enc_ns_cache.probes.active.store(encrypted_ns_mod.max_probes, .seq_cst);

    // probeInBackground should hit the max_probes guard and revert.
    var tls_t = TlsTransport.init(testing.allocator, testing.io);
    tls_t.probeInBackground(server, &enc_ns_cache);

    try testing.expectEqual(encrypted_ns_mod.ServerStatus.unknown, enc_ns_cache.getStatus(addr_key));
}

test "probeThread reverts .probing on shutdown" {
    const io = testing.io;
    var enc_ns_cache = EncryptedNsCache.init(testing.allocator, io);
    defer enc_ns_cache.deinit();

    const server = na.initIp4(.{ 10, 0, 0, 2 }, 53);
    const tls_server = toPort(server, 853);
    const addr_key = AddressKey.fromAddress(tls_server);

    // Claim the probe slot
    try testing.expect(enc_ns_cache.claimProbe(addr_key));

    // Signal shutdown before spawning so tryClaim short-circuits
    enc_ns_cache.probes.shutting_down.store(true, .release);

    var tls_t = TlsTransport.init(testing.allocator, testing.io);
    tls_t.probeInBackground(server, &enc_ns_cache);

    // Wait for the spawned probe to finish via the Group's await.
    enc_ns_cache.awaitProbes();

    try testing.expectEqual(encrypted_ns_mod.ServerStatus.unknown, enc_ns_cache.getStatus(addr_key));
}
