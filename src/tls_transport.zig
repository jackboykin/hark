const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Io = std.Io;
const File = Io.File;
const Certificate = std.crypto.Certificate;
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

pub const TlsConfig = struct {
    server_name: ?[]const u8 = null,
    /// RFC 7858 strict mode: require hostname verification (server_name must be set).
    strict: bool = false,
};

pub const TlsTransport = struct {
    pub const port: u16 = 853;
    const connect_timeout_ms: u32 = 5000;
    const response_timeout_ms: u32 = 10000;

    allocator: Allocator,
    config: TlsConfig,
    ca_bundle: Certificate.Bundle,
    io: Io,
    pool: ?*ConnectionPool = null,

    pub fn init(allocator: Allocator, config: TlsConfig, ca_bundle: Certificate.Bundle, io: Io) TlsTransport {
        return .{ .allocator = allocator, .config = config, .ca_bundle = ca_bundle, .io = io };
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

    pub fn query(self: *TlsTransport, wire_query: []const u8, server: na.Address, response_buf: []u8) ![]const u8 {
        const tls_server = toPort(server, TlsTransport.port);
        const key = AddressKey.fromAddress(tls_server);
        const deadline_ns = monotonic.nowNs() + @as(i128, response_timeout_ms) * std.time.ns_per_ms;

        if (self.tryPooledQuery(key, wire_query, response_buf, deadline_ns)) |data| return data;

        // ── Establish new connection ──
        const conn = try self.connectAndHandshake(tls_server);

        const data = queryOnConnection(conn, wire_query, response_buf, deadline_ns) catch |err| {
            conn.destroyBroken(self.allocator);
            return err;
        };

        if (self.pool) |pool| {
            pool_mod.applyKeepaliveHint(conn, data);
            pool.store(key, conn);
        } else {
            conn.closeAndDestroy(self.allocator);
        }

        return data;
    }

    /// Allocate a PooledConnection wired to `sock`. Caller must free via
    /// `destroyBroken` / `closeAndDestroy` on any subsequent error.
    fn newPooledConnection(self: *TlsTransport, sock: posix.fd_t) !*PooledConnection {
        const conn = try self.allocator.create(PooledConnection);
        const file = File{ .handle = sock, .flags = .{ .nonblocking = false } };
        conn.sock = sock;
        conn.last_used = 0;
        conn.query_count = 0;
        conn.max_queries = 200;
        conn.idle_timeout_sec = null;
        conn.net_reader = File.Reader.initStreaming(file, self.io, &conn.net_read_buf);
        conn.net_writer = File.Writer.initStreaming(file, self.io, &conn.net_write_buf);
        return conn;
    }

    /// Establish a blocking TCP connection, perform TLS handshake,
    /// and return a heap-allocated PooledConnection.
    fn connectAndHandshake(self: *TlsTransport, tls_server: na.Address) !*PooledConnection {
        // Config validation before any side effects. server_name must be a
        // non-empty hostname: ianic skips hostname verification when host="",
        // so a blank name would silently accept any cert from a trusted CA.
        if (self.config.strict and self.config.server_name == null) {
            return error.StrictModeRequiresHostname;
        }
        const server_name = self.config.server_name orelse return error.ServerNameRequired;
        if (server_name.len == 0) return error.ServerNameRequired;

        const sock = try connectTcpBlocking(tls_server, connect_timeout_ms);
        errdefer sys.close(sock);
        sys.setSocketTimeouts(sock, response_timeout_ms);

        const conn = try self.newPooledConnection(sock);
        errdefer self.allocator.destroy(conn);

        try self.handshake(conn, server_name, self.ca_bundle);
        return conn;
    }

    /// Run the TLS handshake on `conn`. `host=""` selects opportunistic mode:
    /// no SNI (vendored ianic patch elides the extension), no cert verification.
    /// Otherwise authenticated mode: SNI sent, full chain + hostname verify.
    /// ALPN advertises "dot" per RFC 9539 §4.4. The peer omitting the echo is
    /// tolerated (Cloudflare / Google do this in violation of RFC 7301 §3.2);
    /// a non-"dot" echo is rejected as a handshake failure — sending a
    /// length-prefixed DNS frame to e.g. an h2 endpoint would corrupt state.
    fn handshake(self: *TlsTransport, conn: *PooledConnection, host: []const u8, root_ca: Certificate.Bundle) !void {
        const rng_impl: std.Random.IoSource = .{ .io = self.io };
        conn.tls = tls.client(&conn.net_reader.interface, &conn.net_writer.interface, .{
            .rng = rng_impl.interface(),
            .now = Io.Timestamp.now(self.io, .real),
            .host = host,
            .root_ca = root_ca,
            .insecure_skip_verify = host.len == 0,
            .alpn_protocols = &.{alpn_dot},
        }) catch |err| {
            log.debug("TLS handshake failed against {s}: {s}", .{ host, @errorName(err) });
            return error.TlsHandshakeFailed;
        };
        if (conn.tls.alpn_protocol) |proto| {
            if (!std.mem.eql(u8, proto, alpn_dot)) {
                log.warn("TLS ALPN mismatch against {s}: peer echoed {s}", .{ host, proto });
                return error.TlsHandshakeFailed;
            }
        }
    }

    /// RFC 9539 opportunistic encrypted query: ALPN "dot", no cert verification,
    /// no SNI, immediate fallback on any failure. Tries pooled connection
    /// first, pools new connections on success. `deadline_ns` is an absolute
    /// monotonic deadline that bounds both connect and query.
    pub fn queryOpportunistic(self: *TlsTransport, wire_query: []const u8, server: na.Address, response_buf: []u8, deadline_ns: i128) ![]const u8 {
        const tls_server = toPort(server, TlsTransport.port);
        const addr_key = AddressKey.fromAddress(tls_server);

        if (self.tryPooledQuery(addr_key, wire_query, response_buf, deadline_ns)) |data| return data;

        // ── New connection ──
        const remaining_ns = deadline_ns - monotonic.nowNs();
        if (remaining_ns <= 0) return error.Timeout;
        const connect_ms: u32 = @intCast(@min(@divFloor(remaining_ns, std.time.ns_per_ms), std.math.maxInt(u32)));
        const sock = try connectTcpBlocking(tls_server, connect_ms);
        const conn = try self.initOpportunisticConnection(sock);

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

    /// Allocate a PooledConnection from a connected socket and perform an
    /// opportunistic TLS handshake (ALPN "dot", no cert, no SNI).
    /// Takes ownership of `sock`: closes it on any failure path.
    fn initOpportunisticConnection(self: *TlsTransport, sock: posix.fd_t) !*PooledConnection {
        errdefer sys.close(sock);
        const conn = try self.newPooledConnection(sock);
        errdefer self.allocator.destroy(conn);

        // RFC 9539 §4.6.3.3/4: no SNI, accept any cert. host="" selects
        // opportunistic mode in handshake().
        try self.handshake(conn, "", .empty);
        return conn;
    }

    fn connectTcpBlocking(tls_server: na.Address, timeout_ms: u32) !posix.fd_t {
        const af: u32 = na.afU32(tls_server);
        const sock = try sys.socket(af, posix.SOCK.STREAM, 0);
        errdefer sys.close(sock);
        sys.setSocketTimeouts(sock, timeout_ms);
        sys.setNoDelay(sock);
        na.connectTo(sock, &tls_server) catch return error.ConnectFailed;
        return sock;
    }

    /// Fire a background probe for a nameserver. Detached thread does blocking
    /// TCP connect + TLS handshake. On success, the connection is pooled.
    pub fn probeInBackground(self: *TlsTransport, server: na.Address, enc_ns_cache: *EncryptedNsCache) void {
        const tls_server = toPort(server, TlsTransport.port);
        const addr_key = AddressKey.fromAddress(tls_server);

        // Cap concurrent probe threads (CAS loop to avoid TOCTOU overcount)
        while (true) {
            const current = enc_ns_cache.active_probes.load(.seq_cst);
            if (current >= encrypted_ns_mod.max_probes) {
                enc_ns_cache.revertProbing(addr_key);
                return;
            }
            if (enc_ns_cache.active_probes.cmpxchgStrong(current, current + 1, .seq_cst, .seq_cst) == null) break;
        }
        // Pass TlsTransport by value: the probe thread is detached and
        // outlives the spawning thread (pool / bg-prefetch) whose stack
        // frame holds the original `*TlsTransport`. Copying snaps the
        // small handle (allocator / config / ca_bundle / io / pool ptr)
        // into the new thread's args before the spawning stack vanishes.
        // The Certificate.Bundle copy aliases byte slices owned by the
        // caller; they must outlive every detached probe. Hark's main
        // bundle is process-lifetime, so this holds.
        const thread = std.Thread.spawn(.{}, probeThread, .{ self.*, tls_server, addr_key, enc_ns_cache }) catch {
            enc_ns_cache.setStatus(addr_key, .failed);
            _ = enc_ns_cache.active_probes.fetchSub(1, .seq_cst);
            return;
        };
        thread.detach();
    }

    fn probeThread(transport: TlsTransport, tls_server: na.Address, addr_key: AddressKey, enc_ns_cache: *EncryptedNsCache) void {
        defer _ = enc_ns_cache.active_probes.fetchSub(1, .seq_cst);
        if (enc_ns_cache.shutting_down.load(.seq_cst)) {
            enc_ns_cache.revertProbing(addr_key);
            return;
        }

        var self = transport; // value copy owned by this thread

        // RFC 9539 §4.3: TCP connect failure is "soft" — could be a
        // transient network blip; retry sooner. TLS handshake failure is
        // "hard" — server reached us but rejected the protocol; damp longer.
        const sock = connectTcpBlocking(tls_server, 4000) catch {
            enc_ns_cache.setStatus(addr_key, .soft_failed);
            return;
        };

        // ── TLS handshake ──
        const conn = self.initOpportunisticConnection(sock) catch {
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

    try sys.updateTimeout(conn.sock, posix.SO.SNDTIMEO, deadline_ns);
    conn.tls.writeAll(framed) catch return error.TlsSendFailed;

    try sys.updateTimeout(conn.sock, posix.SO.RCVTIMEO, deadline_ns);
    var resp_len_buf: [2]u8 = undefined;
    const n_len = conn.tls.readAtLeast(&resp_len_buf, 2) catch return error.TlsRecvFailed;
    if (n_len < 2) return error.TlsRecvFailed;
    const resp_len = mem.readInt(u16, &resp_len_buf, .big);

    if (resp_len == 0 or resp_len > response_buf.len) return error.InvalidLength;

    const n_body = conn.tls.readAtLeast(response_buf[0..resp_len], resp_len) catch return error.TlsRecvFailed;
    if (n_body < resp_len) return error.TlsRecvFailed;

    sys.setQuickAck(conn.sock);
    return response_buf[0..resp_len];
}

// ── Tests ───────────────────────────────────────────────────────────────

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

/// Load the system CA bundle for an authenticated-mode test, or skip the
/// test if the host has none. Caller owns the returned bundle.
fn loadSystemCaBundleOrSkip(io: Io) !Certificate.Bundle {
    var ca_bundle: Certificate.Bundle = .empty;
    ca_bundle.rescan(testing.allocator, io, Io.Timestamp.now(io, .real)) catch return error.SkipZigTest;
    return ca_bundle;
}

/// Drive a single ClientHello from `tls.nonblock.Client` with the given host
/// and return its raw bytes (writes into `out`). Used by the SNI patch tests.
fn captureClientHello(io: Io, host: []const u8, out: []u8) !usize {
    const rng_impl: std.Random.IoSource = .{ .io = io };
    var sc_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var cli = tls.nonblock.Client.init(.{
        .rng = rng_impl.interface(),
        .now = Io.Timestamp.now(io, .real),
        .root_ca = .empty,
        .host = host,
        .insecure_skip_verify = true,
        .alpn_protocols = &.{alpn_dot},
    });
    const cr = try cli.run(&sc_buf, out);
    return cr.send_pos;
}

test "TlsTransport query Cloudflare DoT 1.1.1.1:853" {
    try skipIfNotLinux();
    const io = testing.io;

    var ca_bundle = try loadSystemCaBundleOrSkip(io);
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(testing.allocator, .{
        .server_name = "one.one.one.one",
    }, ca_bundle, io);

    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = na.initIp4(.{ 1, 1, 1, 1 }, 53); // port overridden to 853
    var response_buf: [dns.max_message_len]u8 = undefined;

    const response_data = tls_t.query(wire_query, server, &response_buf) catch |err| switch (err) {
        error.ConnectFailed, error.TlsHandshakeFailed => return error.SkipZigTest,
        else => return err,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const response = try dns.parseMessage(arena.allocator(), response_data);

    try testing.expect(response.header.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.rcode);
    try testing.expect(response.answers.len > 0);
}

test "TlsTransport query Google DoT 8.8.8.8:853" {
    try skipIfNotLinux();
    const io = testing.io;

    var ca_bundle = try loadSystemCaBundleOrSkip(io);
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(testing.allocator, .{
        .server_name = "dns.google",
    }, ca_bundle, io);

    const msg = try dns.buildQuery(testing.allocator, 0x1234, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = na.initIp4(.{ 8, 8, 8, 8 }, 53);
    var response_buf: [dns.max_message_len]u8 = undefined;

    const response_data = tls_t.query(wire_query, server, &response_buf) catch |err| switch (err) {
        error.ConnectFailed, error.TlsHandshakeFailed => return error.SkipZigTest,
        else => return err,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const response = try dns.parseMessage(arena.allocator(), response_data);

    try testing.expect(response.header.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.rcode);
    try testing.expect(response.answers.len > 0);
}

test "TlsTransport queryOpportunistic against 1.1.1.1:853" {
    try skipIfNotLinux();
    const io = testing.io;

    // Opportunistic mode does not need a CA bundle (no cert verification).
    var ca_bundle: Certificate.Bundle = .empty;
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(testing.allocator, .{}, ca_bundle, io);

    const msg = try dns.buildQuery(testing.allocator, 0xC0DE, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = na.initIp4(.{ 1, 1, 1, 1 }, 53);
    var response_buf: [dns.max_message_len]u8 = undefined;
    const deadline = monotonic.nowNs() + 10 * std.time.ns_per_s;

    const response_data = tls_t.queryOpportunistic(wire_query, server, &response_buf, deadline) catch |err| switch (err) {
        error.ConnectFailed, error.TlsHandshakeFailed, error.Timeout => return error.SkipZigTest,
        else => return err,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const response = try dns.parseMessage(arena.allocator(), response_data);

    try testing.expect(response.header.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.rcode);
    try testing.expect(response.answers.len > 0);
}

test "TlsTransport connection pooling reuses connection" {
    try skipIfNotLinux();
    const io = testing.io;

    var ca_bundle = try loadSystemCaBundleOrSkip(io);
    defer ca_bundle.deinit(testing.allocator);

    var pool = ConnectionPool.init(testing.allocator, io);
    defer pool.deinit();

    var tls_t = TlsTransport.init(testing.allocator, .{
        .server_name = "one.one.one.one",
    }, ca_bundle, io);
    tls_t.pool = &pool;

    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = na.initIp4(.{ 1, 1, 1, 1 }, 53);
    var response_buf: [dns.max_message_len]u8 = undefined;

    // First query — establishes connection, stores in pool
    _ = tls_t.query(wire_query, server, &response_buf) catch |err| switch (err) {
        error.ConnectFailed, error.TlsHandshakeFailed => return error.SkipZigTest,
        else => return err,
    };

    // Pool should have one entry
    try testing.expectEqual(@as(usize, 1), pool.entries.count());

    // Second query — should reuse pooled connection
    const response_data = tls_t.query(wire_query, server, &response_buf) catch |err| switch (err) {
        error.ConnectFailed, error.TlsHandshakeFailed, error.TlsSendFailed, error.TlsRecvFailed => return error.SkipZigTest,
        else => return err,
    };

    // Pool should still have one entry (returned after reuse)
    try testing.expectEqual(@as(usize, 1), pool.entries.count());

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const response = try dns.parseMessage(arena.allocator(), response_data);
    try testing.expect(response.header.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.rcode);
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

test "TlsTransport rejects empty server_name" {
    const io = testing.io;
    var ca_bundle: Certificate.Bundle = .empty;
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(testing.allocator, .{
        .server_name = "",
    }, ca_bundle, io);

    var wire_buf: [dns.edns_udp_payload]u8 = undefined;
    var response_buf: [dns.max_message_len]u8 = undefined;
    const server = na.initIp4(.{ 127, 0, 0, 1 }, 853);

    try testing.expectError(error.ServerNameRequired, tls_t.query(&wire_buf, server, &response_buf));
}

test "TlsTransport strict mode without server_name fails fast" {
    const io = testing.io;
    var ca_bundle: Certificate.Bundle = .empty;
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(testing.allocator, .{
        .strict = true,
        .server_name = null,
    }, ca_bundle, io);

    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    @memset(&wire_buf, 0);
    var response_buf: [dns.max_message_len]u8 = undefined;

    const server = na.initIp4(.{ 127, 0, 0, 1 }, 853);
    try testing.expectError(error.StrictModeRequiresHostname, tls_t.query(&wire_buf, server, &response_buf));
}

// Real Cloudflare DoT, but advertise an SNI/verify name no public cert
// could legitimately bear (.invalid is RFC 2606 reserved). Cloudflare's
// chain validates fine; the hostname check inside cert verification must
// reject it. Strict mode currently shares the cert-verify path, so the
// strict variant is a documentation-of-intent assertion: it pins that
// strict mode is at least as strict as default mode, ready to catch a
// future divergence.
fn runHostnameMismatchTest(strict: bool) !void {
    try skipIfNotLinux();
    const io = testing.io;

    var ca_bundle = try loadSystemCaBundleOrSkip(io);
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(testing.allocator, .{
        .server_name = "definitely-not-cloudflare.invalid",
        .strict = strict,
    }, ca_bundle, io);

    const msg = try dns.buildQuery(testing.allocator, 0xDEAD, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = na.initIp4(.{ 1, 1, 1, 1 }, 53);
    var response_buf: [dns.max_message_len]u8 = undefined;

    const result = tls_t.query(wire_query, server, &response_buf);
    if (result) |_| {
        return error.TestUnexpectedSuccess;
    } else |err| switch (err) {
        error.ConnectFailed => return error.SkipZigTest,
        error.TlsHandshakeFailed => {}, // expected
        else => return err,
    }
}

test "TlsTransport authenticated mode rejects hostname mismatch" {
    try runHostnameMismatchTest(false);
}

test "TlsTransport strict mode rejects hostname mismatch" {
    try runHostnameMismatchTest(true);
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

    // Saturate active_probes so the guard triggers
    enc_ns_cache.active_probes.store(encrypted_ns_mod.max_probes, .seq_cst);

    // probeInBackground should hit the max_probes guard and revert.
    var tls_t = TlsTransport.init(testing.allocator, .{}, .empty, testing.io);
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

    // Signal shutdown before spawning
    enc_ns_cache.shutting_down.store(true, .seq_cst);

    var tls_t = TlsTransport.init(testing.allocator, .{}, .empty, testing.io);
    tls_t.probeInBackground(server, &enc_ns_cache);

    // Wait for the detached thread to finish
    while (enc_ns_cache.active_probes.load(.seq_cst) > 0) {
        const ts = std.os.linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = std.os.linux.nanosleep(&ts, null);
    }

    try testing.expectEqual(encrypted_ns_mod.ServerStatus.unknown, enc_ns_cache.getStatus(addr_key));
}
