const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const net = std.net;
const Certificate = std.crypto.Certificate;
const Allocator = mem.Allocator;
const testing = std.testing;
const dns = @import("dns.zig");
const EventLoop = @import("event_loop.zig").EventLoop;
const Completion = @import("event_loop.zig").Completion;
const max_operations = @import("event_loop.zig").max_operations;
const pool_mod = @import("connection_pool.zig");
const ConnectionPool = pool_mod.ConnectionPool;
const PooledConnection = pool_mod.PooledConnection;
const AddressKey = pool_mod.AddressKey;
const VendoredTlsClient = @import("tls_client.zig");
const encrypted_ns_mod = @import("encrypted_ns.zig");
const EncryptedNsCache = encrypted_ns_mod.EncryptedNsCache;
const log = std.log.scoped(.tls_transport);

pub const TlsConfig = struct {
    connect_timeout_ms: u32 = 5000,
    response_timeout_ms: u32 = 10000,
    server_name: ?[]const u8 = null,
    skip_verification: bool = false,
    /// RFC 7858 strict mode: require hostname verification (server_name must be set).
    strict: bool = false,
    port: u16 = 853,
};

const Tag = enum { connect, timeout };
const Ctx = struct { tag: Tag };

pub const TlsTransport = struct {
    loop: *EventLoop,
    allocator: Allocator,
    config: TlsConfig,
    ca_bundle: Certificate.Bundle,
    pool: ?*ConnectionPool = null,

    pub fn init(loop: *EventLoop, allocator: Allocator, config: TlsConfig, ca_bundle: Certificate.Bundle) TlsTransport {
        return .{ .loop = loop, .allocator = allocator, .config = config, .ca_bundle = ca_bundle };
    }

    pub fn query(self: *TlsTransport, wire_query: []const u8, server: net.Address, response_buf: []u8) ![]const u8 {
        const tls_server = toPort(server, self.config.port) orelse return error.UnsupportedAddressFamily;
        const key = AddressKey.fromAddress(tls_server);

        // ── Try pooled connection first ──
        if (self.pool) |pool| {
            if (pool.acquire(key)) |conn| {
                if (queryOnConnection(conn, wire_query, response_buf)) |data| {
                    pool.release(key, conn, true);
                    return data;
                } else |_| {
                    // Pooled connection failed — close it, fall through to new connection
                    pool.release(key, conn, false);
                }
            }
        }

        // ── Establish new connection ──
        const conn = try self.connectAndHandshake(tls_server);

        const data = queryOnConnection(conn, wire_query, response_buf) catch |err| {
            conn.destroyBroken(self.allocator);
            return err;
        };

        // Store in pool or close
        if (self.pool) |pool| {
            pool.store(key, conn);
        } else {
            conn.closeAndDestroy(self.allocator);
        }

        return data;
    }

    /// TCP connect via io_uring + switch to blocking mode with socket timeouts.
    /// Returns a connected, blocking socket. Caller owns the fd.
    fn connectTcp(self: *TlsTransport, tls_server: net.Address, connect_timeout_ms: u32, rw_timeout_ms: u32) !posix.fd_t {
        const af: u32 = if (tls_server.any.family == posix.AF.INET6) posix.AF.INET6 else posix.AF.INET;
        const sock = try posix.socket(af, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(sock);

        var connect_ctx = Ctx{ .tag = .connect };
        var timeout_ctx = Ctx{ .tag = .timeout };

        const connect_op = try self.loop.connect(sock, tls_server, @ptrCast(&connect_ctx));
        const timeout_op = try self.loop.setTimeout(connect_timeout_ms, @ptrCast(&timeout_ctx));

        connect_loop: while (true) {
            var completions: [max_operations]Completion = undefined;
            const results = try self.loop.tick(&completions);
            for (results) |c| {
                const ctx: *Ctx = @ptrCast(@alignCast(c.context));
                switch (ctx.tag) {
                    .connect => {
                        if (c.result.connect.err != null) {
                            self.loop.cancel(timeout_op) catch {};
                            self.loop.flush();
                            return error.ConnectFailed;
                        }
                        self.loop.cancel(timeout_op) catch {};
                        self.loop.flush();
                        break :connect_loop;
                    },
                    .timeout => {
                        if (c.result.timeout.expired) {
                            self.loop.cancel(connect_op) catch {};
                            self.loop.flush();
                            return error.Timeout;
                        }
                    },
                }
            }
        }

        // Switch to blocking mode with socket timeouts
        const current_flags = try posix.fcntl(sock, posix.F.GETFL, 0);
        const nonblock_bit = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
        _ = try posix.fcntl(sock, posix.F.SETFL, current_flags & ~nonblock_bit);

        const timeout_sec: i64 = @intCast(rw_timeout_ms / 1000);
        const timeout_usec: i64 = @intCast(@as(u64, rw_timeout_ms % 1000) * 1000);
        const rw_timeout = posix.timeval{ .sec = timeout_sec, .usec = timeout_usec };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&rw_timeout));
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&rw_timeout));

        return sock;
    }

    /// Establish a TCP connection via io_uring, perform TLS handshake,
    /// and return a heap-allocated PooledConnection.
    fn connectAndHandshake(self: *TlsTransport, tls_server: net.Address) !*PooledConnection {
        const sock = try self.connectTcp(tls_server, self.config.connect_timeout_ms, self.config.response_timeout_ms);
        errdefer posix.close(sock);

        const conn = try self.allocator.create(PooledConnection);
        errdefer self.allocator.destroy(conn);

        const stream = net.Stream{ .handle = sock };
        conn.sock = sock;
        conn.stream = stream;
        conn.last_used = 0;
        conn.net_reader = net.Stream.Reader.init(stream, &conn.net_read_buf);
        conn.net_writer = net.Stream.Writer.init(stream, &conn.net_write_buf);

        // RFC 7858 strict mode: hostname verification is mandatory.
        if (self.config.strict and self.config.server_name == null) {
            return error.StrictModeRequiresHostname;
        }

        if (!self.config.skip_verification and self.config.server_name == null) {
            log.warn("TLS server_name not configured — certificate verification disabled; set server_name for authentication or skip_verification to suppress this warning", .{});
        }

        conn.tls_client = VendoredTlsClient.init(conn.net_reader.interface(), &conn.net_writer.interface, .{
            .host = if (self.config.skip_verification)
                .no_verification
            else if (self.config.server_name) |sn|
                .{ .explicit = sn }
            else
                .no_verification,
            .ca = if (self.config.skip_verification or self.config.server_name == null)
                .no_verification
            else
                .{ .bundle = self.ca_bundle },
            .read_buffer = &conn.tls_read_buf,
            .write_buffer = &conn.tls_write_buf,
        }) catch return error.TlsHandshakeFailed;

        return conn;
    }

    /// RFC 9539 opportunistic encrypted query: ALPN "dot", no cert verification,
    /// no SNI, 4-second connect timeout, immediate fallback on any failure.
    /// Tries pooled connection first, pools new connections on success.
    pub fn queryOpportunistic(self: *TlsTransport, wire_query: []const u8, server: net.Address, response_buf: []u8, timeout_ms: u32) ![]const u8 {
        const tls_server = toPort(server, self.config.port) orelse return error.UnsupportedAddressFamily;
        const addr_key = AddressKey.fromAddress(tls_server);

        // ── Try pooled connection first ──
        if (self.pool) |pool| {
            if (pool.acquire(addr_key)) |conn| {
                if (queryOnConnection(conn, wire_query, response_buf)) |data| {
                    pool.release(addr_key, conn, true);
                    return data;
                } else |_| {
                    pool.release(addr_key, conn, false);
                    // Fall through to new connection
                }
            }
        }

        // ── New connection: TCP connect via io_uring ──
        const conn = try self.connectAndHandshakeOpportunistic(tls_server, timeout_ms);

        const data = queryOnConnection(conn, wire_query, response_buf) catch |err| {
            conn.destroyBroken(self.allocator);
            return err;
        };

        // Store in pool or close
        if (self.pool) |pool| {
            pool.store(addr_key, conn);
        } else {
            conn.closeAndDestroy(self.allocator);
        }

        return data;
    }

    /// Establish an opportunistic TLS connection (ALPN "dot", no cert, no SNI)
    /// and return a heap-allocated PooledConnection.
    fn connectAndHandshakeOpportunistic(self: *TlsTransport, tls_server: net.Address, timeout_ms: u32) !*PooledConnection {
        const sock = try self.connectTcp(tls_server, timeout_ms, timeout_ms);
        errdefer posix.close(sock);
        return self.initOpportunisticConnection(sock);
    }

    /// Allocate a PooledConnection from a connected socket and perform an
    /// opportunistic TLS handshake (ALPN "dot", no cert, no SNI).
    fn initOpportunisticConnection(self: *TlsTransport, sock: posix.fd_t) !*PooledConnection {
        const conn = try self.allocator.create(PooledConnection);
        errdefer self.allocator.destroy(conn);

        const stream = net.Stream{ .handle = sock };
        conn.sock = sock;
        conn.stream = stream;
        conn.last_used = 0;
        conn.net_reader = net.Stream.Reader.init(stream, &conn.net_read_buf);
        conn.net_writer = net.Stream.Writer.init(stream, &conn.net_write_buf);

        // RFC 9539 §4.6.3.3: SHOULD NOT send SNI
        // RFC 9539 §4.6.3.4: MUST accept any certificate
        // RFC 9539 §4.4: MUST include ALPN "dot"
        conn.tls_client = VendoredTlsClient.init(conn.net_reader.interface(), &conn.net_writer.interface, .{
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = &conn.tls_read_buf,
            .write_buffer = &conn.tls_write_buf,
            .alpn = "dot",
        }) catch return error.TlsHandshakeFailed;

        return conn;
    }

    /// Fire a background probe for a nameserver. Detached thread does blocking
    /// TCP connect + TLS handshake. On success, the connection is pooled.
    pub fn probeInBackground(self: *TlsTransport, server: net.Address, enc_ns_cache: *EncryptedNsCache) void {
        const tls_server = toPort(server, self.config.port) orelse return;
        const addr_key = AddressKey.fromAddress(tls_server);

        // Cap concurrent probe threads
        const current = enc_ns_cache.active_probes.load(.seq_cst);
        if (current >= encrypted_ns_mod.max_probes) return;

        _ = enc_ns_cache.active_probes.fetchAdd(1, .seq_cst);
        const thread = std.Thread.spawn(.{}, probeThread, .{ self, tls_server, addr_key, enc_ns_cache }) catch {
            enc_ns_cache.markFailed(addr_key);
            _ = enc_ns_cache.active_probes.fetchSub(1, .seq_cst);
            return;
        };
        thread.detach();
    }

    fn probeThread(self: *TlsTransport, tls_server: net.Address, addr_key: AddressKey, enc_ns_cache: *EncryptedNsCache) void {
        defer _ = enc_ns_cache.active_probes.fetchSub(1, .seq_cst);
        if (enc_ns_cache.shutting_down.load(.seq_cst)) return;

        const probe_timeout_sec: i64 = 4;

        // ── Blocking TCP connect ──
        const af: u32 = if (tls_server.any.family == posix.AF.INET6) posix.AF.INET6 else posix.AF.INET;
        const sock = posix.socket(af, posix.SOCK.STREAM, 0) catch {
            enc_ns_cache.markFailed(addr_key);
            return;
        };

        // Set connect timeout via SO_SNDTIMEO
        const snd_timeout = posix.timeval{ .sec = probe_timeout_sec, .usec = 0 };
        const rcv_timeout = posix.timeval{ .sec = probe_timeout_sec, .usec = 0 };
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&snd_timeout)) catch {};
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&rcv_timeout)) catch {};

        posix.connect(sock, &tls_server.any, tls_server.getOsSockLen()) catch {
            enc_ns_cache.markFailed(addr_key);
            posix.close(sock);
            return;
        };

        // ── TLS handshake ──
        const conn = self.initOpportunisticConnection(sock) catch {
            enc_ns_cache.markFailed(addr_key);
            posix.close(sock);
            return;
        };

        // Success — mark capable and pool the connection
        enc_ns_cache.markCapable(addr_key);
        if (self.pool) |pool| {
            pool.store(addr_key, conn);
        } else {
            conn.closeAndDestroy(self.allocator);
        }
    }
};

/// Return a copy of `addr` with the port overridden, or null for unsupported families.
fn toPort(addr: net.Address, port: u16) ?net.Address {
    var out = addr;
    switch (out.any.family) {
        posix.AF.INET => out.in.setPort(port),
        posix.AF.INET6 => out.in6.setPort(port),
        else => return null,
    }
    return out;
}

/// Send a length-prefixed DNS query over an established TLS connection
/// and read the length-prefixed response.
fn queryOnConnection(conn: *PooledConnection, wire_query: []const u8, response_buf: []u8) ![]const u8 {
    if (wire_query.len > dns.max_udp_payload) return error.QueryTooLarge;
    const msg_len: u16 = @intCast(wire_query.len);
    var len_prefix: [2]u8 = undefined;
    mem.writeInt(u16, &len_prefix, msg_len, .big);

    // Send length-prefixed query
    conn.tls_client.writer.writeAll(&len_prefix) catch return error.TlsSendFailed;
    conn.tls_client.writer.writeAll(wire_query) catch return error.TlsSendFailed;
    conn.tls_client.writer.flush() catch return error.TlsSendFailed;
    conn.net_writer.interface.flush() catch return error.TlsSendFailed;

    // Read 2-byte length prefix
    var resp_len_buf: [2]u8 = undefined;
    conn.tls_client.reader.readSliceAll(&resp_len_buf) catch return error.TlsRecvFailed;
    const resp_len = mem.readInt(u16, &resp_len_buf, .big);

    if (resp_len == 0 or resp_len > response_buf.len) return error.InvalidLength;

    // Read response body
    conn.tls_client.reader.readSliceAll(response_buf[0..resp_len]) catch return error.TlsRecvFailed;

    return response_buf[0..resp_len];
}

// ── Tests ───────────────────────────────────────────────────────────────

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

test "TlsTransport query Cloudflare DoT 1.1.1.1:853" {
    try skipIfNotLinux();

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    // Load system CA bundle
    var ca_bundle: Certificate.Bundle = .{};
    ca_bundle.rescan(testing.allocator) catch return error.SkipZigTest;
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(loop, testing.allocator, .{
        .server_name = "one.one.one.one",
    }, ca_bundle);

    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .a);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = net.Address.initIp4(.{ 1, 1, 1, 1 }, 53); // port overridden to 853
    var response_buf: [65535]u8 = undefined;

    const response_data = tls_t.query(wire_query, server, &response_buf) catch |err| switch (err) {
        error.Timeout, error.ConnectFailed, error.TlsHandshakeFailed => return error.SkipZigTest,
        else => return err,
    };

    // Parse and verify
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const response = try dns.parseMessage(arena.allocator(), response_data);

    try testing.expect(response.header.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.rcode);
    try testing.expect(response.answers.len > 0);
}

test "TlsTransport query Google DoT 8.8.8.8:853" {
    try skipIfNotLinux();

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var ca_bundle: Certificate.Bundle = .{};
    ca_bundle.rescan(testing.allocator) catch return error.SkipZigTest;
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(loop, testing.allocator, .{
        .server_name = "dns.google",
    }, ca_bundle);

    const msg = try dns.buildQuery(testing.allocator, 0x1234, "example.com", .a);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = net.Address.initIp4(.{ 8, 8, 8, 8 }, 53);
    var response_buf: [65535]u8 = undefined;

    const response_data = tls_t.query(wire_query, server, &response_buf) catch |err| switch (err) {
        error.Timeout, error.ConnectFailed, error.TlsHandshakeFailed => return error.SkipZigTest,
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

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var ca_bundle: Certificate.Bundle = .{};
    ca_bundle.rescan(testing.allocator) catch return error.SkipZigTest;
    defer ca_bundle.deinit(testing.allocator);

    var pool = ConnectionPool.init(testing.allocator);
    defer pool.deinit();

    var tls_t = TlsTransport.init(loop, testing.allocator, .{
        .server_name = "one.one.one.one",
    }, ca_bundle);
    tls_t.pool = &pool;

    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .a);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = net.Address.initIp4(.{ 1, 1, 1, 1 }, 53);
    var response_buf: [65535]u8 = undefined;

    // First query — establishes connection, stores in pool
    _ = tls_t.query(wire_query, server, &response_buf) catch |err| switch (err) {
        error.Timeout, error.ConnectFailed, error.TlsHandshakeFailed => return error.SkipZigTest,
        else => return err,
    };

    // Pool should have one entry
    try testing.expectEqual(@as(usize, 1), pool.entries.count());

    // Second query — should reuse pooled connection
    const response_data = tls_t.query(wire_query, server, &response_buf) catch |err| switch (err) {
        error.Timeout, error.ConnectFailed, error.TlsHandshakeFailed, error.TlsSendFailed, error.TlsRecvFailed => return error.SkipZigTest,
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
