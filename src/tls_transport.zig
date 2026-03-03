const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const net = std.net;
const tls = std.crypto.tls;
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
const encryption_state = @import("encryption_state.zig");

pub const TlsConfig = struct {
    connect_timeout_ms: u32 = 5000,
    response_timeout_ms: u32 = 10000,
    server_name: ?[]const u8 = null,
    skip_verification: bool = false,
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
        // Compute pool key with TLS port override
        var tls_server = server;
        switch (tls_server.any.family) {
            posix.AF.INET => tls_server.in.setPort(self.config.port),
            posix.AF.INET6 => tls_server.in6.setPort(self.config.port),
            else => return error.UnsupportedAddressFamily,
        }
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

    /// Establish a TCP connection via io_uring, switch to blocking mode,
    /// perform TLS handshake, and return a heap-allocated PooledConnection.
    fn connectAndHandshake(self: *TlsTransport, tls_server: net.Address) !*PooledConnection {
        // ── Phase 1: TCP connect via io_uring ──
        const af: u32 = if (tls_server.any.family == posix.AF.INET6) posix.AF.INET6 else posix.AF.INET;
        const sock = try posix.socket(af, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(sock);

        var connect_ctx = Ctx{ .tag = .connect };
        var timeout_ctx = Ctx{ .tag = .timeout };

        const connect_op = try self.loop.connect(sock, tls_server, @ptrCast(&connect_ctx));
        const timeout_op = try self.loop.setTimeout(self.config.connect_timeout_ms, @ptrCast(&timeout_ctx));

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

        // ── Phase 2: Switch to blocking mode with socket timeouts ──
        const current_flags = try posix.fcntl(sock, posix.F.GETFL, 0);
        const nonblock_bit = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
        _ = try posix.fcntl(sock, posix.F.SETFL, current_flags & ~nonblock_bit);

        const timeout_sec: i64 = @intCast(self.config.response_timeout_ms / 1000);
        const timeout_usec: i64 = @intCast(@as(u64, self.config.response_timeout_ms % 1000) * 1000);
        const recv_timeout = posix.timeval{ .sec = timeout_sec, .usec = timeout_usec };
        const send_timeout = posix.timeval{ .sec = timeout_sec, .usec = timeout_usec };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&recv_timeout));
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&send_timeout));

        // ── Phase 3: Allocate PooledConnection and perform TLS handshake ──
        const conn = try self.allocator.create(PooledConnection);
        errdefer self.allocator.destroy(conn);

        const stream = net.Stream{ .handle = sock };
        conn.sock = sock;
        conn.stream = stream;
        conn.last_used = 0;
        conn.net_reader = net.Stream.Reader.init(stream, &conn.net_read_buf);
        conn.net_writer = net.Stream.Writer.init(stream, &conn.net_write_buf);

        conn.tls_client = tls.Client.init(conn.net_reader.interface(), &conn.net_writer.interface, .{
            .host = if (self.config.skip_verification)
                .no_verification
            else if (self.config.server_name) |sn|
                .{ .explicit = sn }
            else
                .no_verification,
            .ca = if (self.config.skip_verification)
                .no_verification
            else
                .{ .bundle = self.ca_bundle },
            .read_buffer = &conn.tls_read_buf,
            .write_buffer = &conn.tls_write_buf,
        }) catch {
            posix.close(sock);
            self.allocator.destroy(conn);
            return error.TlsHandshakeFailed;
        };

        return conn;
    }

    /// RFC 9539 opportunistic encrypted query: ALPN "dot", no cert verification,
    /// no SNI, 4-second connect timeout, immediate fallback on any failure.
    pub fn queryOpportunistic(self: *TlsTransport, wire_query: []const u8, server: net.Address, response_buf: []u8) ![]const u8 {
        var tls_server = server;
        switch (tls_server.any.family) {
            posix.AF.INET => tls_server.in.setPort(self.config.port),
            posix.AF.INET6 => tls_server.in6.setPort(self.config.port),
            else => return error.UnsupportedAddressFamily,
        }

        // ── Phase 1: TCP connect via io_uring (4s timeout per RFC 9539 §4.3) ──
        const af: u32 = if (tls_server.any.family == posix.AF.INET6) posix.AF.INET6 else posix.AF.INET;
        const sock = try posix.socket(af, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        defer posix.close(sock);

        var connect_ctx = Ctx{ .tag = .connect };
        var timeout_ctx = Ctx{ .tag = .timeout };

        const connect_op = try self.loop.connect(sock, tls_server, @ptrCast(&connect_ctx));
        const timeout_op = try self.loop.setTimeout(encryption_state.opportunistic_timeout_ms, @ptrCast(&timeout_ctx));

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

        // ── Phase 2: Switch to blocking mode ──
        const current_flags = try posix.fcntl(sock, posix.F.GETFL, 0);
        const nonblock_bit = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
        _ = try posix.fcntl(sock, posix.F.SETFL, current_flags & ~nonblock_bit);

        const timeout_sec: i64 = @intCast(encryption_state.opportunistic_timeout_ms / 1000);
        const timeout_usec: i64 = @intCast(@as(u64, encryption_state.opportunistic_timeout_ms % 1000) * 1000);
        const recv_timeout = posix.timeval{ .sec = timeout_sec, .usec = timeout_usec };
        const send_timeout = posix.timeval{ .sec = timeout_sec, .usec = timeout_usec };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&recv_timeout));
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&send_timeout));

        // ── Phase 3: TLS handshake with vendored client (ALPN "dot") ──
        const stream = net.Stream{ .handle = sock };

        var net_read_buf: [VendoredTlsClient.min_buffer_len]u8 = undefined;
        var net_write_buf: [VendoredTlsClient.min_buffer_len]u8 = undefined;
        var net_reader = net.Stream.Reader.init(stream, &net_read_buf);
        var net_writer = net.Stream.Writer.init(stream, &net_write_buf);

        var tls_read_buf: [VendoredTlsClient.min_buffer_len]u8 = undefined;
        var tls_write_buf: [VendoredTlsClient.min_buffer_len]u8 = undefined;

        // RFC 9539 §4.6.3.3: SHOULD NOT send SNI
        // RFC 9539 §4.6.3.4: MUST accept any certificate
        // RFC 9539 §4.4: MUST include ALPN "dot"
        var tls_client = VendoredTlsClient.init(net_reader.interface(), &net_writer.interface, .{
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = &tls_read_buf,
            .write_buffer = &tls_write_buf,
            .alpn = "dot",
        }) catch {
            return error.TlsHandshakeFailed;
        };

        // ── Phase 4: Send length-prefixed DNS query ──
        if (wire_query.len > dns.max_udp_payload) return error.QueryTooLarge;
        const msg_len: u16 = @intCast(wire_query.len);
        var len_prefix: [2]u8 = undefined;
        mem.writeInt(u16, &len_prefix, msg_len, .big);

        tls_client.writer.writeAll(&len_prefix) catch return error.TlsSendFailed;
        tls_client.writer.writeAll(wire_query) catch return error.TlsSendFailed;
        tls_client.writer.flush() catch return error.TlsSendFailed;
        net_writer.interface.flush() catch return error.TlsSendFailed;

        // ── Phase 5: Receive length-prefixed DNS response ──
        var resp_len_buf: [2]u8 = undefined;
        tls_client.reader.readSliceAll(&resp_len_buf) catch return error.TlsRecvFailed;
        const resp_len = mem.readInt(u16, &resp_len_buf, .big);

        if (resp_len == 0 or resp_len > response_buf.len) return error.InvalidLength;

        tls_client.reader.readSliceAll(response_buf[0..resp_len]) catch return error.TlsRecvFailed;

        // ── Phase 6: Clean shutdown ──
        tls_client.end() catch {};

        return response_buf[0..resp_len];
    }
};

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
