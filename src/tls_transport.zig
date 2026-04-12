const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Io = std.Io;
const File = Io.File;
const Certificate = std.crypto.Certificate;
const Allocator = mem.Allocator;
const testing = std.testing;
const dns = @import("dns.zig");
const EventLoop = @import("event_loop.zig").EventLoop;
const Completion = @import("event_loop.zig").Completion;
const max_operations = @import("event_loop.zig").max_operations;
const pool_mod = @import("connection_pool.zig");
const ConnectionPool = pool_mod.ConnectionPool(pool_mod.PooledConnection);
const PooledConnection = pool_mod.PooledConnection;
const AddressKey = pool_mod.AddressKey;
const VendoredTlsClient = @import("tls_client.zig");
const encrypted_ns_mod = @import("encrypted_ns.zig");
const EncryptedNsCache = encrypted_ns_mod.EncryptedNsCache;
const na = @import("net_address.zig");
const sys = @import("sys.zig");
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
    loop: ?*EventLoop,
    allocator: Allocator,
    config: TlsConfig,
    ca_bundle: Certificate.Bundle,
    io: Io,
    pool: ?*ConnectionPool = null,

    pub fn init(loop: ?*EventLoop, allocator: Allocator, config: TlsConfig, ca_bundle: Certificate.Bundle, io: Io) TlsTransport {
        return .{ .loop = loop, .allocator = allocator, .config = config, .ca_bundle = ca_bundle, .io = io };
    }

    pub fn query(self: *TlsTransport, wire_query: []const u8, server: na.Address, response_buf: []u8) ![]const u8 {
        const tls_server = toPort(server, self.config.port);
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

    /// TCP connect via io_uring, then switch to blocking mode with socket timeouts.
    /// Requires a non-null EventLoop; pool threads must use connectTcpBlocking.
    fn connectTcp(self: *TlsTransport, tls_server: na.Address, connect_timeout_ms: u32, rw_timeout_ms: u32) !posix.fd_t {
        const loop = self.loop orelse unreachable; // pool threads must use connectTcpBlocking
        const af: u32 = na.afU32(tls_server);
        const sock = try sys.socket(af, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        errdefer sys.close(sock);

        var connect_ctx = Ctx{ .tag = .connect };
        var timeout_ctx = Ctx{ .tag = .timeout };

        const connect_op = try loop.connect(sock, tls_server, @ptrCast(&connect_ctx));
        const timeout_op = try loop.setTimeout(connect_timeout_ms, @ptrCast(&timeout_ctx));

        connect_loop: while (true) {
            var completions: [max_operations]Completion = undefined;
            const results = try loop.tick(&completions);
            for (results) |c| {
                const ctx: *Ctx = @ptrCast(@alignCast(c.context));
                switch (ctx.tag) {
                    .connect => {
                        if (c.result.connect.err != null) {
                            loop.cancel(timeout_op) catch {};
                            loop.flush();
                            return error.ConnectFailed;
                        }
                        loop.cancel(timeout_op) catch {};
                        loop.flush();
                        break :connect_loop;
                    },
                    .timeout => {
                        if (c.result.timeout.expired) {
                            loop.cancel(connect_op) catch {};
                            loop.flush();
                            return error.Timeout;
                        }
                    },
                }
            }
        }

        // Switch to blocking mode with socket timeouts
        const current_flags = try sys.fcntl(sock, posix.F.GETFL, 0);
        const nonblock_bit = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
        _ = try sys.fcntl(sock, posix.F.SETFL, current_flags & ~nonblock_bit);

        sys.setSocketTimeouts(sock, rw_timeout_ms);

        return sock;
    }

    /// Establish a TCP connection via io_uring, perform TLS handshake,
    /// and return a heap-allocated PooledConnection.
    fn connectAndHandshake(self: *TlsTransport, tls_server: na.Address) !*PooledConnection {
        const sock = try self.connectTcp(tls_server, self.config.connect_timeout_ms, self.config.response_timeout_ms);
        errdefer sys.close(sock);

        const conn = try self.allocator.create(PooledConnection);
        errdefer self.allocator.destroy(conn);

        const file = File{ .handle = sock, .flags = .{ .nonblocking = false } };
        conn.sock = sock;
        conn.last_used = 0;
        conn.net_reader = File.Reader.initStreaming(file, self.io, &conn.net_read_buf);
        conn.net_writer = File.Writer.initStreaming(file, self.io, &conn.net_write_buf);

        // RFC 7858 strict mode: hostname verification is mandatory.
        if (self.config.strict and self.config.server_name == null) {
            return error.StrictModeRequiresHostname;
        }

        if (!self.config.skip_verification and self.config.server_name == null) {
            return error.ServerNameRequired;
        }

        conn.tls_client = VendoredTlsClient.init(&conn.net_reader.interface, &conn.net_writer.interface, .{
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
            .alpn = "dot", // RFC 9539 §4.4: DoT queries MUST use ALPN "dot"
            .read_buffer = &conn.tls_read_buf,
            .write_buffer = &conn.tls_write_buf,
        }, self.io) catch return error.TlsHandshakeFailed;

        return conn;
    }

    /// RFC 9539 opportunistic encrypted query: ALPN "dot", no cert verification,
    /// no SNI, 4-second connect timeout, immediate fallback on any failure.
    /// Tries pooled connection first, pools new connections on success.
    /// Auto-detects io_uring vs blocking connect based on whether self.loop is set.
    pub fn queryOpportunistic(self: *TlsTransport, wire_query: []const u8, server: na.Address, response_buf: []u8, timeout_ms: u32) ![]const u8 {
        const tls_server = toPort(server, self.config.port);
        const addr_key = AddressKey.fromAddress(tls_server);

        // ── Try pooled connection first ──
        if (self.pool) |pool| {
            if (pool.acquire(addr_key)) |conn| {
                if (queryOnConnection(conn, wire_query, response_buf)) |data| {
                    pool.release(addr_key, conn, true);
                    return data;
                } else |_| {
                    pool.release(addr_key, conn, false);
                }
            }
        }

        // ── New connection: blocking if no EventLoop, io_uring otherwise ──
        const conn = if (self.loop == null) blk: {
            const sock = try connectTcpBlocking(tls_server, timeout_ms);
            errdefer sys.close(sock);
            break :blk try self.initOpportunisticConnection(sock);
        } else try self.connectAndHandshakeOpportunistic(tls_server, timeout_ms);

        const data = queryOnConnection(conn, wire_query, response_buf) catch |err| {
            conn.destroyBroken(self.allocator);
            return err;
        };

        if (self.pool) |pool| {
            pool.store(addr_key, conn);
        } else {
            conn.closeAndDestroy(self.allocator);
        }

        return data;
    }

    /// Establish an opportunistic TLS connection (ALPN "dot", no cert, no SNI)
    /// and return a heap-allocated PooledConnection.
    fn connectAndHandshakeOpportunistic(self: *TlsTransport, tls_server: na.Address, timeout_ms: u32) !*PooledConnection {
        const sock = try self.connectTcp(tls_server, timeout_ms, timeout_ms);
        errdefer sys.close(sock);
        return self.initOpportunisticConnection(sock);
    }

    /// Allocate a PooledConnection from a connected socket and perform an
    /// opportunistic TLS handshake (ALPN "dot", no cert, no SNI).
    fn initOpportunisticConnection(self: *TlsTransport, sock: posix.fd_t) !*PooledConnection {
        const conn = try self.allocator.create(PooledConnection);
        errdefer self.allocator.destroy(conn);

        const file = File{ .handle = sock, .flags = .{ .nonblocking = false } };
        conn.sock = sock;
        conn.last_used = 0;
        conn.net_reader = File.Reader.initStreaming(file, self.io, &conn.net_read_buf);
        conn.net_writer = File.Writer.initStreaming(file, self.io, &conn.net_write_buf);

        // RFC 9539 §4.6.3.3: SHOULD NOT send SNI
        // RFC 9539 §4.6.3.4: MUST accept any certificate
        // RFC 9539 §4.4: MUST include ALPN "dot"
        conn.tls_client = VendoredTlsClient.init(&conn.net_reader.interface, &conn.net_writer.interface, .{
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = &conn.tls_read_buf,
            .write_buffer = &conn.tls_write_buf,
            .alpn = "dot",
            .alpn_required = false,
        }, self.io) catch return error.TlsHandshakeFailed;

        return conn;
    }

    fn connectTcpBlocking(tls_server: na.Address, timeout_ms: u32) !posix.fd_t {
        const af: u32 = na.afU32(tls_server);
        const sock = try sys.socket(af, posix.SOCK.STREAM, 0);
        errdefer sys.close(sock);
        sys.setSocketTimeouts(sock, timeout_ms);
        na.connectTo(sock, &tls_server) catch return error.ConnectFailed;
        return sock;
    }

    /// Fire a background probe for a nameserver. Detached thread does blocking
    /// TCP connect + TLS handshake. On success, the connection is pooled.
    pub fn probeInBackground(self: *TlsTransport, server: na.Address, enc_ns_cache: *EncryptedNsCache) void {
        const tls_server = toPort(server, self.config.port);
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
        const thread = std.Thread.spawn(.{}, probeThread, .{ self, tls_server, addr_key, enc_ns_cache }) catch {
            enc_ns_cache.markFailed(addr_key);
            _ = enc_ns_cache.active_probes.fetchSub(1, .seq_cst);
            return;
        };
        thread.detach();
    }

    fn probeThread(self: *TlsTransport, tls_server: na.Address, addr_key: AddressKey, enc_ns_cache: *EncryptedNsCache) void {
        defer _ = enc_ns_cache.active_probes.fetchSub(1, .seq_cst);
        if (enc_ns_cache.shutting_down.load(.seq_cst)) {
            enc_ns_cache.revertProbing(addr_key);
            return;
        }

        const sock = connectTcpBlocking(tls_server, 4000) catch {
            enc_ns_cache.markFailed(addr_key);
            return;
        };

        // ── TLS handshake ──
        const conn = self.initOpportunisticConnection(sock) catch {
            enc_ns_cache.markFailed(addr_key);
            sys.close(sock);
            return;
        };

        // Success — mark capable and pool the connection
        enc_ns_cache.markCapable(addr_key);
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
    const io = testing.io;

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    // Load system CA bundle
    var ca_bundle: Certificate.Bundle = .empty;
    ca_bundle.rescan(testing.allocator, io, Io.Timestamp.now(io, .real)) catch return error.SkipZigTest;
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(loop, testing.allocator, .{
        .server_name = "one.one.one.one",
    }, ca_bundle, io);

    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .a);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = na.initIp4(.{ 1, 1, 1, 1 }, 53); // port overridden to 853
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
    const io = testing.io;

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var ca_bundle: Certificate.Bundle = .empty;
    ca_bundle.rescan(testing.allocator, io, Io.Timestamp.now(io, .real)) catch return error.SkipZigTest;
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(loop, testing.allocator, .{
        .server_name = "dns.google",
    }, ca_bundle, io);

    const msg = try dns.buildQuery(testing.allocator, 0x1234, "example.com", .a);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = na.initIp4(.{ 8, 8, 8, 8 }, 53);
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
    const io = testing.io;

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var ca_bundle: Certificate.Bundle = .empty;
    ca_bundle.rescan(testing.allocator, io, Io.Timestamp.now(io, .real)) catch return error.SkipZigTest;
    defer ca_bundle.deinit(testing.allocator);

    var pool = ConnectionPool.init(testing.allocator, io);
    defer pool.deinit();

    var tls_t = TlsTransport.init(loop, testing.allocator, .{
        .server_name = "one.one.one.one",
    }, ca_bundle, io);
    tls_t.pool = &pool;

    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .a);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = na.initIp4(.{ 1, 1, 1, 1 }, 53);
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
    // Safe to use undefined: returns before spawning a thread or accessing other fields.
    var tls_t: TlsTransport = undefined;
    tls_t.config = .{};
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

    // Safe to use undefined: shutdown flag forces early return before accessing other fields.
    var tls_t: TlsTransport = undefined;
    tls_t.config = .{};
    tls_t.probeInBackground(server, &enc_ns_cache);

    // Wait for the detached thread to finish
    while (enc_ns_cache.active_probes.load(.seq_cst) > 0) {
        const ts = std.os.linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = std.os.linux.nanosleep(&ts, null);
    }

    try testing.expectEqual(encrypted_ns_mod.ServerStatus.unknown, enc_ns_cache.getStatus(addr_key));
}
