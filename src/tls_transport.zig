//! RFC 9539 DoT to authoritatives: ALPN "dot", no SNI, no verification.
const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const Allocator = mem.Allocator;
const posix = std.posix;
const testing = std.testing;
const assert = std.debug.assert;
const dns = @import("dns.zig");
const pool_mod = @import("connection_pool.zig");
const TlsClient = @import("tls_client.zig");
const na = @import("net_address.zig");
const AddressKey = na.AddressKey;
const sys = @import("sys.zig");
const blocking_transport = @import("blocking_transport.zig");
const monotonic = @import("monotonic.zig");
const log = std.log.scoped(.tls_transport);

pub const port: u16 = 853;
/// RFC 9539 §4.4.
const alpn_dot = "dot";

pub const Pool = pool_mod.ConnectionPool(Connection);

/// Self-referential; heap-only.
pub const Connection = struct {
    stream: Io.net.Stream,
    io: Io,
    /// Per-op bound; a trickling peer can't outlast it.
    deadline_ns: i128,
    net_reader: Io.Reader,
    net_writer: Io.Writer,
    tls: TlsClient,
    last_used: i64 = 0,
    query_count: u16 = 0,
    /// RFC 7766 §6.2.1.
    max_queries: u16 = 200,
    /// RFC 7828 hint; null → pool `max_idle_sec`.
    idle_timeout_sec: ?i64 = null,
    read_buf: [TlsClient.min_buffer_len]u8,
    write_buf: [TlsClient.min_buffer_len]u8,
    tls_read_buf: [TlsClient.min_buffer_len]u8,

    fn readStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const conn: *Connection = @alignCast(@fieldParentPtr("net_reader", r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        sys.pollReady(conn.stream.socket.handle, posix.POLL.IN, conn.deadline_ns) catch return error.ReadFailed;
        const n = sys.netRead(conn.io, conn.stream.socket.handle, dest) catch return error.ReadFailed;
        if (n == 0) return error.EndOfStream;
        w.advance(n);
        return n;
    }

    fn writeDrain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const conn: *Connection = @alignCast(@fieldParentPtr("net_writer", w));
        sys.pollReady(conn.stream.socket.handle, posix.POLL.OUT, conn.deadline_ns) catch return error.WriteFailed;
        const n = sys.netWriteVec(conn.io, conn.stream.socket.handle, w.buffered(), data, splat) catch return error.WriteFailed;
        return w.consume(n);
    }

    pub fn destroyBroken(self: *Connection, allocator: Allocator) void {
        self.stream.close(self.io);
        allocator.destroy(self);
    }
};

pub fn tlsAddress(server: na.Address) na.Address {
    return switch (server) {
        .ip4 => |v4| na.initIp4(v4.bytes, port),
        .ip6 => |v6| na.initIp6(v6.bytes, port, v6.flow, v6.interface.index),
    };
}

/// A pooled failure (usually an idle close) is not the server's verdict.
pub fn query(pool: *Pool, allocator: Allocator, wire_query: []const u8, server: na.Address, deadline_ns: i128) Allocator.Error!?[]u8 {
    const key = AddressKey.fromAddress(server);
    if (pool.acquire(key)) |conn| {
        // The budget is sized for a 3-RTT dial; a black-holed conn gets one share.
        const now = monotonic.nowNs();
        conn.deadline_ns = now + @divTrunc(deadline_ns - now, 4);
        if (try exchange(pool, key, conn, allocator, wire_query)) |data| return data;
    }
    const conn = dial(pool, server, deadline_ns) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    return exchange(pool, key, conn, allocator, wire_query);
}

pub fn dial(pool: *Pool, server: na.Address, deadline_ns: i128) !*Connection {
    const stream = try blocking_transport.connectTcp(tlsAddress(server), try sys.remainingTimeoutMs(deadline_ns));
    errdefer stream.close(pool.io);
    const conn = try pool.allocator.create(Connection);
    errdefer pool.allocator.destroy(conn);
    conn.* = .{
        .stream = stream,
        .io = pool.io,
        .deadline_ns = deadline_ns,
        .net_reader = .{ .vtable = &.{ .stream = Connection.readStream }, .buffer = &conn.read_buf, .seek = 0, .end = 0 },
        .net_writer = .{ .vtable = &.{ .drain = Connection.writeDrain }, .buffer = &conn.write_buf },
        .tls = undefined,
        .read_buf = undefined,
        .write_buf = undefined,
        .tls_read_buf = undefined,
    };

    var entropy: [TlsClient.Options.entropy_len]u8 = undefined;
    pool.io.random(&entropy);
    var selected: ?usize = null;
    // Missing ALPN echo tolerated (Cloudflare, Google); a non-"dot" echo fails.
    conn.tls = TlsClient.init(&conn.net_reader, &conn.net_writer, .{
        .host = .no_verification,
        .ca = .no_verification,
        .alpn = .{ .protocols = &.{alpn_dot}, .selected_protocol = &selected },
        .read_buffer = &conn.tls_read_buf,
        .write_buffer = &.{},
        .entropy = &entropy,
        .realtime_now = monotonic.wallclockTimestamp(pool.io),
        // Frames are self-delimiting; a bare FIN is an idle close.
        .allow_truncation_attacks = true,
    }) catch |err| {
        var addr_buf: [64]u8 = undefined;
        log.debug("TLS handshake failed: {s} server={s}", .{ @errorName(err), na.format(tlsAddress(server), &addr_buf) });
        return error.TlsHandshakeFailed;
    };
    return conn;
}

fn exchange(pool: *Pool, key: AddressKey, conn: *Connection, allocator: Allocator, wire_query: []const u8) Allocator.Error!?[]u8 {
    const data = exchangeOn(conn, allocator, wire_query) catch |err| {
        pool.release(key, conn, false);
        return if (err == error.OutOfMemory) error.OutOfMemory else null;
    };
    pool_mod.applyKeepaliveHint(conn, data);
    pool.release(key, conn, true);
    return data;
}

fn exchangeOn(conn: *Connection, allocator: Allocator, wire_query: []const u8) ![]u8 {
    // Unbuffered TLS writer: one record into net_writer, one write at flush.
    var staging: [2 + dns.edns_udp_payload]u8 = undefined;
    comptime assert(staging.len <= std.crypto.tls.max_ciphertext_inner_record_len);
    const framed = try dns.stageLengthPrefixed(&staging, wire_query);
    assert(conn.net_writer.buffered().len == 0);
    try conn.tls.writer.writeAll(framed);
    try conn.net_writer.flush();

    var len_buf: [2]u8 = undefined;
    try conn.tls.reader.readSliceAll(&len_buf);
    const len = mem.readInt(u16, &len_buf, .big);
    if (len == 0) return error.InvalidLength;
    const response = try allocator.alloc(u8, len);
    errdefer allocator.free(response);
    try conn.tls.reader.readSliceAll(response);
    sys.setQuickAck(conn.stream.socket.handle);
    return response;
}

test "reads give up at the deadline on a peer that never speaks" {
    // Backlog connects; peer stays mute.
    const io = testing.io;
    var server = try na.initIp4(.{ 127, 0, 0, 1 }, 0).listen(io, .{ .mode = .stream, .protocol = .tcp });
    defer server.deinit(io);
    const stream = try blocking_transport.connectTcp(server.socket.address, 1000);
    defer stream.close(io);

    const conn = try testing.allocator.create(Connection);
    defer testing.allocator.destroy(conn);
    const budget_ns: i128 = 200 * std.time.ns_per_ms;
    const start = monotonic.nowNs();
    conn.* = .{
        .stream = stream,
        .io = io,
        .deadline_ns = start + budget_ns,
        .net_reader = .{ .vtable = &.{ .stream = Connection.readStream }, .buffer = &conn.read_buf, .seek = 0, .end = 0 },
        .net_writer = .{ .vtable = &.{ .drain = Connection.writeDrain }, .buffer = &conn.write_buf },
        .tls = undefined,
        .read_buf = undefined,
        .write_buf = undefined,
        .tls_read_buf = undefined,
    };
    var byte: [1]u8 = undefined;
    try testing.expectError(error.ReadFailed, conn.net_reader.readSliceAll(&byte));
    try testing.expect(monotonic.nowNs() - start < 5 * budget_ns);
}

test "query dials cold then reuses the pooled connection against 1.1.1.1:853" {
    const io = testing.io;
    var pool = Pool.init(testing.allocator, io);
    defer pool.deinit();

    const server = na.initIp4(.{ 1, 1, 1, 1 }, 53);
    const msg = try dns.buildQuery(testing.allocator, 0xC0DE, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const first = try query(&pool, testing.allocator, wire_query, server, monotonic.nowNs() + 10 * std.time.ns_per_s) orelse
        return error.SkipZigTest;
    defer testing.allocator.free(first);
    try testing.expectEqual(@as(usize, 1), pool.total_conns);

    const second = try query(&pool, testing.allocator, wire_query, server, monotonic.nowNs() + 10 * std.time.ns_per_s) orelse
        return error.SkipZigTest;
    defer testing.allocator.free(second);
    try testing.expectEqual(@as(usize, 1), pool.total_conns);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const response = try dns.parseMessage(arena.allocator(), first);
    try testing.expect(response.header.flags.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.flags.rcode);
    try testing.expect(response.answers.len > 0);
}
