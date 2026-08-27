const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Io = std.Io;
const File = Io.File;
const Allocator = mem.Allocator;
const testing = std.testing;
const assert = std.debug.assert;
const dns = @import("dns.zig");
const pool_mod = @import("connection_pool.zig");
const ConnectionPool = pool_mod.ConnectionPool(pool_mod.PooledConnection);
const PooledConnection = pool_mod.PooledConnection;
const TlsClient = @import("tls_client.zig");
const encrypted_ns_mod = @import("encrypted_ns.zig");
const EncryptedNsCache = encrypted_ns_mod.EncryptedNsCache;
const na = @import("net_address.zig");
const AddressKey = na.AddressKey;
const sys = @import("sys.zig");
const blocking_transport = @import("blocking_transport.zig");
const monotonic = @import("monotonic.zig");
const log = std.log.scoped(.tls_transport);

/// RFC 9539 §4.4: DoT ALPN identifier ("dot").
const alpn_dot = "dot";

/// RFC 9539 opportunistic DoT transport: encrypts queries to authoritative
/// servers over TLS (ALPN "dot", no SNI, no certificate verification),
/// falling back to Do53 on any failure.
pub const TlsTransport = struct {
    pub const port: u16 = 853;

    allocator: Allocator,
    io: Io,
    /// Non-optional: a poolless transport could serve nothing.
    pool: *ConnectionPool,

    pub fn init(allocator: Allocator, io: Io, pool: *ConnectionPool) TlsTransport {
        return .{ .allocator = allocator, .io = io, .pool = pool };
    }

    pub const PooledResult = union(enum) {
        /// Answer bytes, allocated exactly to the response length (the
        /// allocator is typically a budgeted per-query arena).
        data: []u8,
        /// No pooled connection for this server.
        none,
        /// A pooled connection existed but the exchange failed (released broken).
        broken,
    };

    /// Query strictly on a pooled connection — never dials, so the caller's
    /// thread never pays TCP+TLS handshake latency. `.none` means the caller
    /// should serve over Do53 and rebuild warmth in the background.
    ///
    /// A conn the peer already idle-closed fails before any response byte;
    /// that says the pool was cold, not that the server is bad — report
    /// `.none`, never `.broken` (demoting cycled every short-lived-conn
    /// server through soft-damping and starved the encrypted path; a server
    /// that always closes unanswered thus stays .capable — accepted).
    /// `.broken` means the server took the query, then wedged or died.
    pub fn queryPooled(self: *TlsTransport, allocator: Allocator, wire_query: []const u8, server: na.Address, deadline_ns: i128) PooledResult {
        const tls_server = toPort(server, TlsTransport.port);
        const key = AddressKey.fromAddress(tls_server);
        const conn = self.pool.acquire(key) orelse return .none;
        if (queryOnConnection(conn, wire_query, allocator, deadline_ns)) |data| {
            pool_mod.applyKeepaliveHint(conn, data);
            self.pool.release(key, conn, true);
            return .{ .data = data };
        } else |err| {
            self.pool.release(key, conn, false);
            if (err == error.DeadOnArrival) return .none;
            return .broken;
        }
    }

    /// Dial + handshake a fresh DoT connection into the pool. The only
    /// connection-creating path, so handshake latency stays on background
    /// threads. Kernel timeouts stay armed for the handshake reads;
    /// `queryOnConnection` re-tightens per deadline (`connectTcpRaw`
    /// `.address` CONTRACT). error.ConnectFailed = transient; anything
    /// else reached the server and failed the protocol.
    fn dialAndPool(self: *TlsTransport, tls_server: na.Address, addr_key: AddressKey, connect_ms: u32) !void {
        const stream = blocking_transport.connectTcpRaw(tls_server, connect_ms) catch |e|
            return if (e == error.ConnectRefused) error.ConnectRefused else error.ConnectFailed;
        errdefer stream.close(self.io);
        sys.setSocketTimeout(stream.socket.handle, posix.SO.RCVTIMEO, connect_ms);
        const conn = try self.newPooledConnection(stream);
        errdefer self.allocator.destroy(conn);
        // RFC 9539 §4.6.3.3/4: no SNI, accept any cert.
        try self.handshake(conn, tls_server);
        self.pool.store(addr_key, conn);
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

    /// Run the TLS handshake on `conn` (RFC 9539): no SNI, no cert
    /// verification, ALPN "dot" per §4.4. A peer omitting the echo is
    /// tolerated (Cloudflare / Google do this in violation of RFC 7301
    /// §3.2); a non-"dot" echo fails the handshake — sending a
    /// length-prefixed DNS frame to e.g. an h2 endpoint would corrupt state.
    fn handshake(self: *TlsTransport, conn: *PooledConnection, tls_server: na.Address) !void {
        var entropy: [TlsClient.Options.entropy_len]u8 = undefined;
        self.io.random(&entropy);
        var selected: ?usize = null;
        conn.tls = TlsClient.init(&conn.net_reader.interface, &conn.net_writer.interface, .{
            .host = .no_verification,
            .ca = .no_verification,
            .alpn = .{ .protocols = &.{alpn_dot}, .selected_protocol = &selected },
            .read_buffer = &conn.tls_read_buf,
            .write_buffer = &.{},
            .entropy = &entropy,
            .realtime_now = monotonic.wallclockTimestamp(self.io),
            // DNS frames carry their own length prefix, so a bare FIN before
            // a record is an idle close (DeadOnArrival), not a truncation.
            .allow_truncation_attacks = true,
        }) catch |err| {
            var addr_buf: [64]u8 = undefined;
            log.debug("TLS handshake failed: {s} server={s}", .{ @errorName(err), na.format(tls_server, &addr_buf) });
            return error.TlsHandshakeFailed;
        };
    }

    pub const ProbeKind = encrypted_ns_mod.ProbeKind;

    /// Claim (via the cache's gate) and fire a background dial; on
    /// success the connection is pooled.
    pub fn probeInBackground(self: *TlsTransport, server: na.Address, enc_ns_cache: *EncryptedNsCache, kind: ProbeKind) void {
        const tls_server = toPort(server, TlsTransport.port);
        const addr_key = AddressKey.fromAddress(tls_server);
        if (!enc_ns_cache.claim(addr_key, kind)) return;

        if (!enc_ns_cache.probes.tryClaim()) {
            enc_ns_cache.revertClaim(addr_key, kind);
            return;
        }
        // Pass TlsTransport by value: the probe outlives the spawning
        // stack frame (pool / bg-prefetch) that holds the original
        // `*TlsTransport`. Copying snaps the small handle (allocator / io /
        // pool ptr) into the spawned task's args.
        enc_ns_cache.probes.spawn(self.io, probeThread, .{ self.*, tls_server, addr_key, enc_ns_cache, kind }) catch {
            // ConcurrencyUnavailable is transient (spawn pressure), not a
            // protocol failure — revert the .probing claim so the next
            // query can probe again instead of poisoning the entry with
            // `.failed` and skipping DoT for the full damping window.
            enc_ns_cache.revertClaim(addr_key, kind);
            enc_ns_cache.probes.release();
            return;
        };
    }

    fn probeThread(transport: TlsTransport, tls_server: na.Address, addr_key: AddressKey, enc_ns_cache: *EncryptedNsCache, kind: ProbeKind) void {
        defer enc_ns_cache.probes.release();

        var self = transport; // value copy owned by this task

        // RFC 9539 §4.3: TCP connect failure is "soft" — could be a
        // transient network blip; retry sooner. TLS handshake failure is
        // "hard" — server reached us but rejected the protocol; damp longer.
        // Hard band is .discover-only: a .rewarm target already proved it
        // speaks DoT (if it truly dropped DoT, damping decays to .unknown
        // and the next .discover hard-fails it). OOM is a local resource
        // event, never a protocol verdict.
        // A refused :853 (RST) is the exception — the port is definitively
        // closed, not a blip, so hard-band it for an hour on any probe kind
        // rather than spending ~60 soft rediscovery dials.
        self.dialAndPool(tls_server, addr_key, 4000) catch |err| {
            if (err == error.ConnectRefused) {
                enc_ns_cache.setStatus(addr_key, .failed);
                return;
            }
            const hard = kind == .discover and
                err != error.ConnectFailed and err != error.OutOfMemory;
            enc_ns_cache.setStatus(addr_key, if (hard) .failed else .soft_failed);
            return;
        };

        enc_ns_cache.setStatus(addr_key, .capable);
        if (kind == .discover) {
            var addr_buf: [64]u8 = undefined;
            log.info("server {s} supports DoT (RFC 9539)", .{na.format(tls_server, &addr_buf)});
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
/// direction, which bounds each syscall but not the payload: a peer dripping
/// one byte per interval resets the timer on every read and can hold a
/// resolution thread for hours. Under RFC 9539 that peer's address comes from
/// the delegation of the zone being resolved — chosen by whoever registered
/// the domain — so "upstream peers are trustworthy" is not a defence here.
/// What limits the damage today is `opportunistic` being off by default.
///
/// TODO: bound the whole payload as the Do53 TCP path does with
/// `sys.readExactDeadline`. The TLS layer buffers records rather than exposing
/// raw syscalls, so the read loop needs a per-syscall deadline hook first.
fn queryOnConnection(conn: *PooledConnection, wire_query: []const u8, allocator: Allocator, deadline_ns: i128) ![]u8 {
    // One staged frame → one TLS record → one syscall: the unbuffered TLS
    // writer encrypts straight into the socket writer, and only the flush
    // touches the wire.
    var staging: [2 + dns.edns_udp_payload]u8 = undefined;
    comptime assert(staging.len <= std.crypto.tls.max_ciphertext_inner_record_len);
    const framed = try dns.stageLengthPrefixed(&staging, wire_query);

    // Dead-on-arrival (see queryPooled): an idle-closed conn is caught on
    // the read side — the flush succeeds under half-close, then the read
    // sees the peer's close_notify or bare FIN before any response byte. A
    // peer that RSTs idle conns instead fails the flush; the std File path
    // maps that to BrokenPipe (EPIPE) or Unexpected (ECONNRESET → errnoBug),
    // never a distinct reset error. Either way the query never reached the
    // server, so it is a cold-pool signal — report DeadOnArrival and let the
    // dial path judge real deadness, rather than demoting a healthy server
    // and sawtoothing the capable gauge.
    const handle = conn.stream.socket.handle;
    try sys.updateTimeout(handle, posix.SO.SNDTIMEO, deadline_ns);
    assert(conn.net_writer.interface.buffered().len == 0);
    conn.tls.writer.writeAll(framed) catch return error.TlsSendFailed;
    conn.net_writer.interface.flush() catch return error.DeadOnArrival;

    try sys.updateTimeout(handle, posix.SO.RCVTIMEO, deadline_ns);
    var resp_len_buf: [2]u8 = undefined;
    conn.tls.reader.readSliceAll(&resp_len_buf) catch |err| {
        if (err == error.EndOfStream) return error.DeadOnArrival;
        // err is null at entry: errored conns are destroyed, never re-pooled.
        if (conn.net_reader.err) |e| if (e == error.ConnectionResetByPeer) return error.DeadOnArrival;
        return error.TlsRecvFailed;
    };
    const resp_len = mem.readInt(u16, &resp_len_buf, .big);
    if (resp_len == 0) return error.InvalidLength;

    // Exact-size, allocated only after the length prefix is known.
    const response_buf = try allocator.alloc(u8, resp_len);
    errdefer allocator.free(response_buf);

    conn.tls.reader.readSliceAll(response_buf) catch return error.TlsRecvFailed;

    sys.setQuickAck(handle);
    return response_buf;
}

// ── Tests ───────────────────────────────────────────────────────────────

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

test "TlsTransport queryPooled never dials" {
    // Cold pool must come back instantly as .none — the caller's thread
    // never pays a handshake.
    const io = testing.io;
    var pool = ConnectionPool.init(testing.allocator, io);
    defer pool.deinit();
    var tls_t = TlsTransport.init(testing.allocator, io, &pool);

    const server = na.initIp4(.{ 192, 0, 2, 1 }, 53);
    const deadline = monotonic.nowNs() + std.time.ns_per_s;
    try testing.expect(tls_t.queryPooled(testing.allocator, &.{}, server, deadline) == .none);
    try testing.expectEqual(@as(usize, 0), pool.entries.count());
}

test "TlsTransport dialAndPool then queryPooled against 1.1.1.1:853" {
    try skipIfNotLinux();
    const io = testing.io;

    var pool = ConnectionPool.init(testing.allocator, io);
    defer pool.deinit();
    var tls_t = TlsTransport.init(testing.allocator, io, &pool);

    // Background-thread shape: dial + handshake parks a warm connection.
    const server = na.initIp4(.{ 1, 1, 1, 1 }, 53);
    const tls_server = toPort(server, TlsTransport.port);
    tls_t.dialAndPool(tls_server, AddressKey.fromAddress(tls_server), 5000) catch
        return error.SkipZigTest;
    try testing.expectEqual(@as(usize, 1), pool.entries.count());

    const msg = try dns.buildQuery(testing.allocator, 0xC0DE, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    // First exchange rides the parked connection.
    const deadline = monotonic.nowNs() + 10 * std.time.ns_per_s;
    const response_data = switch (tls_t.queryPooled(testing.allocator, wire_query, server, deadline)) {
        .data => |data| data,
        .none, .broken => return error.SkipZigTest,
    };
    defer testing.allocator.free(response_data);
    try testing.expectEqual(@as(usize, 1), pool.entries.count());

    // Second exchange reuses it (still exactly one pooled conn).
    const deadline2 = monotonic.nowNs() + 10 * std.time.ns_per_s;
    switch (tls_t.queryPooled(testing.allocator, wire_query, server, deadline2)) {
        .data => |data2| testing.allocator.free(data2),
        .none, .broken => return error.SkipZigTest,
    }
    try testing.expectEqual(@as(usize, 1), pool.entries.count());

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const response = try dns.parseMessage(arena.allocator(), response_data);
    try testing.expect(response.header.flags.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.flags.rcode);
    try testing.expect(response.answers.len > 0);
}

test "probeInBackground reverts .probing when max_probes hit" {
    const io = testing.io;
    var enc_ns_cache = EncryptedNsCache.init(testing.allocator, io);
    defer enc_ns_cache.deinit();

    const server = na.initIp4(.{ 10, 0, 0, 1 }, 53);
    const tls_server = toPort(server, 853);
    const addr_key = AddressKey.fromAddress(tls_server);

    // Saturate the probe-cap counter so the guard triggers.
    enc_ns_cache.probes.active.store(encrypted_ns_mod.max_probes, .seq_cst);

    var pool = ConnectionPool.init(testing.allocator, io);
    defer pool.deinit();
    var tls_t = TlsTransport.init(testing.allocator, io, &pool);

    // .discover: claim then cap-revert forgets the entry entirely.
    tls_t.probeInBackground(server, &enc_ns_cache, .discover);
    try testing.expectEqual(encrypted_ns_mod.ServerStatus.unknown, enc_ns_cache.getStatus(addr_key));

    // .rewarm: the same revert must RESTORE .capable — spawn pressure on
    // the probe pool must not erase proven capability.
    enc_ns_cache.setStatus(addr_key, .capable);
    tls_t.probeInBackground(server, &enc_ns_cache, .rewarm);
    try testing.expectEqual(encrypted_ns_mod.ServerStatus.capable, enc_ns_cache.getStatus(addr_key));
}
