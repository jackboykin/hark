const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const testing = std.testing;
const Io = std.Io;
const dns = @import("dns.zig");
const monotonic = @import("monotonic.zig");
const pool_mod = @import("connection_pool.zig");
const TcpConnectionPool = pool_mod.TcpConnectionPool;
const TcpPooledConnection = pool_mod.TcpPooledConnection;
const na = @import("net_address.zig");
const AddressKey = na.AddressKey;
const sys = @import("sys.zig");

// UDP and TCP both flow through std.Io.net (Socket/Stream — reads via
// `std.Io.net.Stream.read`/`io.operate(.net_read)`, writes via `io.vtable.netWrite`).
// Connect-side TCP still opens the fd via raw posix for SO_SNDTIMEO — Zig's
// `netConnectIp` accepts a timeout option but its Io.Threaded backend panics on
// it. queryStaggered and the TCP loops
// drop to posix.poll on socket.handle rather than Io.select over receive
// futures — see comments at each call site.

pub const Config = struct {
    timeout_ms: u32 = 5000,
    retransmit_count: u32 = 2,
};

/// Map a UDP-send error to a transport-level error. Kernel-async ICMP
/// unreachable surfaces as ConnectionRefused. MessageOversize means our
/// serialized query exceeded path MTU — should not happen under normal EDNS
/// limits, so a distinct variant lets it stand out in logs.
fn mapUdpSendErr(err: anyerror) error{ PeerUnreachable, MessageTooBig, SendFailed } {
    return switch (err) {
        error.ConnectionRefused, error.HostUnreachable, error.NetworkUnreachable => error.PeerUnreachable,
        error.MessageOversize => error.MessageTooBig,
        else => error.SendFailed,
    };
}

/// Create a UDP socket bound to a random ephemeral port (RFC 5452 §9.1).
/// Source-port randomization is the kernel's job — `bind` with port 0
/// returns an Io.net.Socket with `address` populated to the resolved port.
fn openUdpSocket(dest: na.Address, io: Io) !Io.net.Socket {
    const bind_addr = na.wildcardFor(dest);
    return bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
}

/// Blocking UDP transport. Per-thread persistent unconnected sockets per
/// address family, rebound every `rebind_after_queries` to refresh source-port
/// randomness (RFC 5452 §9.1). The staggered path uses short-lived
/// per-leg sockets.
pub const BlockingUdpTransport = struct {
    config: Config,
    io: Io,
    sock_v4: ?Io.net.Socket = null,
    sock_v6: ?Io.net.Socket = null,
    v4_queries: u32 = 0,
    v6_queries: u32 = 0,

    /// Rotate the persistent socket every N queries for defense-in-depth:
    /// rebinding picks a fresh random source port, re-randomizing the
    /// RFC 5452 entropy. 4096 is small enough that an attacker guessing
    /// source-port+query-id has a narrow window per binding.
    const rebind_after_queries: u32 = 4096;

    pub fn init(config: Config, io: Io) BlockingUdpTransport {
        return .{ .config = config, .io = io };
    }

    pub fn deinit(self: *BlockingUdpTransport) void {
        if (self.sock_v4) |s| s.close(self.io);
        if (self.sock_v6) |s| s.close(self.io);
        self.sock_v4 = null;
        self.sock_v6 = null;
    }

    fn persistentSocket(self: *BlockingUdpTransport, dest: na.Address) !Io.net.Socket {
        const sock_ref, const counter_ref = switch (dest) {
            .ip4 => .{ &self.sock_v4, &self.v4_queries },
            .ip6 => .{ &self.sock_v6, &self.v6_queries },
        };
        if (sock_ref.* != null and counter_ref.* >= rebind_after_queries) {
            sock_ref.*.?.close(self.io);
            sock_ref.* = null;
            counter_ref.* = 0;
        }
        if (sock_ref.* == null) {
            sock_ref.* = try openUdpSocket(dest, self.io);
        }
        counter_ref.* += 1;
        return sock_ref.*.?;
    }

    pub fn query(self: *BlockingUdpTransport, wire_query: []const u8, query_id: u16, upstream: na.Address, response_buf: []u8) ![]const u8 {
        return self.queryWithTimeout(wire_query, query_id, upstream, self.config.timeout_ms, response_buf);
    }

    /// `response_buf` must outlive every slice the caller holds from the
    /// Message they parse out of the returned bytes — parsed Name labels
    /// and rdata byte slices alias this buffer. Pass a per-query arena-
    /// allocated buffer so wire-buffer lifetime matches parsed-Message
    /// lifetime.
    pub fn queryWithTimeout(self: *BlockingUdpTransport, wire_query: []const u8, query_id: u16, upstream: na.Address, timeout_ms: u32, response_buf: []u8) ![]const u8 {
        const sock = try self.persistentSocket(upstream);

        const retransmit_ms = @max(50, timeout_ms / 3);

        sock.send(self.io, &upstream, wire_query) catch |err| return mapUdpSendErr(err);

        const deadline_ns = monotonic.nowNs() + @as(i128, timeout_ms) * 1_000_000;
        var retransmits_left: u32 = self.config.retransmit_count;

        while (true) {
            const remaining_ns = deadline_ns - monotonic.nowNs();
            if (remaining_ns <= 0) return error.Timeout;

            const remain_ms: u32 = @intCast(@min(
                @divFloor(remaining_ns, 1_000_000),
                retransmit_ms,
            ));
            if (remain_ms == 0) return error.Timeout;

            const msg = sock.receiveTimeout(
                self.io,
                response_buf,
                .{ .duration = .{ .raw = .fromMilliseconds(remain_ms), .clock = .awake } },
            ) catch |err| switch (err) {
                error.Timeout => {
                    if (retransmits_left == 0) return error.Timeout;
                    retransmits_left -= 1;
                    sock.send(self.io, &upstream, wire_query) catch |e| return mapUdpSendErr(e);
                    continue;
                },
                error.PortUnreachable => return error.PeerUnreachable,
                else => return error.RecvFailed,
            };

            if (msg.data.len < 2) continue;

            // Userspace source check: the persistent socket is unconnected so
            // it can receive responses addressed to any peer. Require full
            // (IP, port) match to mirror the 4-tuple enforcement a connected
            // socket would get from the kernel — off-path attackers spoofing
            // the upstream IP with a random source port are otherwise
            // accepted at this layer (RFC 5452 §9.2 assumes 5-tuple).
            if (!msg.from.eql(&upstream)) continue;

            const resp_id = mem.readInt(u16, msg.data[0..2], .big);
            if (resp_id == query_id) {
                return msg.data;
            }
            // Wrong ID — keep waiting.
        }
    }

    const StaggeredResult = struct {
        response_data: []const u8,
        responding_idx: u8,
    };

    /// Bounds stack-allocated pollfd + socket arrays in `queryStaggered`.
    /// Must be >= any caller's effective cap.
    pub const max_staggered_legs = 4;

    /// Race up to `max_staggered_legs` nameservers; return the first valid
    /// response. Each leg gets an unconnected UDP socket with a unique
    /// kernel-assigned ephemeral port (RFC 5452 §9.1). Callers must pass
    /// distinct destination IPs — racing the same IP would not increase
    /// birthday entropy.
    ///
    /// Per-leg source filtering is done in userspace by `tryRecv` via
    /// `msg.from.eql(expected_server)` — the legs are unconnected so the
    /// kernel cannot enforce a 4-tuple filter for us.
    ///
    /// `wire_queries`, `query_ids`, `servers` must be parallel arrays of length
    /// 2..`max_staggered_legs`. Leg `i` launches at `query_start + i*stagger_ms`
    /// unless an earlier leg responds first. `response_buf` lifetime: see
    /// queryWithTimeout.
    ///
    /// Multi-socket wait still uses `posix.poll` over `socket.handle` because
    /// `Io.select` over `receiveTimeout` futures is heavier than it's worth
    /// at this scale; revisit when `Io.Evented` networking lands.
    pub fn queryStaggered(
        self: *BlockingUdpTransport,
        wire_queries: []const []const u8,
        query_ids: []const u16,
        servers: []const na.Address,
        stagger_ms: u32,
        overall_timeout_ms: u32,
        response_buf: []u8,
    ) !StaggeredResult {
        const leg_n = servers.len;
        std.debug.assert(leg_n >= 2 and leg_n <= max_staggered_legs);
        std.debug.assert(leg_n == wire_queries.len and leg_n == query_ids.len);

        var socks: [max_staggered_legs]Io.net.Socket = undefined;
        var sock_count: usize = 0;
        defer for (socks[0..sock_count]) |s| s.close(self.io);

        const deadline_ns = monotonic.nowNs() + @as(i128, overall_timeout_ms) * 1_000_000;
        const stagger_ns: i128 = @as(i128, stagger_ms) * 1_000_000;

        // Launch leg 0 synchronously so the caller sees send errors
        // immediately rather than spinning in the poll loop.
        const s0 = try openUdpSocket(servers[0], self.io);
        socks[0] = s0;
        sock_count = 1;
        s0.send(self.io, &servers[0], wire_queries[0]) catch |err| return mapUdpSendErr(err);
        var next_launch_ns: i128 = monotonic.nowNs() + stagger_ns;

        while (true) {
            const now_ns = monotonic.nowNs();
            if (now_ns >= deadline_ns) return error.Timeout;

            // Fire any legs whose stagger interval has elapsed.
            while (sock_count < leg_n and now_ns >= next_launch_ns) {
                const idx = sock_count;
                const s = openUdpSocket(servers[idx], self.io) catch {
                    // Out of ephemeral ports / fd budget: stop trying to fan
                    // out, keep polling the legs already in flight.
                    next_launch_ns = deadline_ns;
                    break;
                };
                socks[idx] = s;
                sock_count += 1;
                s.send(self.io, &servers[idx], wire_queries[idx]) catch {
                    next_launch_ns = deadline_ns;
                    break;
                };
                next_launch_ns = monotonic.nowNs() + stagger_ns;
            }

            // Poll until the deadline or the next scheduled launch, whichever
            // comes first.
            const wait_until_ns = if (sock_count < leg_n)
                @min(deadline_ns, next_launch_ns)
            else
                deadline_ns;
            const wait_ns = wait_until_ns - monotonic.nowNs();
            if (wait_ns <= 0) continue;
            const wait_ms: i32 = @intCast(@min(@divFloor(wait_ns, 1_000_000), std.math.maxInt(i32)));

            var polls: [max_staggered_legs]posix.pollfd = undefined;
            for (0..sock_count) |i| {
                polls[i] = .{ .fd = socks[i].handle, .events = posix.POLL.IN, .revents = 0 };
            }
            const n = posix.poll(polls[0..sock_count], wait_ms) catch 0;
            if (n == 0) continue; // next launch fires, or overall deadline expires

            for (0..sock_count) |i| {
                if (polls[i].revents & posix.POLL.IN != 0) {
                    if (tryRecv(socks[i], self.io, &servers[i], query_ids[i], response_buf)) |data| {
                        return .{ .response_data = data, .responding_idx = @intCast(i) };
                    }
                }
            }
            // All readable sockets had unparseable/wrong-id packets; keep polling.
        }
    }

    /// Drain one datagram from a readable socket and validate it as a DNS
    /// response from the expected server with the expected query ID.
    /// Returns the response slice (into `response_buf`) or null on any
    /// mismatch / receive error.
    fn tryRecv(
        sock: Io.net.Socket,
        io: Io,
        expected_server: *const na.Address,
        expected_id: u16,
        response_buf: []u8,
    ) ?[]const u8 {
        // poll(2) said readable; zero-timeout recv pulls one datagram or
        // returns error.Timeout if the queue is already drained (rare
        // post-poll kernel race — treat as "nothing here").
        const msg = sock.receiveTimeout(io, response_buf, .{ .duration = .{ .raw = .zero, .clock = .awake } }) catch return null;
        if (msg.data.len < 2) return null;
        // Source check mirrors queryWithTimeout's RFC 5452 §9.2 enforcement.
        if (!msg.from.eql(expected_server)) return null;
        const resp_id = mem.readInt(u16, msg.data[0..2], .big);
        if (resp_id != expected_id) return null;
        return msg.data;
    }
};

// TCP transport using blocking sockets for thread-pool resolution.
// Tracks total deadline to mitigate slow-trickle attacks where an
// attacker sends one byte at a time — every iteration of the data
// loop polls with the remaining deadline before issuing a read/write.

const tcp_connect_timeout_ms: u32 = 5000;
const tcp_response_timeout_ms: u32 = 10000;

/// Send a DNS query over TCP. With pool != null, tries an idle pooled
/// connection first and stores a fresh one on success.
pub fn queryTcp(
    io: Io,
    wire_query: []const u8,
    server: na.Address,
    response_buf: []u8,
    pool: ?*TcpConnectionPool,
) ![]const u8 {
    const deadline_ns = monotonic.nowNs() + @as(i128, tcp_response_timeout_ms) * 1_000_000;

    if (pool) |p| {
        const key = AddressKey.fromAddress(server);
        if (p.acquire(key)) |conn| {
            if (sendAndReceiveTcp(conn.stream, io, wire_query, response_buf, deadline_ns)) |data| {
                pool_mod.applyKeepaliveHint(conn, data);
                p.release(key, conn, true);
                return data;
            } else |_| {
                p.release(key, conn, false);
            }
        }
    }

    const stream = try connectTcp(server);
    const data = sendAndReceiveTcp(stream, io, wire_query, response_buf, deadline_ns) catch |err| {
        stream.close(io);
        return err;
    };

    if (pool) |p| {
        const key = AddressKey.fromAddress(server);
        const new_conn = p.allocator.create(TcpPooledConnection) catch {
            // Pool out of memory — close the stream since no one will own it.
            stream.close(io);
            return data;
        };
        new_conn.* = .{ .stream = stream, .io = io, .last_used = undefined, .query_count = undefined };
        pool_mod.applyKeepaliveHint(new_conn, data);
        p.store(key, new_conn);
        return data;
    }

    stream.close(io);
    return data;
}

/// Open a connected TCP stream — the raw connect kernel shared by Do53
/// (`connectTcp`) and DoT (`tls_transport.dialAndPool`). The fd is
/// opened via raw posix so we can apply SO_SNDTIMEO for the connect
/// itself — Zig's `IpAddress.connect` accepts a timeout option but its
/// Io.Threaded backend panics on it. SNDTIMEO is left set to
/// `connect_timeout_ms`; each caller resets or re-arms it for its data
/// phase. Once the stdlib grows working connect timeouts, this collapses
/// to one line.
///
/// `.address` is intentionally zero (not populated via getsockname).
/// CONTRACT: no caller reads `Stream.socket.address` on a client-side
/// stream. Audit on zig bumps: close/read/write paths must only touch
/// `.handle`. The family-tag may not match
/// the peer's family (zero is ip4 here, even on ip6 connects); a
/// future `Stream.peerAddress()` or address-formatting code would
/// silently lie. Populate via `na.getSockName` if that ever matters.
pub fn connectTcpRaw(server: na.Address, connect_timeout_ms: u32) !Io.net.Stream {
    const af: u32 = na.afU32(server);
    const sock_fd = try sys.socket(af, posix.SOCK.STREAM, 0);
    errdefer sys.close(sock_fd);
    sys.setSocketTimeout(sock_fd, posix.SO.SNDTIMEO, connect_timeout_ms);
    sys.setNoDelay(sock_fd);
    na.connectTo(sock_fd, &server) catch |e|
        return if (e == error.ConnectionRefused) error.ConnectRefused else error.ConnectFailed;
    return .{ .socket = .{ .handle = sock_fd, .address = na.initIp4(.{ 0, 0, 0, 0 }, 0) } };
}

/// Do53 connect: clear SNDTIMEO after connect so subsequent data ops
/// don't surface EAGAIN through netRead/netWrite, which `netReadPosix`/
/// `netWritePosix` treat as a programmer bug — deadlines here are
/// enforced in userspace (`sendAndReceiveTcp`).
pub fn connectTcp(server: na.Address) !Io.net.Stream {
    const stream = try connectTcpRaw(server, tcp_connect_timeout_ms);
    sys.clearSocketTimeout(stream.socket.handle, posix.SO.SNDTIMEO);
    return stream;
}

/// Length-prefixed DNS query/response on a connected TCP stream, via the
/// deadline-bounded exact-I/O kernels in sys.zig (userspace deadline
/// enforcement — kernel-side SO_*TIMEO can't be used because Io.Threaded's
/// netRead/netWrite treat EAGAIN as a bug). Timeout passes through;
/// every other failure collapses to SendFailed on the write side,
/// ConnectionClosed on the read side.
pub fn sendAndReceiveTcp(stream: Io.net.Stream, io: Io, wire_query: []const u8, response_buf: []u8, deadline_ns: i128) ![]const u8 {
    const handle = stream.socket.handle;

    // ── Send length-prefixed query ──
    var send_buf: [2 + dns.edns_udp_payload]u8 = undefined;
    const framed = try dns.stageLengthPrefixed(&send_buf, wire_query);
    sys.writeAllDeadline(io, handle, framed, deadline_ns) catch |err| switch (err) {
        error.Timeout => return error.Timeout,
        else => return error.SendFailed,
    };

    // ── Receive length-prefixed response ──
    var len_buf: [2]u8 = undefined;
    sys.readExactDeadline(io, handle, &len_buf, deadline_ns) catch |err| switch (err) {
        error.Timeout => return error.Timeout,
        else => return error.ConnectionClosed,
    };

    const body_len = mem.readInt(u16, &len_buf, .big);
    if (body_len == 0 or body_len > response_buf.len) return error.InvalidLength;

    sys.readExactDeadline(io, handle, response_buf[0..body_len], deadline_ns) catch |err| switch (err) {
        error.Timeout => return error.Timeout,
        else => return error.ConnectionClosed,
    };

    sys.setQuickAck(handle);
    return response_buf[0..body_len];
}

// ── Tests ────────────────────────────────────────────────────────────────

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

test "mapUdpSendErr classifies the Socket.SendError surface" {
    // PeerUnreachable bucket: any "this peer can't be reached" signal so the
    // resolver can fail over to a sibling NS without spending the timeout.
    try testing.expectEqual(error.PeerUnreachable, mapUdpSendErr(error.ConnectionRefused));
    try testing.expectEqual(error.PeerUnreachable, mapUdpSendErr(error.HostUnreachable));
    try testing.expectEqual(error.PeerUnreachable, mapUdpSendErr(error.NetworkUnreachable));

    // MessageTooBig: distinct because it indicates a serialization bug, not a
    // network problem — retrying or failing over won't help.
    try testing.expectEqual(error.MessageTooBig, mapUdpSendErr(error.MessageOversize));

    // Everything else collapses to SendFailed.
    try testing.expectEqual(error.SendFailed, mapUdpSendErr(error.NetworkDown));
    try testing.expectEqual(error.SendFailed, mapUdpSendErr(error.SystemResources));
    try testing.expectEqual(error.SendFailed, mapUdpSendErr(error.SocketUnconnected));
    try testing.expectEqual(error.SendFailed, mapUdpSendErr(error.AccessDenied));
}

test "BlockingUdpTransport loopback query" {
    try skipIfNotLinux();
    const io = testing.io;

    var transport = BlockingUdpTransport.init(.{ .timeout_ms = 2000 }, io);

    const server_bind = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    const server_sock = try server_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer server_sock.close(io);
    const server_addr = server_sock.address;

    const msg = try dns.buildQuery(testing.allocator, 0x1234, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const thread = try std.Thread.spawn(.{}, echoServerThread, .{ server_sock, io });

    var response_buf: [dns.edns_udp_payload]u8 = undefined;
    const response = try transport.query(wire_query, 0x1234, server_addr, &response_buf);
    thread.join();

    try testing.expect(response.len >= 12);
    const resp_id = mem.readInt(u16, response[0..2], .big);
    try testing.expectEqual(@as(u16, 0x1234), resp_id);
    try testing.expect(response[2] & 0x80 != 0);
}

test "BlockingUdpTransport timeout" {
    try skipIfNotLinux();
    const io = testing.io;

    var transport = BlockingUdpTransport.init(.{ .timeout_ms = 100, .retransmit_count = 0 }, io);

    // Black-hole server: bind a socket and never read from it.
    const server_bind = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    const server_sock = try server_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer server_sock.close(io);
    const server_addr = server_sock.address;

    const msg = try dns.buildQuery(testing.allocator, 0x5678, "timeout.test", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    var response_buf: [dns.edns_udp_payload]u8 = undefined;
    const result = transport.query(wire_query, 0x5678, server_addr, &response_buf);
    try testing.expectError(error.Timeout, result);
}

test "BlockingUdpTransport IPv6 loopback query" {
    try skipIfNotLinux();
    const io = testing.io;

    var transport = BlockingUdpTransport.init(.{ .timeout_ms = 2000 }, io);

    const server_bind = na.initIp6(@splat(0), 0, 0, 0);
    const server_sock = server_bind.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch |err| switch (err) {
        error.AddressFamilyUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer server_sock.close(io);

    const port = server_sock.address.getPort();
    const server_addr = na.initIp6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, port, 0, 0);

    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .aaaa, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const thread = try std.Thread.spawn(.{}, echoServerThread, .{ server_sock, io });

    var response_buf: [dns.edns_udp_payload]u8 = undefined;
    const response = try transport.query(wire_query, 0xABCD, server_addr, &response_buf);
    thread.join();

    try testing.expect(response.len >= 12);
    const resp_id = mem.readInt(u16, response[0..2], .big);
    try testing.expectEqual(@as(u16, 0xABCD), resp_id);
    try testing.expect(response[2] & 0x80 != 0);
}

/// Mock UDP echo server for tests: reads one query, echoes it back with QR bit set.
fn echoServerThread(sock: Io.net.Socket, io: Io) void {
    var recv_buf: [dns.max_udp_payload]u8 = undefined;
    const msg = sock.receiveTimeout(io, &recv_buf, .{ .duration = .{ .raw = .fromMilliseconds(2000), .clock = .awake } }) catch return;
    if (msg.data.len < 2) return;

    var resp: [dns.max_udp_payload]u8 = undefined;
    @memcpy(resp[0..msg.data.len], msg.data);
    resp[2] |= 0x80;
    sock.send(io, &msg.from, resp[0..msg.data.len]) catch return;
}

/// Mock TCP echo server for tests: accepts one connection, reads one
/// length-prefixed DNS query, echoes it back with the QR bit set, closes.
fn tcpEchoServerThread(server: *Io.net.Server, io: Io) void {
    const stream = server.accept(io) catch return;
    defer stream.close(io);
    const handle = stream.socket.handle;

    var len_buf: [2]u8 = undefined;
    var len_filled: usize = 0;
    while (len_filled < 2) {
        const n = sys.netRead(io, handle, len_buf[len_filled..]) catch return;
        if (n == 0) return;
        len_filled += n;
    }
    const body_len = mem.readInt(u16, &len_buf, .big);
    if (body_len < 12 or body_len > dns.edns_udp_payload) return;

    var body_buf: [dns.edns_udp_payload]u8 = undefined;
    var body_filled: usize = 0;
    while (body_filled < body_len) {
        const n = sys.netRead(io, handle, body_buf[body_filled..body_len]) catch return;
        if (n == 0) return;
        body_filled += n;
    }
    body_buf[2] |= 0x80; // QR bit

    var resp: [2 + dns.edns_udp_payload]u8 = undefined;
    mem.writeInt(u16, resp[0..2], body_len, .big);
    @memcpy(resp[2 .. 2 + body_len], body_buf[0..body_len]);

    var sent: usize = 0;
    while (sent < 2 + body_len) {
        const n = sys.netWrite(io, handle, resp[sent .. 2 + body_len]) catch return;
        if (n == 0) return;
        sent += n;
    }
}

test "queryTcp loopback query" {
    try skipIfNotLinux();
    const io = testing.io;

    const listen_addr = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try listen_addr.listen(io, .{ .mode = .stream, .protocol = .tcp });
    defer server.deinit(io);
    const server_addr = server.socket.address;

    const msg = try dns.buildQuery(testing.allocator, 0x1234, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const thread = try std.Thread.spawn(.{}, tcpEchoServerThread, .{ &server, io });

    var response_buf: [dns.edns_udp_payload]u8 = undefined;
    const response = try queryTcp(io, wire_query, server_addr, &response_buf, null);
    thread.join();

    try testing.expect(response.len >= 12);
    const resp_id = mem.readInt(u16, response[0..2], .big);
    try testing.expectEqual(@as(u16, 0x1234), resp_id);
    try testing.expect(response[2] & 0x80 != 0);
}

test "connectTcp leaves SNDTIMEO disarmed for the userspace-deadline data path" {
    // The Do53 TCP data path enforces deadlines in userspace and relies on
    // the kernel timeout being *off*: Io.Threaded's netWritePosix treats
    // EAGAIN as a programmer bug and panics. connectTcpRaw arms SNDTIMEO for
    // the connect itself, so connectTcp must disarm it afterwards.
    //
    // This used to be spelled setSocketTimeout(fd, SNDTIMEO, 0), relying on
    // timeval{0,0} meaning "no timeout"; it is now clearSocketTimeout, since
    // setSocketTimeout floors at 1 ms. Without this test that conversion had
    // no coverage — reverting it broke nothing, while arming a 1 ms write
    // timeout on the data path.
    try skipIfNotLinux();
    const io = testing.io;

    const listen_addr = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try listen_addr.listen(io, .{ .mode = .stream, .protocol = .tcp });
    defer server.deinit(io);

    const stream = try connectTcp(server.socket.address);
    defer sys.close(stream.socket.handle);

    var tv: posix.timeval = undefined;
    var len: posix.socklen_t = @sizeOf(posix.timeval);
    const rc = std.os.linux.getsockopt(stream.socket.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv), &len);
    try testing.expectEqual(@as(std.os.linux.E, .SUCCESS), std.os.linux.errno(rc));
    try testing.expectEqual(@as(@TypeOf(tv.sec), 0), tv.sec);
    try testing.expectEqual(@as(@TypeOf(tv.usec), 0), tv.usec);
}

test "connectTcpRaw surfaces a refused port as ConnectRefused, not ConnectFailed" {
    // The encrypted-NS demotion path hard-bands a refused :853 for an hour
    // and soft-bands a transient failure for 60 s. That split is only
    // possible if the refusal errno survives the connect wrapper instead of
    // collapsing to a generic ConnectFailed.
    try skipIfNotLinux();
    const io = testing.io;

    // Grab an ephemeral port, then close the listener so the port refuses.
    const listen_addr = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try listen_addr.listen(io, .{ .mode = .stream, .protocol = .tcp });
    const refused = server.socket.address;
    server.deinit(io);

    try testing.expectError(error.ConnectRefused, connectTcpRaw(refused, tcp_connect_timeout_ms));
}
