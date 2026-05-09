const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const rand = @import("rand.zig");
const monotonic = @import("monotonic.zig");
const TcpConnectionPool = @import("connection_pool.zig").TcpConnectionPool;
const TcpPooledConnection = @import("connection_pool.zig").TcpPooledConnection;
const na = @import("net_address.zig");
const AddressKey = na.AddressKey;
const sys = @import("sys.zig");

pub const Config = struct {
    timeout_ms: u32 = 5000,
    retransmit_count: u32 = 2,
};

/// Map a UDP-send syscall error to a transport-level error. WouldBlock from
/// SO_SNDTIMEO means the kernel send buffer stayed jammed past the deadline;
/// kernel-async ICMP unreachable surfaces here too. MessageTooBig means our
/// serialized query exceeded path MTU — should not happen under normal EDNS
/// limits, so a distinct variant lets it stand out in logs.
fn mapUdpSendErr(err: anyerror) error{ Timeout, PeerUnreachable, MessageTooBig, SendFailed } {
    return switch (err) {
        error.WouldBlock => error.Timeout,
        error.ConnectionRefused => error.PeerUnreachable,
        error.MessageTooBig => error.MessageTooBig,
        else => error.SendFailed,
    };
}

/// Create a UDP socket bound to a random ephemeral port (RFC 5452).
fn openUdpSocket(dest: na.Address, io: std.Io) !posix.fd_t {
    const af: u32 = na.afU32(dest);
    const sock = try sys.socket(af, posix.SOCK.DGRAM, 0);
    errdefer sys.close(sock);

    for (0..64) |_| {
        const port = rand.ephemeralPort(io);
        const addr = if (af == posix.AF.INET6)
            na.initIp6(.{0} ** 16, port, 0, 0)
        else
            na.initIp4(.{ 0, 0, 0, 0 }, port);
        na.bindTo(sock, &addr) catch |err| switch (err) {
            error.AddressInUse => continue,
            else => return err,
        };
        return sock;
    }
    return error.AddressInUse;
}

/// Blocking UDP transport. Per-thread persistent unconnected sockets per
/// address family, rebound every `rebind_after_queries` to refresh source-port
/// randomness (RFC 5452 §9.1). The staggered path uses short-lived connected
/// sockets per leg.
pub const BlockingUdpTransport = struct {
    config: Config,
    io: std.Io,
    sock_v4: ?posix.fd_t = null,
    sock_v6: ?posix.fd_t = null,
    v4_queries: u32 = 0,
    v6_queries: u32 = 0,
    // 0 means "unknown" — forces the next setsockopt through.
    last_rcvtimeo_v4_ms: u32 = 0,
    last_rcvtimeo_v6_ms: u32 = 0,

    /// Rotate the persistent socket every N queries for defense-in-depth:
    /// rebinding picks a fresh random source port, re-randomizing the
    /// RFC 5452 entropy. 4096 is small enough that an attacker guessing
    /// source-port+query-id has a narrow window per binding.
    const rebind_after_queries: u32 = 4096;

    pub fn init(config: Config, io: std.Io) BlockingUdpTransport {
        return .{ .config = config, .io = io };
    }

    pub fn deinit(self: *BlockingUdpTransport) void {
        if (self.sock_v4) |fd| sys.close(fd);
        if (self.sock_v6) |fd| sys.close(fd);
        self.sock_v4 = null;
        self.sock_v6 = null;
        self.last_rcvtimeo_v4_ms = 0;
        self.last_rcvtimeo_v6_ms = 0;
    }

    const PersistentSocket = struct {
        fd: posix.fd_t,
        last_rcvtimeo_ms: *u32,
    };

    fn persistentSocket(self: *BlockingUdpTransport, dest: na.Address) !PersistentSocket {
        const sock_ref, const counter_ref, const timeo_ref = switch (dest) {
            .ip4 => .{ &self.sock_v4, &self.v4_queries, &self.last_rcvtimeo_v4_ms },
            .ip6 => .{ &self.sock_v6, &self.v6_queries, &self.last_rcvtimeo_v6_ms },
        };
        if (sock_ref.* != null and counter_ref.* >= rebind_after_queries) {
            sys.close(sock_ref.*.?);
            sock_ref.* = null;
            counter_ref.* = 0;
            timeo_ref.* = 0;
        }
        if (sock_ref.* == null) {
            sock_ref.* = try openUdpSocket(dest, self.io);
            timeo_ref.* = 0;
        }
        counter_ref.* += 1;
        return .{ .fd = sock_ref.*.?, .last_rcvtimeo_ms = timeo_ref };
    }

    fn setRcvTimeoIfChanged(sock: PersistentSocket, ms: u32) void {
        if (sock.last_rcvtimeo_ms.* == ms) return;
        sys.setSocketTimeout(sock.fd, posix.SO.RCVTIMEO, ms);
        sock.last_rcvtimeo_ms.* = ms;
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

        // Retransmit interval: 1/3 of overall timeout, at least 50ms
        const retransmit_ms = @max(50, timeout_ms / 3);
        setRcvTimeoIfChanged(sock, retransmit_ms);

        var upstream_sa: na.PosixAddress = undefined;
        const upstream_sa_len = na.toSockaddr(&upstream, &upstream_sa);

        _ = sys.sendto(sock.fd, wire_query, 0, &upstream_sa.any, upstream_sa_len) catch |err| return mapUdpSendErr(err);

        const deadline_ns = monotonic.nowNs() + @as(i128, timeout_ms) * 1_000_000;
        var retransmits_left: u32 = self.config.retransmit_count;

        while (true) {
            const remaining_ns = deadline_ns - monotonic.nowNs();
            if (remaining_ns <= 0) return error.Timeout;

            var src_sa: na.PosixAddress = undefined;
            var src_sa_len: posix.socklen_t = @sizeOf(na.PosixAddress);
            const n = sys.recvfrom(sock.fd, response_buf, 0, @ptrCast(&src_sa), &src_sa_len) catch |err| switch (err) {
                error.WouldBlock => {
                    // Timeout on recv — retransmit or fail.
                    if (retransmits_left == 0) return error.Timeout;
                    retransmits_left -= 1;
                    _ = sys.sendto(sock.fd, wire_query, 0, &upstream_sa.any, upstream_sa_len) catch |e| return mapUdpSendErr(e);

                    const remain_ms = @as(u32, @intCast(@min(
                        @divFloor(remaining_ns, 1_000_000),
                        retransmit_ms,
                    )));
                    if (remain_ms == 0) return error.Timeout;
                    setRcvTimeoIfChanged(sock, remain_ms);
                    continue;
                },
                error.ConnectionRefused => return error.PeerUnreachable,
                else => return error.RecvFailed,
            };

            if (n < 2) continue;

            // Userspace source check: the persistent socket is unconnected so
            // it can receive responses addressed to any peer. Require full
            // (IP, port) match to mirror the 4-tuple enforcement a connected
            // socket would get from the kernel — off-path attackers spoofing
            // the upstream IP with a random source port are otherwise
            // accepted at this layer (RFC 5452 §9.2 assumes 5-tuple).
            const src_addr = na.fromSockaddr(&src_sa);
            if (!src_addr.eql(&upstream)) continue;

            const resp_id = mem.readInt(u16, response_buf[0..2], .big);
            if (resp_id == query_id) {
                return response_buf[0..n];
            }
            // Wrong ID — keep waiting.
        }
    }

    pub const StaggeredResult = struct {
        response_data: []const u8,
        responding_idx: u8,
    };

    /// Bounds stack-allocated pollfd + socket arrays in `queryStaggered`.
    /// Must be >= any caller's effective cap.
    pub const max_staggered_legs = 4;

    /// Race up to `max_staggered_legs` nameservers; return the first valid
    /// response. Each leg gets a connected UDP socket with a unique random
    /// source port (RFC 5452 §9.1). Callers must pass distinct destination IPs
    /// — racing the same IP would not increase birthday entropy.
    ///
    /// `wire_queries`, `query_ids`, `servers` must be parallel arrays of length
    /// 2..`max_staggered_legs`. Leg `i` launches at `query_start + i*stagger_ms`
    /// unless an earlier leg responds first. `response_buf` lifetime: see
    /// queryWithTimeout.
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

        var socks: [max_staggered_legs]posix.fd_t = undefined;
        var sock_count: usize = 0;
        defer for (socks[0..sock_count]) |fd| sys.close(fd);

        const deadline_ns = monotonic.nowNs() + @as(i128, overall_timeout_ms) * 1_000_000;
        const stagger_ns: i128 = @as(i128, stagger_ms) * 1_000_000;

        // Launch leg 0 synchronously so the caller sees connect/send errors
        // immediately rather than spinning in the poll loop.
        const s0 = try openUdpSocket(servers[0], self.io);
        socks[0] = s0;
        sock_count = 1;
        na.connectTo(s0, &servers[0]) catch return error.SendFailed;
        _ = sys.send(s0, wire_queries[0], 0) catch |err| return mapUdpSendErr(err);
        var next_launch_ns: i128 = monotonic.nowNs() + stagger_ns;

        while (true) {
            const now_ns = monotonic.nowNs();
            if (now_ns >= deadline_ns) return error.Timeout;

            // Fire any legs whose stagger interval has elapsed.
            while (sock_count < leg_n and now_ns >= next_launch_ns) {
                const idx = sock_count;
                const fd = openUdpSocket(servers[idx], self.io) catch {
                    // Out of ephemeral ports / fd budget: stop trying to fan
                    // out, keep polling the legs already in flight.
                    next_launch_ns = deadline_ns;
                    break;
                };
                socks[idx] = fd;
                sock_count += 1;
                na.connectTo(fd, &servers[idx]) catch {
                    next_launch_ns = deadline_ns;
                    break;
                };
                _ = sys.send(fd, wire_queries[idx], 0) catch {
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
                polls[i] = .{ .fd = socks[i], .events = posix.POLL.IN, .revents = 0 };
            }
            const n = posix.poll(polls[0..sock_count], wait_ms) catch 0;
            if (n == 0) continue; // next launch fires, or overall deadline expires

            for (0..sock_count) |i| {
                if (polls[i].revents & posix.POLL.IN != 0) {
                    if (tryRecv(socks[i], query_ids[i], response_buf)) |len| {
                        return .{ .response_data = response_buf[0..len], .responding_idx = @intCast(i) };
                    }
                }
            }
            // All readable sockets had unparseable/wrong-id packets; keep polling.
        }
    }

    /// Try to receive a valid DNS response. Returns byte count or null.
    fn tryRecv(sock: posix.fd_t, expected_id: u16, response_buf: []u8) ?usize {
        const n = sys.recv(sock, response_buf, posix.MSG.DONTWAIT) catch return null;
        if (n < 2) return null;
        const resp_id = mem.readInt(u16, response_buf[0..2], .big);
        if (resp_id != expected_id) return null;
        return n;
    }
};

pub const TcpConfig = struct {
    connect_timeout_ms: u32 = 5000,
    response_timeout_ms: u32 = 10000,
};

/// TCP transport using blocking sockets for thread-pool resolution.
/// Tracks total deadline to mitigate slow-trickle attacks where an
/// attacker sends one byte at a time to reset per-recv SO_RCVTIMEO.
pub const BlockingTcpTransport = struct {
    config: TcpConfig,

    pub fn init(config: TcpConfig) BlockingTcpTransport {
        return .{ .config = config };
    }

    /// Send a DNS query over TCP. With pool != null, tries an idle pooled
    /// connection first and stores a fresh one on success. Mirrors
    /// TlsTransport.query's optional-pool shape.
    pub fn query(
        self: *BlockingTcpTransport,
        wire_query: []const u8,
        server: na.Address,
        response_buf: []u8,
        pool: ?*TcpConnectionPool,
    ) ![]const u8 {
        const deadline_ns = monotonic.nowNs() + @as(i128, self.config.response_timeout_ms) * 1_000_000;

        if (pool) |p| {
            const key = AddressKey.fromAddress(server);
            if (p.acquire(key)) |conn| {
                if (sendAndReceiveTcp(conn.sock, wire_query, response_buf, deadline_ns)) |data| {
                    p.release(key, conn, true);
                    return data;
                } else |_| {
                    p.release(key, conn, false);
                }
            }
        }

        const sock = try self.connectTcp(server);
        const data = sendAndReceiveTcp(sock, wire_query, response_buf, deadline_ns) catch |err| {
            sys.close(sock);
            return err;
        };

        if (pool) |p| {
            const key = AddressKey.fromAddress(server);
            const new_conn = p.allocator.create(TcpPooledConnection) catch {
                // Pool out of memory — close the socket since no one will own it.
                sys.close(sock);
                return data;
            };
            new_conn.* = .{ .sock = sock, .last_used = undefined, .query_count = undefined };
            p.store(key, new_conn);
            return data;
        }

        sys.close(sock);
        return data;
    }

    fn connectTcp(self: *BlockingTcpTransport, server: na.Address) !posix.fd_t {
        const af: u32 = na.afU32(server);
        const sock = try sys.socket(af, posix.SOCK.STREAM, 0);
        errdefer sys.close(sock);
        sys.setSocketTimeout(sock, posix.SO.SNDTIMEO, self.config.connect_timeout_ms);
        sys.setNoDelay(sock);
        na.connectTo(sock, &server) catch return error.ConnectFailed;
        return sock;
    }

    /// Length-prefixed DNS query/response on a connected TCP socket. The
    /// per-syscall SO_*TIMEO is the remaining deadline; the userspace check
    /// before each read/write enforces the total deadline (slow-trickle).
    fn sendAndReceiveTcp(sock: posix.fd_t, wire_query: []const u8, response_buf: []u8, deadline_ns: i128) ![]const u8 {
        try sys.updateTimeout(sock, posix.SO.SNDTIMEO, deadline_ns);
        try sys.updateTimeout(sock, posix.SO.RCVTIMEO, deadline_ns);

        // ── Send length-prefixed query ──
        var send_buf: [2 + dns.edns_udp_payload]u8 = undefined;
        const framed = try dns.stageLengthPrefixed(&send_buf, wire_query);

        var bytes_sent: usize = 0;
        while (bytes_sent < framed.len) {
            if (monotonic.nowNs() >= deadline_ns) return error.Timeout;
            const n = sys.write(sock, framed[bytes_sent..]) catch return error.SendFailed;
            if (n == 0) return error.SendFailed;
            bytes_sent += n;
        }

        // ── Receive length-prefixed response ──
        var len_buf: [2]u8 = undefined;
        var len_filled: usize = 0;

        while (len_filled < 2) {
            if (monotonic.nowNs() >= deadline_ns) return error.Timeout;
            const n = sys.read(sock, len_buf[len_filled..]) catch return error.ConnectionClosed;
            if (n == 0) return error.ConnectionClosed;
            len_filled += n;
        }

        const body_len = mem.readInt(u16, &len_buf, .big);
        if (body_len == 0 or body_len > response_buf.len) return error.InvalidLength;

        var body_filled: usize = 0;
        while (body_filled < body_len) {
            if (monotonic.nowNs() >= deadline_ns) return error.Timeout;
            const n = sys.read(sock, response_buf[body_filled..body_len]) catch return error.ConnectionClosed;
            if (n == 0) return error.ConnectionClosed;
            body_filled += n;
        }

        sys.setQuickAck(sock);
        return response_buf[0..body_len];
    }
};

// ── Tests ────────────────────────────────────────────────────────────────

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

test "BlockingUdpTransport loopback query" {
    try skipIfNotLinux();
    const io = testing.io;

    var transport = BlockingUdpTransport.init(.{ .timeout_ms = 2000 }, io);

    // Create a mock "server" socket
    const server_sock = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer sys.close(server_sock);
    const server_bind = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    var bind_storage: na.PosixAddress = undefined;
    const bind_len = na.toSockaddr(&server_bind, &bind_storage);
    try sys.bind(server_sock, &bind_storage.any, bind_len);

    // Get server address
    const server_addr = try na.getSockName(server_sock);

    // Build a DNS query
    const msg = try dns.buildQuery(testing.allocator, 0x1234, "example.com", .a, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const thread = try std.Thread.spawn(.{}, echoServerThread, .{server_sock});

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

    // Create a server socket that never responds (black hole)
    const server_sock = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer sys.close(server_sock);
    const server_bind = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    var bind_storage: na.PosixAddress = undefined;
    const bind_len = na.toSockaddr(&server_bind, &bind_storage);
    try sys.bind(server_sock, &bind_storage.any, bind_len);

    const server_addr = try na.getSockName(server_sock);

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

    const server_sock = sys.socket(posix.AF.INET6, posix.SOCK.DGRAM, 0) catch |err| switch (err) {
        error.AddressFamilyNotSupported => return error.SkipZigTest,
        else => return err,
    };
    defer sys.close(server_sock);
    const server_bind = na.initIp6(.{0} ** 16, 0, 0, 0);
    var bind_storage: na.PosixAddress = undefined;
    const bind_len = na.toSockaddr(&server_bind, &bind_storage);
    try sys.bind(server_sock, &bind_storage.any, bind_len);

    const port = (try na.getSockName(server_sock)).getPort();
    const server_addr = na.initIp6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, port, 0, 0);

    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .aaaa, .{});
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const thread = try std.Thread.spawn(.{}, echoServerThread, .{server_sock});

    var response_buf: [dns.edns_udp_payload]u8 = undefined;
    const response = try transport.query(wire_query, 0xABCD, server_addr, &response_buf);
    thread.join();

    try testing.expect(response.len >= 12);
    const resp_id = mem.readInt(u16, response[0..2], .big);
    try testing.expectEqual(@as(u16, 0xABCD), resp_id);
    try testing.expect(response[2] & 0x80 != 0);
}

/// Mock UDP echo server for tests: reads one query, echoes it back with QR bit set.
fn echoServerThread(sock: posix.fd_t) void {
    var polls = [1]posix.pollfd{.{ .fd = sock, .events = posix.POLL.IN, .revents = 0 }};
    const poll_result = posix.poll(&polls, 2000) catch return;
    if (poll_result == 0) return;

    var recv_buf: [dns.max_udp_payload]u8 = undefined;
    var client_addr: na.PosixAddress = std.mem.zeroes(na.PosixAddress);
    var client_addr_len: posix.socklen_t = @sizeOf(na.PosixAddress);
    const n = sys.recvfrom(sock, &recv_buf, 0, @ptrCast(&client_addr), &client_addr_len) catch return;
    if (n < 2) return;

    var resp: [dns.max_udp_payload]u8 = undefined;
    @memcpy(resp[0..n], recv_buf[0..n]);
    resp[2] |= 0x80;
    _ = sys.sendto(sock, resp[0..n], 0, @ptrCast(&client_addr), client_addr_len) catch return;
}
