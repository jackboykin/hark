const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const openUdpSocket = @import("transport.zig").openUdpSocket;
const monotonic = @import("monotonic.zig");
const AddressKey = @import("connection_pool.zig").AddressKey;
const TcpConnectionPool = @import("connection_pool.zig").TcpConnectionPool;
const TcpPooledConnection = @import("connection_pool.zig").TcpPooledConnection;
const na = @import("net_address.zig");
const sys = @import("sys.zig");

pub const Config = struct {
    timeout_ms: u32 = 5000,
    retransmit_count: u32 = 2,
};

/// UDP transport using blocking sockets for thread-pool resolution.
///
/// `queryWithTimeout` uses per-thread persistent unconnected sockets (one per
/// address family) bound to a random ephemeral port. Source-port randomness
/// (RFC 5452 §9.1) is preserved by rebinding every `rebind_after_queries`
/// queries. The `queryStaggered` path still opens short-lived connected
/// sockets per call — racing two responses on one shared socket is doable
/// but needs more care, and the staggered path only fires when
/// `stagger_ms > 0` and 2+ NS are available.
pub const BlockingUdpTransport = struct {
    config: Config,
    io: std.Io,
    response_buf: [4096]u8 = undefined,
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

    pub fn query(self: *BlockingUdpTransport, wire_query: []const u8, query_id: u16, upstream: na.Address) ![]const u8 {
        return self.queryWithTimeout(wire_query, query_id, upstream, self.config.timeout_ms);
    }

    pub fn queryWithTimeout(self: *BlockingUdpTransport, wire_query: []const u8, query_id: u16, upstream: na.Address, timeout_ms: u32) ![]const u8 {
        const sock = try self.persistentSocket(upstream);

        // Retransmit interval: 1/3 of overall timeout, at least 50ms
        const retransmit_ms = @max(50, timeout_ms / 3);
        setRcvTimeoIfChanged(sock, retransmit_ms);

        var upstream_sa: na.PosixAddress = undefined;
        const upstream_sa_len = na.toSockaddr(&upstream, &upstream_sa);

        _ = sys.sendto(sock.fd, wire_query, 0, &upstream_sa.any, upstream_sa_len) catch return error.Timeout;

        const deadline_ns = monotonic.nowNs() + @as(i128, timeout_ms) * 1_000_000;
        var retransmits_left: u32 = self.config.retransmit_count;

        while (true) {
            const remaining_ns = deadline_ns - monotonic.nowNs();
            if (remaining_ns <= 0) return error.Timeout;

            var src_sa: na.PosixAddress = undefined;
            var src_sa_len: posix.socklen_t = @sizeOf(na.PosixAddress);
            const n = sys.recvfrom(sock.fd, &self.response_buf, 0, @ptrCast(&src_sa), &src_sa_len) catch |err| switch (err) {
                error.WouldBlock => {
                    // Timeout on recv — retransmit or fail.
                    if (retransmits_left == 0) return error.Timeout;
                    retransmits_left -= 1;
                    _ = sys.sendto(sock.fd, wire_query, 0, &upstream_sa.any, upstream_sa_len) catch return error.Timeout;

                    const remain_ms = @as(u32, @intCast(@min(
                        @divFloor(remaining_ns, 1_000_000),
                        retransmit_ms,
                    )));
                    if (remain_ms == 0) return error.Timeout;
                    setRcvTimeoIfChanged(sock, remain_ms);
                    continue;
                },
                else => return error.Timeout,
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

            const resp_id = mem.readInt(u16, self.response_buf[0..2], .big);
            if (resp_id == query_id) {
                return self.response_buf[0..n];
            }
            // Wrong ID — keep waiting.
        }
    }

    pub const StaggeredResult = struct {
        response_data: []const u8,
        responding_idx: u8,
    };

    /// Send a query to two nameservers with staggered timing, take first valid response.
    /// Each leg uses a connected UDP socket with unique source port (RFC 5452 §9.1).
    /// Only races queries to different server IPs — birthday attack surface is not amplified
    /// because each leg targets a different destination.
    pub fn queryStaggered(
        self: *BlockingUdpTransport,
        wire_queries: [2][]const u8,
        query_ids: [2]u16,
        servers: [2]na.Address,
        stagger_ms: u32,
        overall_timeout_ms: u32,
    ) !StaggeredResult {
        // Open and connect socket for server[0]
        const sock0 = try self.openSocket(servers[0]);
        defer sys.close(sock0);
        na.connectTo(sock0, &servers[0]) catch return error.Timeout;
        _ = sys.send(sock0, wire_queries[0], 0) catch return error.Timeout;

        const deadline_ns = monotonic.nowNs() + @as(i128, overall_timeout_ms) * 1_000_000;

        // Phase 1: wait stagger_ms for server[0]
        {
            const wait_ms: i32 = @intCast(@min(stagger_ms, overall_timeout_ms));
            var polls = [1]posix.pollfd{.{ .fd = sock0, .events = posix.POLL.IN, .revents = 0 }};
            const n = posix.poll(&polls, wait_ms) catch 0;
            if (n > 0) {
                if (polls[0].revents & posix.POLL.IN != 0) {
                    if (self.tryRecv(sock0, query_ids[0])) |len| {
                        return .{ .response_data = self.response_buf[0..len], .responding_idx = 0 };
                    }
                }
            }
        }

        // Phase 2: server[0] didn't respond in stagger window — also query server[1]
        const remaining_ns = deadline_ns - monotonic.nowNs();
        if (remaining_ns <= 0) return error.Timeout;

        const sock1 = try self.openSocket(servers[1]);
        defer sys.close(sock1);
        na.connectTo(sock1, &servers[1]) catch return error.Timeout;
        _ = sys.send(sock1, wire_queries[1], 0) catch return error.Timeout;

        // Phase 3: poll both sockets for remaining time
        while (true) {
            const remain_ns = deadline_ns - monotonic.nowNs();
            if (remain_ns <= 0) return error.Timeout;
            const remain_ms: i32 = @intCast(@min(@divFloor(remain_ns, 1_000_000), std.math.maxInt(i32)));
            if (remain_ms <= 0) return error.Timeout;

            var polls = [2]posix.pollfd{
                .{ .fd = sock0, .events = posix.POLL.IN, .revents = 0 },
                .{ .fd = sock1, .events = posix.POLL.IN, .revents = 0 },
            };
            const n = posix.poll(&polls, remain_ms) catch return error.Timeout;
            if (n == 0) return error.Timeout;

            // Check both — prefer whichever has data
            if (polls[0].revents & posix.POLL.IN != 0) {
                if (self.tryRecv(sock0, query_ids[0])) |len| {
                    return .{ .response_data = self.response_buf[0..len], .responding_idx = 0 };
                }
            }
            if (polls[1].revents & posix.POLL.IN != 0) {
                if (self.tryRecv(sock1, query_ids[1])) |len| {
                    return .{ .response_data = self.response_buf[0..len], .responding_idx = 1 };
                }
            }
            // POLLERR/POLLHUP — keep polling until timeout
        }
    }

    /// Try to receive a valid DNS response. Returns byte count or null.
    fn tryRecv(self: *BlockingUdpTransport, sock: posix.fd_t, expected_id: u16) ?usize {
        const n = sys.recv(sock, &self.response_buf, posix.MSG.DONTWAIT) catch return null;
        if (n < 2) return null;
        const resp_id = mem.readInt(u16, self.response_buf[0..2], .big);
        if (resp_id != expected_id) return null;
        return n;
    }

    fn openSocket(self: *BlockingUdpTransport, dest: na.Address) !posix.fd_t {
        return openUdpSocket(dest, self.io);
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

    pub fn query(self: *BlockingTcpTransport, wire_query: []const u8, server: na.Address, response_buf: []u8) ![]const u8 {
        const sock = try self.connectTcp(server);
        defer sys.close(sock);
        const deadline_ns = monotonic.nowNs() + @as(i128, self.config.response_timeout_ms) * 1_000_000;
        return sendAndReceiveTcp(sock, wire_query, response_buf, deadline_ns);
    }

    /// Query with TCP connection pooling. Tries a pooled connection first,
    /// falls back to a fresh connection, and stores it for reuse on success.
    pub fn queryPooled(self: *BlockingTcpTransport, wire_query: []const u8, server: na.Address, response_buf: []u8, pool: *TcpConnectionPool) ![]const u8 {
        const key = AddressKey.fromAddress(server);
        const deadline_ns = monotonic.nowNs() + @as(i128, self.config.response_timeout_ms) * 1_000_000;

        // Try pooled connection
        if (pool.acquire(key)) |conn| {
            if (sendAndReceiveTcp(conn.sock, wire_query, response_buf, deadline_ns)) |data| {
                pool.release(key, conn, true);
                return data;
            } else |_| {
                pool.release(key, conn, false);
            }
        }

        // Fresh connection
        const sock = try self.connectTcp(server);
        const data = sendAndReceiveTcp(sock, wire_query, response_buf, deadline_ns) catch |err| {
            sys.close(sock);
            return err;
        };

        // Store in pool for reuse
        const new_conn = pool.allocator.create(TcpPooledConnection) catch {
            sys.close(sock);
            return data;
        };
        new_conn.* = .{ .sock = sock, .last_used = undefined, .query_count = undefined };
        pool.store(key, new_conn);
        return data;
    }

    fn connectTcp(self: *BlockingTcpTransport, server: na.Address) !posix.fd_t {
        const af: u32 = na.afU32(server);
        const sock = try sys.socket(af, posix.SOCK.STREAM, 0);
        errdefer sys.close(sock);
        sys.setSocketTimeout(sock, posix.SO.SNDTIMEO, self.config.connect_timeout_ms);
        na.connectTo(sock, &server) catch return error.ConnectFailed;
        return sock;
    }

    /// Send a length-prefixed DNS query and receive the response on an
    /// already-connected TCP socket, enforcing an absolute deadline.
    fn sendAndReceiveTcp(sock: posix.fd_t, wire_query: []const u8, response_buf: []u8, deadline_ns: i128) ![]const u8 {
        // ── Send length-prefixed query ──
        var send_buf: [2 + dns.edns_udp_payload]u8 = undefined;
        if (wire_query.len > dns.edns_udp_payload) return error.QueryTooLarge;
        const msg_len: u16 = @intCast(wire_query.len);
        mem.writeInt(u16, send_buf[0..2], msg_len, .big);
        @memcpy(send_buf[2..][0..wire_query.len], wire_query);
        const total_send = 2 + wire_query.len;

        var bytes_sent: usize = 0;
        while (bytes_sent < total_send) {
            try sys.updateTimeout(sock, posix.SO.SNDTIMEO, deadline_ns);
            const n = sys.write(sock, send_buf[bytes_sent..total_send]) catch return error.SendFailed;
            if (n == 0) return error.SendFailed;
            bytes_sent += n;
        }

        // ── Receive length-prefixed response ──
        var len_buf: [2]u8 = undefined;
        var len_filled: usize = 0;

        while (len_filled < 2) {
            try sys.updateTimeout(sock, posix.SO.RCVTIMEO, deadline_ns);
            const n = sys.read(sock, len_buf[len_filled..]) catch return error.ConnectionClosed;
            if (n == 0) return error.ConnectionClosed;
            len_filled += n;
        }

        const body_len = mem.readInt(u16, &len_buf, .big);
        if (body_len == 0 or body_len > response_buf.len) return error.InvalidLength;

        var body_filled: usize = 0;
        while (body_filled < body_len) {
            try sys.updateTimeout(sock, posix.SO.RCVTIMEO, deadline_ns);
            const n = sys.read(sock, response_buf[body_filled..body_len]) catch return error.ConnectionClosed;
            if (n == 0) return error.ConnectionClosed;
            body_filled += n;
        }

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
    const msg = try dns.buildQuery(testing.allocator, 0x1234, "example.com", .a);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [512]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const thread = try std.Thread.spawn(.{}, echoServerThread, .{server_sock});

    const response = try transport.query(wire_query, 0x1234, server_addr);
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

    const msg = try dns.buildQuery(testing.allocator, 0x5678, "timeout.test", .a);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [512]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const result = transport.query(wire_query, 0x5678, server_addr);
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

    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .aaaa);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [512]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const thread = try std.Thread.spawn(.{}, echoServerThread, .{server_sock});

    const response = try transport.query(wire_query, 0xABCD, server_addr);
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

    var recv_buf: [512]u8 = undefined;
    var client_addr: na.PosixAddress = std.mem.zeroes(na.PosixAddress);
    var client_addr_len: posix.socklen_t = @sizeOf(na.PosixAddress);
    const n = sys.recvfrom(sock, &recv_buf, 0, @ptrCast(&client_addr), &client_addr_len) catch return;
    if (n < 2) return;

    var resp: [512]u8 = undefined;
    @memcpy(resp[0..n], recv_buf[0..n]);
    resp[2] |= 0x80;
    _ = sys.sendto(sock, resp[0..n], 0, @ptrCast(&client_addr), client_addr_len) catch return;
}
