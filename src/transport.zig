const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const EventLoop = @import("event_loop.zig").EventLoop;
const Completion = @import("event_loop.zig").Completion;
const max_operations = @import("event_loop.zig").max_operations;
const BlockingUdpTransport = @import("blocking_transport.zig").BlockingUdpTransport;
const rand = @import("rand.zig");

pub const QueryResult = struct {
    response_data: []const u8,
};

/// Transport-agnostic UDP interface for resolvers.
pub const AnyUdpTransport = union(enum) {
    uring: *UdpTransport,
    blocking: *BlockingUdpTransport,

    pub fn getTimeoutMs(self: AnyUdpTransport) u32 {
        return switch (self) {
            .uring => |t| t.config.timeout_ms,
            .blocking => |t| t.config.timeout_ms,
        };
    }

    pub fn query(self: AnyUdpTransport, wire_query: []const u8, query_id: u16, upstream: std.net.Address) ![]const u8 {
        return switch (self) {
            .uring => |t| t.query(wire_query, query_id, upstream),
            .blocking => |t| t.query(wire_query, query_id, upstream),
        };
    }

    pub fn queryWithTimeout(self: AnyUdpTransport, wire_query: []const u8, query_id: u16, upstream: std.net.Address, timeout_ms: u32) ![]const u8 {
        return switch (self) {
            .uring => |t| t.queryWithTimeout(wire_query, query_id, upstream, timeout_ms),
            .blocking => |t| t.queryWithTimeout(wire_query, query_id, upstream, timeout_ms),
        };
    }
};

pub const Config = struct {
    timeout_ms: u32 = 5000,
    retransmit_ms: u32 = 1000,
    max_retries: u32 = 3,
};

const ContextTag = enum { recv, retransmit, overall };
const Context = struct {
    tag: ContextTag,
};

pub const UdpTransport = struct {
    loop: *EventLoop,
    config: Config,

    pub fn init(loop: *EventLoop, config: Config) !UdpTransport {
        return .{ .loop = loop, .config = config };
    }

    pub fn deinit(self: *UdpTransport) void {
        _ = self;
    }

    /// Create a fresh UDP socket bound to a random ephemeral port (RFC 5452
    /// source-port randomization).  The caller must close the returned fd.
    fn openSocket(dest: std.net.Address) !posix.fd_t {
        return openUdpSocket(dest, true);
    }

    pub fn query(self: *UdpTransport, wire_query: []const u8, query_id: u16, upstream: std.net.Address) ![]const u8 {
        return self.queryWithTimeout(wire_query, query_id, upstream, self.config.timeout_ms);
    }

    /// Like `query`, but with a caller-specified overall timeout in milliseconds.
    pub fn queryWithTimeout(self: *UdpTransport, wire_query: []const u8, query_id: u16, upstream: std.net.Address, timeout_ms: u32) ![]const u8 {
        // Per-query socket for source-port randomization (RFC 5452)
        const sock = try openSocket(upstream);
        errdefer posix.close(sock);

        var recv_ctx = Context{ .tag = .recv };
        var retransmit_ctx = Context{ .tag = .retransmit };
        var overall_ctx = Context{ .tag = .overall };

        // Send initial query
        _ = try self.loop.sendTo(sock, wire_query, upstream, @ptrCast(&recv_ctx));

        // Start recv
        var recv_op = try self.loop.recvFrom(sock, @ptrCast(&recv_ctx));

        // Retransmit interval: 1/3 of overall timeout, at least 50ms
        const retransmit_ms = @max(50, timeout_ms / 3);

        // Start retransmit timer
        var retransmit_op = try self.loop.setTimeout(retransmit_ms, @ptrCast(&retransmit_ctx));

        // Start overall timeout
        const overall_op = try self.loop.setTimeout(timeout_ms, @ptrCast(&overall_ctx));

        var retries_left: u32 = self.config.max_retries;

        while (true) {
            var completions: [max_operations]Completion = undefined;
            const results = try self.loop.tick(&completions);

            for (results) |c| {
                const ctx: *Context = @ptrCast(@alignCast(c.context));
                switch (ctx.tag) {
                    .recv => {
                        switch (c.result) {
                            .recv => |r| {
                                if (r.err != null) continue;
                                // Validate source address matches upstream (RFC 5452)
                                if (!addressMatchesUpstream(r.addr, upstream)) continue;
                                // Check DNS ID matches
                                if (r.data.len >= 2) {
                                    const resp_id = mem.readInt(u16, r.data[0..2], .big);
                                    if (resp_id == query_id) {
                                        // Cancel timers
                                        self.loop.cancel(retransmit_op) catch {};
                                        self.loop.cancel(overall_op) catch {};
                                        // Drain remaining completions
                                        self.drainPending();
                                        posix.close(sock);
                                        return r.data;
                                    }
                                }
                                // Wrong ID — re-queue recv
                                recv_op = try self.loop.recvFrom(sock, @ptrCast(&recv_ctx));
                            },
                            else => {},
                        }
                    },
                    .retransmit => {
                        if (c.result != .timeout) continue;
                        if (!c.result.timeout.expired) continue;
                        if (retries_left == 0) continue;
                        retries_left -= 1;
                        // Retransmit
                        _ = try self.loop.sendTo(sock, wire_query, upstream, @ptrCast(&recv_ctx));
                        // Reset retransmit timer
                        retransmit_op = try self.loop.setTimeout(self.config.retransmit_ms, @ptrCast(&retransmit_ctx));
                    },
                    .overall => {
                        if (c.result != .timeout) continue;
                        if (!c.result.timeout.expired) continue;
                        // Overall timeout — cancel everything and fail
                        self.loop.cancel(recv_op) catch {};
                        self.loop.cancel(retransmit_op) catch {};
                        self.drainPending();
                        return error.Timeout; // errdefer closes sock
                    },
                }
            }
        }
    }

    fn drainPending(self: *UdpTransport) void {
        self.loop.flush();
    }
};

/// Create a UDP socket bound to a random ephemeral port (RFC 5452).
/// Set nonblock=true for io_uring, false for blocking transport.
pub fn openUdpSocket(dest: std.net.Address, nonblock: bool) !posix.fd_t {
    const af: u32 = dest.any.family;
    const flags: u32 = posix.SOCK.DGRAM | if (nonblock) @as(u32, posix.SOCK.NONBLOCK) else 0;
    const sock = try posix.socket(af, flags, 0);
    errdefer posix.close(sock);

    for (0..16) |_| {
        const port = rand.ephemeralPort();
        const addr = anyAddr(af, port);
        posix.bind(sock, &addr.any, addr.getOsSockLen()) catch |err| switch (err) {
            error.AddressInUse => continue,
            else => return err,
        };
        return sock;
    }
    const addr = anyAddr(af, 0);
    try posix.bind(sock, &addr.any, addr.getOsSockLen());
    return sock;
}

pub fn anyAddr(af: u32, port: u16) std.net.Address {
    return if (af == posix.AF.INET6)
        std.net.Address.initIp6(.{0} ** 16, port, 0, 0)
    else
        std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
}

/// Compare two addresses by IP, ignoring port.
pub fn addressMatchesUpstream(response: std.net.Address, upstream: std.net.Address) bool {
    if (response.any.family != upstream.any.family) return false;
    return switch (response.any.family) {
        posix.AF.INET => response.in.sa.addr == upstream.in.sa.addr,
        posix.AF.INET6 => mem.eql(u8, &response.in6.sa.addr, &upstream.in6.sa.addr),
        else => false,
    };
}

// ── Tests ───────────────────────────────────────────────────────────────

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

test "UdpTransport loopback query" {
    try skipIfNotLinux();
    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = try UdpTransport.init(loop, .{});
    defer transport.deinit();

    // Create a mock "server" socket
    const server_sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(server_sock);
    const server_bind = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try posix.bind(server_sock, &server_bind.any, server_bind.getOsSockLen());

    // Get server address
    var server_addr: std.net.Address = undefined;
    var addr_len: posix.socklen_t = @sizeOf(std.net.Address);
    try posix.getsockname(server_sock, @ptrCast(&server_addr), &addr_len);

    // Build a DNS query
    const msg = try dns.buildQuery(testing.allocator, 0x1234, "example.com", .a);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [512]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    // Spawn a "server" thread that reads the query and sends back a response
    const ServerThread = struct {
        fn run(sock: posix.fd_t) void {
            // Poll for data with a timeout
            var polls = [1]std.posix.pollfd{.{
                .fd = sock,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const poll_result = std.posix.poll(&polls, 2000) catch return;
            if (poll_result == 0) return;

            var recv_buf: [512]u8 = undefined;
            var client_addr: std.net.Address = std.mem.zeroes(std.net.Address);
            var client_addr_len: posix.socklen_t = @sizeOf(std.net.Address);
            const n = posix.recvfrom(sock, &recv_buf, 0, @ptrCast(&client_addr), &client_addr_len) catch return;
            if (n < 2) return;

            // Build a simple response: copy the query and set QR bit
            var resp: [512]u8 = undefined;
            @memcpy(resp[0..n], recv_buf[0..n]);
            resp[2] |= 0x80;

            _ = posix.sendto(sock, resp[0..n], 0, @ptrCast(&client_addr), client_addr_len) catch return;
        }
    };

    const thread = try std.Thread.spawn(.{}, ServerThread.run, .{server_sock});

    // Send query via transport
    const response = try transport.query(wire_query, 0x1234, server_addr);
    thread.join();

    // Verify we got a response with matching ID and QR=1
    try testing.expect(response.len >= 12);
    const resp_id = mem.readInt(u16, response[0..2], .big);
    try testing.expectEqual(@as(u16, 0x1234), resp_id);
    try testing.expect(response[2] & 0x80 != 0); // QR bit set
}

test "UdpTransport IPv6 loopback query" {
    try skipIfNotLinux();
    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = try UdpTransport.init(loop, .{});
    defer transport.deinit();

    // Create a mock IPv6 "server" socket
    const server_sock = posix.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0) catch |err| switch (err) {
        error.AddressFamilyNotSupported => return error.SkipZigTest,
        else => return err,
    };
    defer posix.close(server_sock);
    const server_bind = std.net.Address.initIp6(.{0} ** 16, 0, 0, 0);
    try posix.bind(server_sock, &server_bind.any, server_bind.getOsSockLen());

    // Get server address and set to ::1
    var server_addr: std.net.Address = undefined;
    var addr_len: posix.socklen_t = @sizeOf(std.net.Address);
    try posix.getsockname(server_sock, @ptrCast(&server_addr), &addr_len);
    const port = server_addr.getPort();
    server_addr = std.net.Address.initIp6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, port, 0, 0);

    // Build a DNS query
    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .aaaa);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [512]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    // Spawn a "server" thread that reads the query and sends back a response
    const ServerThread = struct {
        fn run(sock: posix.fd_t) void {
            var polls = [1]std.posix.pollfd{.{
                .fd = sock,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const poll_result = std.posix.poll(&polls, 2000) catch return;
            if (poll_result == 0) return;

            var recv_buf: [512]u8 = undefined;
            var client_addr: std.net.Address = std.mem.zeroes(std.net.Address);
            var client_addr_len: posix.socklen_t = @sizeOf(std.net.Address);
            const n = posix.recvfrom(sock, &recv_buf, 0, @ptrCast(&client_addr), &client_addr_len) catch return;
            if (n < 2) return;

            var resp: [512]u8 = undefined;
            @memcpy(resp[0..n], recv_buf[0..n]);
            resp[2] |= 0x80;

            _ = posix.sendto(sock, resp[0..n], 0, @ptrCast(&client_addr), client_addr_len) catch return;
        }
    };

    const thread = try std.Thread.spawn(.{}, ServerThread.run, .{server_sock});

    const response = try transport.query(wire_query, 0xABCD, server_addr);
    thread.join();

    try testing.expect(response.len >= 12);
    const resp_id = mem.readInt(u16, response[0..2], .big);
    try testing.expectEqual(@as(u16, 0xABCD), resp_id);
    try testing.expect(response[2] & 0x80 != 0);
}

test "UdpTransport timeout" {
    try skipIfNotLinux();
    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    // Use very short timeouts for the test
    var transport = try UdpTransport.init(loop, .{
        .timeout_ms = 100,
        .retransmit_ms = 30,
        .max_retries = 1,
    });
    defer transport.deinit();

    // Create a server socket that never responds (black hole)
    const server_sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(server_sock);
    const server_bind = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try posix.bind(server_sock, &server_bind.any, server_bind.getOsSockLen());

    var server_addr: std.net.Address = undefined;
    var addr_len: posix.socklen_t = @sizeOf(std.net.Address);
    try posix.getsockname(server_sock, @ptrCast(&server_addr), &addr_len);

    const msg = try dns.buildQuery(testing.allocator, 0x5678, "timeout.test", .a);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [512]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const result = transport.query(wire_query, 0x5678, server_addr);
    try testing.expectError(error.Timeout, result);
}
