const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const EventLoop = @import("event_loop.zig").EventLoop;
const Completion = @import("event_loop.zig").Completion;
const max_operations = @import("event_loop.zig").max_operations;

pub const QueryResult = struct {
    response_data: []const u8,
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
    sock: posix.fd_t,
    config: Config,

    pub fn init(loop: *EventLoop, config: Config) !UdpTransport {
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(sock);

        const bind_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
        try posix.bind(sock, &bind_addr.any, bind_addr.getOsSockLen());

        return .{ .loop = loop, .sock = sock, .config = config };
    }

    pub fn deinit(self: *UdpTransport) void {
        posix.close(self.sock);
    }

    pub fn query(self: *UdpTransport, wire_query: []const u8, query_id: u16, upstream: std.net.Address) ![]const u8 {
        var recv_ctx = Context{ .tag = .recv };
        var retransmit_ctx = Context{ .tag = .retransmit };
        var overall_ctx = Context{ .tag = .overall };

        // Send initial query
        _ = try self.loop.sendTo(self.sock, wire_query, upstream, @ptrCast(&recv_ctx));

        // Start recv
        var recv_op = try self.loop.recvFrom(self.sock, @ptrCast(&recv_ctx));

        // Start retransmit timer
        var retransmit_op = try self.loop.setTimeout(self.config.retransmit_ms, @ptrCast(&retransmit_ctx));

        // Start overall timeout
        const overall_op = try self.loop.setTimeout(self.config.timeout_ms, @ptrCast(&overall_ctx));

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
                                // Check DNS ID matches
                                if (r.data.len >= 2) {
                                    const resp_id = mem.readInt(u16, r.data[0..2], .big);
                                    if (resp_id == query_id) {
                                        // Cancel timers
                                        self.loop.cancel(retransmit_op) catch {};
                                        self.loop.cancel(overall_op) catch {};
                                        // Drain remaining completions
                                        self.drainPending();
                                        return r.data;
                                    }
                                }
                                // Wrong ID — re-queue recv
                                recv_op = try self.loop.recvFrom(self.sock, @ptrCast(&recv_ctx));
                            },
                            .send => {},
                            .timeout => {},
                        }
                    },
                    .retransmit => {
                        if (c.result != .timeout) continue;
                        if (!c.result.timeout.expired) continue;
                        if (retries_left == 0) continue;
                        retries_left -= 1;
                        // Retransmit
                        _ = try self.loop.sendTo(self.sock, wire_query, upstream, @ptrCast(&recv_ctx));
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
                        return error.Timeout;
                    },
                }
            }
        }
    }

    fn drainPending(self: *UdpTransport) void {
        self.loop.flush();
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

test "UdpTransport loopback query" {
    try skipIfNotLinux();
    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
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

test "UdpTransport timeout" {
    try skipIfNotLinux();
    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
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
