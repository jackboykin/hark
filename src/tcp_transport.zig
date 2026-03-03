const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const EventLoop = @import("event_loop.zig").EventLoop;
const Completion = @import("event_loop.zig").Completion;
const max_operations = @import("event_loop.zig").max_operations;

pub const TcpConfig = struct {
    connect_timeout_ms: u32 = 5000,
    response_timeout_ms: u32 = 10000,
};

const Tag = enum { connect, timeout, send, recv };
const Ctx = struct { tag: Tag };

pub const TcpTransport = struct {
    loop: *EventLoop,
    config: TcpConfig,

    pub fn init(loop: *EventLoop, config: TcpConfig) TcpTransport {
        return .{ .loop = loop, .config = config };
    }

    pub fn query(self: *TcpTransport, wire_query: []const u8, server: std.net.Address, response_buf: []u8) ![]const u8 {
        // Create TCP socket matching server address family
        const af: u32 = if (server.any.family == posix.AF.INET6) posix.AF.INET6 else posix.AF.INET;
        const sock = try posix.socket(af, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        defer posix.close(sock);

        var connect_ctx = Ctx{ .tag = .connect };
        var timeout_ctx = Ctx{ .tag = .timeout };
        var send_ctx = Ctx{ .tag = .send };
        var recv_ctx = Ctx{ .tag = .recv };

        // ── Phase 1: Connect ──
        const connect_op = try self.loop.connect(sock, server, @ptrCast(&connect_ctx));
        var timeout_op = try self.loop.setTimeout(self.config.connect_timeout_ms, @ptrCast(&timeout_ctx));

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
                    else => {},
                }
            }
        }

        // ── Phase 2: Send length-prefixed query ──
        var send_buf: [2 + dns.max_udp_payload]u8 = undefined;
        if (wire_query.len > dns.max_udp_payload) return error.QueryTooLarge;
        const msg_len: u16 = @intCast(wire_query.len);
        mem.writeInt(u16, send_buf[0..2], msg_len, .big);
        @memcpy(send_buf[2..][0..wire_query.len], wire_query);
        const total_send = 2 + wire_query.len;

        timeout_op = try self.loop.setTimeout(self.config.response_timeout_ms, @ptrCast(&timeout_ctx));
        var bytes_sent: usize = 0;

        while (bytes_sent < total_send) {
            const send_op = try self.loop.tcpSend(sock, send_buf[bytes_sent..total_send], @ptrCast(&send_ctx));

            send_wait: while (true) {
                var completions: [max_operations]Completion = undefined;
                const results = try self.loop.tick(&completions);
                for (results) |c| {
                    const ctx: *Ctx = @ptrCast(@alignCast(c.context));
                    switch (ctx.tag) {
                        .send => {
                            if (c.result.tcp_send.bytes_sent <= 0) {
                                self.loop.cancel(timeout_op) catch {};
                                self.loop.flush();
                                return error.SendFailed;
                            }
                            bytes_sent += @intCast(c.result.tcp_send.bytes_sent);
                            break :send_wait;
                        },
                        .timeout => {
                            if (c.result.timeout.expired) {
                                self.loop.cancel(send_op) catch {};
                                self.loop.flush();
                                return error.Timeout;
                            }
                        },
                        else => {},
                    }
                }
            }
        }

        // ── Phase 3: Receive length-prefixed response ──
        var len_buf: [2]u8 = undefined;
        var len_filled: usize = 0;
        var body_len: ?u16 = null;
        var body_filled: usize = 0;

        recv_loop: while (true) {
            const recv_op = try self.loop.tcpRecv(sock, @ptrCast(&recv_ctx));

            recv_wait: while (true) {
                var completions: [max_operations]Completion = undefined;
                const results = try self.loop.tick(&completions);
                for (results) |c| {
                    const ctx: *Ctx = @ptrCast(@alignCast(c.context));
                    switch (ctx.tag) {
                        .recv => {
                            const r = c.result.tcp_recv;
                            if (r.err != null or r.data.len == 0) {
                                self.loop.cancel(timeout_op) catch {};
                                self.loop.flush();
                                return error.ConnectionClosed;
                            }

                            var pos: usize = 0;

                            // Fill length prefix
                            while (len_filled < 2 and pos < r.data.len) {
                                len_buf[len_filled] = r.data[pos];
                                len_filled += 1;
                                pos += 1;
                            }
                            if (len_filled == 2 and body_len == null) {
                                const bl = mem.readInt(u16, &len_buf, .big);
                                if (bl == 0 or bl > response_buf.len) {
                                    self.loop.cancel(timeout_op) catch {};
                                    self.loop.flush();
                                    return error.InvalidLength;
                                }
                                body_len = bl;
                            }

                            // Copy body data
                            if (body_len) |bl| {
                                const remaining = r.data[pos..];
                                const need = bl - body_filled;
                                const to_copy = @min(remaining.len, need);
                                @memcpy(response_buf[body_filled..][0..to_copy], remaining[0..to_copy]);
                                body_filled += to_copy;

                                if (body_filled >= bl) {
                                    self.loop.cancel(timeout_op) catch {};
                                    self.loop.flush();
                                    break :recv_loop;
                                }
                            }
                            break :recv_wait;
                        },
                        .timeout => {
                            if (c.result.timeout.expired) {
                                self.loop.cancel(recv_op) catch {};
                                self.loop.flush();
                                return error.Timeout;
                            }
                        },
                        else => {},
                    }
                }
            }
        }

        return response_buf[0..body_len.?];
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

test "TcpTransport query 8.8.8.8 for example.com A" {
    try skipIfNotLinux();

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var tcp = TcpTransport.init(loop, .{});

    const msg = try dns.buildQuery(testing.allocator, 0xABCD, "example.com", .a);
    defer dns.freeMessage(testing.allocator, msg);
    var wire_buf: [dns.max_udp_payload]u8 = undefined;
    const wire_query = try dns.serializeMessage(&wire_buf, msg);

    const server = std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 53);
    var response_buf: [65535]u8 = undefined;

    const response_data = tcp.query(wire_query, server, &response_buf) catch |err| switch (err) {
        error.Timeout, error.ConnectFailed => return error.SkipZigTest,
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
