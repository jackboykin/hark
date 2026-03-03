const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const net = std.net;
const tls = std.crypto.tls;
const Certificate = std.crypto.Certificate;
const testing = std.testing;
const dns = @import("dns.zig");
const EventLoop = @import("event_loop.zig").EventLoop;
const Completion = @import("event_loop.zig").Completion;
const max_operations = @import("event_loop.zig").max_operations;

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
    config: TlsConfig,
    ca_bundle: Certificate.Bundle,

    pub fn init(loop: *EventLoop, config: TlsConfig, ca_bundle: Certificate.Bundle) TlsTransport {
        return .{ .loop = loop, .config = config, .ca_bundle = ca_bundle };
    }

    pub fn query(self: *TlsTransport, wire_query: []const u8, server: net.Address, response_buf: []u8) ![]const u8 {
        // Create TCP socket matching server address family
        const af: u32 = if (server.any.family == posix.AF.INET6) posix.AF.INET6 else posix.AF.INET;
        const sock = try posix.socket(af, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        defer posix.close(sock);

        // Override port to configured TLS port
        var tls_server = server;
        switch (tls_server.any.family) {
            posix.AF.INET => {
                tls_server.in.setPort(self.config.port);
            },
            posix.AF.INET6 => {
                tls_server.in6.setPort(self.config.port);
            },
            else => return error.UnsupportedAddressFamily,
        }

        // ── Phase 1: Connect via io_uring ──
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
        // Clear O_NONBLOCK for blocking TLS I/O
        const current_flags = try posix.fcntl(sock, posix.F.GETFL, 0);
        const nonblock_bit = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
        _ = try posix.fcntl(sock, posix.F.SETFL, current_flags & ~nonblock_bit);

        // Set socket timeouts for TLS handshake + data
        const timeout_sec: i64 = @intCast(self.config.response_timeout_ms / 1000);
        const timeout_usec: i64 = @intCast(@as(u64, self.config.response_timeout_ms % 1000) * 1000);
        const recv_timeout = posix.timeval{ .sec = timeout_sec, .usec = timeout_usec };
        const send_timeout = posix.timeval{ .sec = timeout_sec, .usec = timeout_usec };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&recv_timeout));
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&send_timeout));

        // ── Phase 3: TLS handshake ──
        const stream = net.Stream{ .handle = sock };

        // Network I/O buffers for the TLS encrypted stream
        var net_read_buf: [tls.Client.min_buffer_len]u8 = undefined;
        var net_write_buf: [tls.Client.min_buffer_len]u8 = undefined;
        var net_reader = net.Stream.Reader.init(stream, &net_read_buf);
        var net_writer = net.Stream.Writer.init(stream, &net_write_buf);

        // TLS plaintext buffers
        var tls_read_buf: [tls.Client.min_buffer_len]u8 = undefined;
        var tls_write_buf: [tls.Client.min_buffer_len]u8 = undefined;

        var tls_client = tls.Client.init(net_reader.interface(), &net_writer.interface, .{
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
            .read_buffer = &tls_read_buf,
            .write_buffer = &tls_write_buf,
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
        // TLS flush only pushes ciphertext into the output buffer — flush to network
        net_writer.interface.flush() catch return error.TlsSendFailed;

        // ── Phase 5: Receive length-prefixed DNS response ──
        // Read 2-byte length prefix
        var resp_len_buf: [2]u8 = undefined;
        tls_client.reader.readSliceAll(&resp_len_buf) catch return error.TlsRecvFailed;
        const resp_len = mem.readInt(u16, &resp_len_buf, .big);

        if (resp_len == 0 or resp_len > response_buf.len) return error.InvalidLength;

        // Read response body
        tls_client.reader.readSliceAll(response_buf[0..resp_len]) catch return error.TlsRecvFailed;

        // ── Phase 6: Clean shutdown ──
        tls_client.end() catch {};

        return response_buf[0..resp_len];
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

test "TlsTransport query Cloudflare DoT 1.1.1.1:853" {
    try skipIfNotLinux();

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    // Load system CA bundle
    var ca_bundle: Certificate.Bundle = .{};
    ca_bundle.rescan(testing.allocator) catch return error.SkipZigTest;
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(loop, .{
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
        error.SystemOutdated => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var ca_bundle: Certificate.Bundle = .{};
    ca_bundle.rescan(testing.allocator) catch return error.SkipZigTest;
    defer ca_bundle.deinit(testing.allocator);

    var tls_t = TlsTransport.init(loop, .{
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
