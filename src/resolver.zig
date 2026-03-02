const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const posix = std.posix;
const dns = @import("dns.zig");
const EventLoop = @import("event_loop.zig").EventLoop;
const UdpTransport = @import("transport.zig").UdpTransport;
const Config = @import("transport.zig").Config;

pub const ForwardingResolver = struct {
    transport: *UdpTransport,

    pub fn init(transport: *UdpTransport) ForwardingResolver {
        return .{ .transport = transport };
    }

    pub fn resolve(self: *ForwardingResolver, allocator: mem.Allocator, name: []const u8, qtype: dns.RType, upstream: std.net.Address) !dns.Message {
        // Generate random query ID
        var id_bytes: [2]u8 = undefined;
        std.crypto.random.bytes(&id_bytes);
        const query_id = mem.readInt(u16, &id_bytes, .big);

        // Build query message
        const query_msg = try dns.buildQuery(allocator, query_id, name, qtype);

        // Serialize to wire format
        var wire_buf: [dns.max_udp_payload]u8 = undefined;
        const wire_query = try dns.serializeMessage(&wire_buf, query_msg);

        // Send and receive
        const response_data = try self.transport.query(wire_query, query_id, upstream);

        // Parse response
        const response = try dns.parseMessage(allocator, response_data);

        // Warn about truncation
        if (response.header.tc) {
            std.log.warn("response truncated (TC bit set), TCP fallback not yet implemented", .{});
        }

        return response;
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

test "ForwardingResolver resolve example.com A via 8.8.8.8" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = UdpTransport.init(loop, .{}) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = ForwardingResolver.init(&transport);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const upstream = std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 53);
    const response = resolver.resolve(arena.allocator(), "example.com", .a, upstream) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest, // no network
        else => return err,
    };

    try testing.expect(response.header.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.rcode);
    try testing.expect(response.answers.len > 0);
}
