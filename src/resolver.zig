const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const posix = std.posix;
const dns = @import("dns.zig");
const BlockingUdpTransport = @import("blocking_transport.zig").BlockingUdpTransport;
const BlockingTcpTransport = @import("blocking_transport.zig").BlockingTcpTransport;
const rand = @import("rand.zig");
const TlsTransport = @import("tls_transport.zig").TlsTransport;
const na = @import("net_address.zig");

pub const ForwardingResolver = struct {
    transport: *BlockingUdpTransport,
    tcp_transport: ?*BlockingTcpTransport,
    tls_transport: ?*TlsTransport,
    io: std.Io,

    pub const Config = struct {
        transport: *BlockingUdpTransport,
        tcp_transport: ?*BlockingTcpTransport = null,
        tls_transport: ?*TlsTransport = null,
        io: std.Io,
    };

    pub fn init(cfg: Config) ForwardingResolver {
        return .{
            .transport = cfg.transport,
            .tcp_transport = cfg.tcp_transport,
            .tls_transport = cfg.tls_transport,
            .io = cfg.io,
        };
    }

    pub fn resolve(self: *ForwardingResolver, allocator: mem.Allocator, name: []const u8, qtype: dns.RType, upstream: na.Address) !dns.Message {
        const query_id = rand.queryId(self.io);

        // Build query message (with EDNS0)
        const query_msg = try dns.buildQueryWithOptions(allocator, query_id, name, qtype, .{ .edns = .{} });

        // Serialize to wire format
        var wire_buf: [dns.edns_udp_payload]u8 = undefined;
        const wire_query = try dns.serializeMessage(&wire_buf, query_msg);

        const expected_name = query_msg.questions[0].name;

        // DoT path: send directly over TLS (already TCP-based, no TC-bit fallback needed)
        if (self.tls_transport) |tls_t| {
            const response_buf = try allocator.alloc(u8, dns.max_message_len);
            const response_data = try tls_t.query(wire_query, upstream, response_buf);
            const msg = try dns.parseMessage(allocator, response_data);
            try dns.validateResponse(msg, expected_name, qtype);
            return msg;
        }

        // Do53 path: UDP with TCP fallback on truncation.
        const response_buf = try allocator.alloc(u8, dns.edns_udp_payload);
        const response_data = try self.transport.query(wire_query, query_id, upstream, response_buf);

        // TC bit: retry over TCP before parsing (RFC 2181 — ignore truncated data)
        if (dns.hasTcBit(response_data)) {
            if (self.tcp_transport) |tcp| {
                const tcp_buf = try allocator.alloc(u8, dns.max_message_len);
                if (tcp.query(wire_query, upstream, tcp_buf)) |tcp_data| {
                    const msg = try dns.parseMessage(allocator, tcp_data);
                    try dns.validateResponse(msg, expected_name, qtype);
                    return msg;
                } else |_| {
                    // TCP failed — fall through to parse truncated response as last resort
                }
            }
        }

        const msg = try dns.parseMessage(allocator, response_data);
        try dns.validateResponse(msg, expected_name, qtype);
        return msg;
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

test "ForwardingResolver resolve example.com A via 8.8.8.8" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    const io = testing.io;

    var transport = BlockingUdpTransport.init(.{}, io);

    var resolver = ForwardingResolver.init(.{ .transport = &transport, .io = io });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const upstream = na.initIp4(.{ 8, 8, 8, 8 }, 53);
    const response = resolver.resolve(arena.allocator(), "example.com", .a, upstream) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest, // no network
        else => return err,
    };

    try testing.expect(response.header.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.rcode);
    try testing.expect(response.answers.len > 0);
}
