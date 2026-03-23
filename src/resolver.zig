const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const posix = std.posix;
const dns = @import("dns.zig");
const EventLoop = @import("event_loop.zig").EventLoop;
const UdpTransport = @import("transport.zig").UdpTransport;
const AnyUdpTransport = @import("transport.zig").AnyUdpTransport;
const AnyTcpTransport = @import("tcp_transport.zig").AnyTcpTransport;
const rand = @import("rand.zig");
const TlsTransport = @import("tls_transport.zig").TlsTransport;
const Config = @import("transport.zig").Config;
const na = @import("net_address.zig");

pub const ForwardingResolver = struct {
    transport: AnyUdpTransport,
    tcp_transport: ?AnyTcpTransport = null,
    tls_transport: ?*TlsTransport = null,
    io: std.Io = undefined,

    pub fn init(transport: AnyUdpTransport) ForwardingResolver {
        return .{ .transport = transport, .tcp_transport = null, .tls_transport = null };
    }

    pub fn initWithTcp(transport: AnyUdpTransport, tcp: AnyTcpTransport) ForwardingResolver {
        return .{ .transport = transport, .tcp_transport = tcp, .tls_transport = null };
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
            var response_buf: [65535]u8 = undefined;
            const response_data = try tls_t.query(wire_query, upstream, &response_buf);
            const msg = try dns.parseMessage(allocator, response_data);
            if (!msg.header.qr) return error.FormatError;
            if (!dns.validateQuestionMatch(msg, expected_name, qtype)) {
                // RFC 9619 / Unbound model: error responses (FORMERR, SERVFAIL, REFUSED)
                // may omit the question section. Accept them — nothing to poison.
                // Reject NOERROR/NXDOMAIN with missing questions (suspicious).
                if (msg.header.rcode == .no_error or msg.header.rcode == .name_error) return error.FormatError;
            }
            return msg;
        }

        // Do53 path: UDP with TCP fallback on truncation
        const response_data = try self.transport.query(wire_query, query_id, upstream);

        // TC bit: retry over TCP before parsing (RFC 2181 — ignore truncated data)
        if (dns.hasTcBit(response_data)) {
            if (self.tcp_transport) |tcp| {
                var tcp_buf: [65535]u8 = undefined;
                if (tcp.query(wire_query, upstream, &tcp_buf)) |tcp_data| {
                    const msg = try dns.parseMessage(allocator, tcp_data);
                    if (!msg.header.qr) return error.FormatError;
                    if (!dns.validateQuestionMatch(msg, expected_name, qtype)) {
                        if (msg.header.rcode == .no_error or msg.header.rcode == .name_error) return error.FormatError;
                    }
                    return msg;
                } else |_| {
                    // TCP failed — fall through to parse truncated response as last resort
                }
            }
        }

        const msg = try dns.parseMessage(allocator, response_data);
        if (!msg.header.qr) return error.FormatError;
        if (!dns.validateQuestionMatch(msg, expected_name, qtype)) {
            if (msg.header.rcode == .no_error or msg.header.rcode == .name_error) return error.FormatError;
        }
        return msg;
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

test "ForwardingResolver resolve example.com A via 8.8.8.8" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    const io = testing.io;

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = UdpTransport.init(loop, .{}, io) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = ForwardingResolver{ .transport = .{ .uring = &transport }, .io = io };

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
