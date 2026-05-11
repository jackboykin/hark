const std = @import("std");
const mem = std.mem;
const dns = @import("dns.zig");
const rand = @import("rand.zig");
const na = @import("net_address.zig");
const Transports = @import("transport.zig").Transports;

pub const ForwardingResolver = struct {
    transports: Transports,
    io: std.Io,

    pub fn resolve(self: *ForwardingResolver, allocator: mem.Allocator, name: []const u8, qtype: dns.RType, upstream: na.Address) !dns.Message {
        const query_id = rand.queryId(self.io);

        // Build query message (with EDNS0)
        const query_msg = try dns.buildQuery(allocator, query_id, name, qtype, .{ .edns = .{} });

        // Serialize to wire format
        var wire_buf: [dns.edns_udp_payload]u8 = undefined;
        const wire_query = try dns.serializeMessage(&wire_buf, query_msg);

        const expected_name = query_msg.questions[0].name;

        // DoT path: send directly over TLS (already TCP-based, no TC-bit fallback needed)
        if (self.transports.tls) |tls_t| {
            const response_buf = try allocator.alloc(u8, dns.max_message_len);
            const response_data = try tls_t.query(wire_query, upstream, response_buf);
            const msg = try dns.parseMessage(allocator, response_data);
            try dns.validateResponse(msg, expected_name, qtype);
            return msg;
        }

        // Do53 path: UDP with TCP fallback on truncation.
        const response_buf = try allocator.alloc(u8, dns.edns_udp_payload);
        const response_data = try self.transports.udp.query(wire_query, query_id, upstream, response_buf);

        // TC bit: retry over TCP before parsing (RFC 2181 — ignore truncated data)
        if (dns.hasTcBit(response_data)) {
            if (self.transports.tcp) |tcp| {
                const tcp_buf = try allocator.alloc(u8, dns.max_message_len);
                if (tcp.query(wire_query, upstream, tcp_buf, null)) |tcp_data| {
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
