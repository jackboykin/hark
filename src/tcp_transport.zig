const BlockingTcpTransport = @import("blocking_transport.zig").BlockingTcpTransport;
const TcpConnectionPool = @import("connection_pool.zig").TcpConnectionPool;
const na = @import("net_address.zig");

/// TCP transport interface for resolvers.
pub const AnyTcpTransport = union(enum) {
    blocking: *BlockingTcpTransport,

    pub fn query(self: AnyTcpTransport, wire_query: []const u8, server: na.Address, response_buf: []u8) ![]const u8 {
        return switch (self) {
            .blocking => |t| t.query(wire_query, server, response_buf),
        };
    }

    /// Query with optional TCP connection pooling.
    pub fn queryPooled(self: AnyTcpTransport, wire_query: []const u8, server: na.Address, response_buf: []u8, pool: ?*TcpConnectionPool) ![]const u8 {
        return switch (self) {
            .blocking => |t| if (pool) |p|
                t.queryPooled(wire_query, server, response_buf, p)
            else
                t.query(wire_query, server, response_buf),
        };
    }
};
