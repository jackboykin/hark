const std = @import("std");
const posix = std.posix;
const BlockingUdpTransport = @import("blocking_transport.zig").BlockingUdpTransport;
const rand = @import("rand.zig");
const na = @import("net_address.zig");
const sys = @import("sys.zig");

/// UDP transport interface for resolvers.
pub const AnyUdpTransport = union(enum) {
    blocking: *BlockingUdpTransport,

    pub fn getTimeoutMs(self: AnyUdpTransport) u32 {
        return switch (self) {
            .blocking => |t| t.config.timeout_ms,
        };
    }

    pub fn query(self: AnyUdpTransport, wire_query: []const u8, query_id: u16, upstream: na.Address) ![]const u8 {
        return switch (self) {
            .blocking => |t| t.query(wire_query, query_id, upstream),
        };
    }

    pub fn queryWithTimeout(self: AnyUdpTransport, wire_query: []const u8, query_id: u16, upstream: na.Address, timeout_ms: u32) ![]const u8 {
        return switch (self) {
            .blocking => |t| t.queryWithTimeout(wire_query, query_id, upstream, timeout_ms),
        };
    }
};

/// Create a UDP socket bound to a random ephemeral port (RFC 5452).
pub fn openUdpSocket(dest: na.Address, io: std.Io) !posix.fd_t {
    const af: u32 = na.afU32(dest);
    const flags: u32 = posix.SOCK.DGRAM;
    const sock = try sys.socket(af, flags, 0);
    errdefer sys.close(sock);

    for (0..64) |_| {
        const port = rand.ephemeralPort(io);
        const addr = anyAddr(af, port);
        na.bindTo(sock, &addr) catch |err| switch (err) {
            error.AddressInUse => continue,
            else => return err,
        };
        return sock;
    }
    return error.AddressInUse;
}

pub fn anyAddr(af: u32, port: u16) na.Address {
    return if (af == posix.AF.INET6)
        na.initIp6(.{0} ** 16, port, 0, 0)
    else
        na.initIp4(.{ 0, 0, 0, 0 }, port);
}

/// Compare two addresses by IP, ignoring port.
pub fn addressMatchesUpstream(response: na.Address, upstream: na.Address) bool {
    return na.ipEqual(response, upstream);
}
