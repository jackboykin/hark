const std = @import("std");
const posix = std.posix;
const rand = @import("rand.zig");
const na = @import("net_address.zig");
const sys = @import("sys.zig");

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
