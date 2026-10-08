//! Stub zones: zones whose servers the operator tells hark
//! (`stub-zones`), as the hints tell it the root's. Their names are asked
//! of those servers alone.
const dns = @import("dns.zig");
const na = @import("net_address.zig");

pub const Zone = struct {
    apex: dns.Name,
    servers: []const na.Address,
};
