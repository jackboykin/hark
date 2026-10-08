//! Stub zones: zones whose servers the operator tells hark
//! (`stub-zones`), as the hints tell it the root's. Their names are asked
//! of those servers alone.
const dns = @import("dns.zig");
const na = @import("net_address.zig");
const special_use = @import("special_use.zig");

pub const Zone = struct {
    apex: dns.Name,
    servers: []const na.Address,
};

/// The deepest stub zone at or above `name`. None claims a name whose
/// answer its RFC fixes.
pub fn under(zones: []const Zone, name: dns.Name) ?*const Zone {
    var deepest: ?*const Zone = null;
    for (zones) |*z| {
        if (deepest) |d| if (z.apex.labels.len <= d.apex.labels.len) continue;
        if (name.isSubdomainOf(z.apex)) deepest = z;
    }
    return if (deepest != null and special_use.fixed(name)) null else deepest;
}

/// The stub zone a question belongs to: its name's, but for DS, which
/// is its parent's data (RFC 4035 §2.4), the parent's.
pub fn of(zones: []const Zone, name: dns.Name, qtype: dns.RType) ?*const Zone {
    if (qtype != .ds or name.labels.len == 0) return under(zones, name);
    return under(zones, .{ .labels = name.labels[1..] });
}

test "a stub zone never claims a name whose answer its RFC fixes" {
    const zones = [_]Zone{.{ .apex = .{ .labels = &.{"arpa"} }, .servers = &.{} }};
    try @import("std").testing.expectEqual(null, under(&zones, .{ .labels = &.{ "ipv4only", "arpa" } }));
}
