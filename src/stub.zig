//! Stub zones: zones whose servers the operator tells hark
//! (`stub-zones`), as the hints tell it the root's. Their names are asked
//! of those servers alone, and nothing else speaks for them.
const dns = @import("dns.zig");
const na = @import("net_address.zig");
const special_use = @import("special_use.zig");
const graph = @import("graph.zig");
const walk = @import("walk.zig");
const delegation = @import("delegation.zig");

const Graph = graph.Graph;
const CellId = graph.CellId;
const Failure = graph.Failure;

pub const Zone = struct {
    apex: dns.Name,
    servers: []const na.Address,
};

pub fn under(zones: []const Zone, name: dns.Name) ?*const Zone {
    var deepest: ?*const Zone = null;
    for (zones) |*z| {
        if (deepest) |d| if (z.apex.depth() <= d.apex.depth()) continue;
        if (name.isSubdomainOf(z.apex)) deepest = z;
    }
    return if (deepest != null and special_use.fixed(name)) null else deepest;
}

/// A DS is its parent's data (RFC 4035 §2.4), so it belongs to the parent's stub zone.
pub fn of(zones: []const Zone, name: dns.Name, qtype: dns.RType) ?*const Zone {
    return under(zones, if (qtype == .ds) name.parent() orelse name else name);
}

pub const Scratch = struct {
    ask: ?walk.Ask = null,
};

const referred: Failure = .{ .code = .no_reachable_authority, .text = "stub server referred" };

pub fn run(g: *Graph, id: CellId) !void {
    const name = g.cell(id).name;
    const qtype = g.cell(id).key.rtype;
    const s = g.cell(id).scratch.stub;
    if (s.ask == null) s.ask = .{ .zone = of(g.cfg.stub_zones, name, qtype).?.apex };
    const a = &s.ask.?;
    switch (try walk.ask(g, id, a, name, qtype)) {
        .pending => return,
        .exhausted => return g.failRemembered(id, walk.ended(g, a)),
        .reply => |kept| {
            if (delegation.extractReferral(kept.msg, name, a.zone) != null) return g.failRemembered(id, referred);
            return switch (kept.verdict) {
                .reply => |r| g.settle(id, .{ .stub = r }, walk.replyExpiry(r)),
                .loop => g.failRemembered(id, walk.Links.loop),
                .none => g.failRemembered(id, walk.ended(g, a)),
            };
        },
    }
}

test "a stub zone never claims a name whose answer its RFC fixes" {
    const zones = [_]Zone{.{ .apex = .lit("arpa"), .servers = &.{} }};
    try @import("std").testing.expectEqual(null, under(&zones, .lit("ipv4only.arpa")));
}
