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

pub const Scratch = struct {
    ask: walk.Ask = .{},
    started: bool = false,
};

/// A told server's referral: the zone is what its servers answer.
const referred: Failure = .{ .code = .no_reachable_authority, .text = "stub server referred" };

/// `stub(name, type)`: asked of the zone's servers alone, their reply
/// judged as any authority's and settled as given, never validated.
pub fn run(g: *Graph, id: CellId) !void {
    const name = g.cell(id).name;
    const qtype = g.cell(id).key.rtype;
    const s = g.cell(id).scratch.stub;
    if (!s.started) {
        s.ask.reset(of(g.cfg.stub_zones, name, qtype).?.apex);
        s.started = true;
    }
    switch (try walk.ask(g, id, &s.ask, name, qtype)) {
        .pending => return,
        .exhausted => return g.failRemembered(id, walk.ended(g, &s.ask)),
        .reply => |kept| {
            if (delegation.extractReferral(kept.msg, name, s.ask.zone) != null) return g.failRemembered(id, referred);
            return switch (kept.verdict) {
                .reply => |r| g.settle(id, .{ .stub = r }, walk.replyExpiry(r)),
                .loop => g.failRemembered(id, walk.Links.loop),
                // No useful response (RFC 9520 §2).
                .none => g.failRemembered(id, walk.ended(g, &s.ask)),
            };
        },
    }
}

test "a stub zone never claims a name whose answer its RFC fixes" {
    const zones = [_]Zone{.{ .apex = .{ .labels = &.{"arpa"} }, .servers = &.{} }};
    try @import("std").testing.expectEqual(null, under(&zones, .{ .labels = &.{ "ipv4only", "arpa" } }));
}
