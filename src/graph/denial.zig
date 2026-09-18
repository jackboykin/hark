//! RFC 8198 aggressive use. Every NSEC a secure negative carried is the
//! fact `rrset(owner, NSEC)`, and this index orders those facts by owner
//! within their signing zone, so a later question inside a known span is
//! denied from memory with the proofs attached, asking nobody. The index
//! only finds candidates; the verdict is `validateNegativeProof`'s, the
//! same oracle a live denial faces.
const std = @import("std");
const dns = @import("../dns.zig");
const dnssec = @import("../dnssec.zig");
const graph = @import("graph.zig");

const Graph = graph.Graph;
const CellId = graph.CellId;
const RR = dns.ResourceRecord;

/// Records from one section, aged from when it was taken.
const Taken = struct { rrs: []const RR, stored_ns: i64, expires_ns: i64 };

const Zone = struct {
    /// `rrset(owner, NSEC)` cells in canonical owner order.
    nsecs: std.ArrayList(CellId) = .empty,
    /// The apex SOA and its signatures: the synthesised authority section
    /// starts with it (RFC 2308 §3).
    soa: ?Taken = null,

    /// Drop what has expired, so the neighbour of a name is a live proof.
    fn prune(z: *Zone, g: *Graph) void {
        var w: usize = 0;
        for (z.nsecs.items) |id| if (g.fresh(id)) {
            z.nsecs.items[w] = id;
            w += 1;
        };
        z.nsecs.shrinkRetainingCapacity(w);
    }

    /// Where `name` sorts among the owners.
    fn position(z: *const Zone, g: *Graph, name: dns.Name) usize {
        var lo: usize = 0;
        var hi: usize = z.nsecs.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (dnssec.canonicalNameOrder(g.cell(z.nsecs.items[mid]).name, name) == .lt) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    fn exact(z: *const Zone, g: *Graph, name: dns.Name) ?CellId {
        const pos = z.position(g, name);
        if (pos == z.nsecs.items.len) return null;
        const id = z.nsecs.items[pos];
        return if (g.cell(id).name.eql(name) and g.fresh(id)) id else null;
    }

    /// The fresh NSEC whose range holds `name` (RFC 6840 §4.1 geometry); the
    /// last owner wraps to cover what sorts before the first.
    fn span(z: *const Zone, g: *Graph, name: dns.Name) ?CellId {
        const n = z.nsecs.items.len;
        if (n == 0) return null;
        const pos = z.position(g, name);
        for ([_]usize{ if (pos > 0) pos - 1 else n - 1, n - 1 }) |i| {
            const id = z.nsecs.items[i];
            if (g.fresh(id) and dnssec.nsecCovers(g.cell(id).name, nsecOf(g, id), name)) return id;
        }
        return null;
    }
};

fn nsecOf(g: *Graph, id: CellId) dns.NsecData {
    return g.cell(id).value.rrset.answers[0].rdata.nsec;
}

pub const Index = struct {
    zones: std.StringHashMapUnmanaged(Zone) = .empty,

    pub fn deinit(ix: *Index, gpa: std.mem.Allocator) void {
        var it = ix.zones.valueIterator();
        while (it.next()) |z| z.nsecs.deinit(gpa);
        ix.zones.deinit(gpa);
    }
};

/// A proof carries at most this many NSECs (closest encloser, next closer,
/// wildcard); the rest is stuffing.
const max_proofs = 8;

/// A secure negative's proofs, verified under `signer`, become facts: each
/// NSEC with its signatures as `rrset(owner, NSEC)`, for as long as the
/// verdict holds, its own TTL runs and the negative cap allows (RFC 8198
/// §5.4).
pub fn absorb(g: *Graph, by: CellId, signer: dns.Name, r: graph.Reply, expires_ns: i64) !void {
    var buf: [dns.max_dotted_len + 1]u8 = undefined;
    const gop = try g.denial.zones.getOrPut(g.gpa, signer.formatLower(&buf));
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
        gop.key_ptr.* = g.arena.dupe(u8, gop.key_ptr.*) catch |e| {
            g.denial.zones.removeByPtr(gop.key_ptr);
            return e;
        };
    }
    const z = gop.value_ptr;
    z.prune(g);
    var proofs: usize = 0;
    for (r.authorities) |rr| {
        if ((rr.rtype != .nsec and rr.rtype != .soa) or !rr.name.isSubdomainOf(signer)) continue;
        if (rr.rtype == .nsec and (minimal(rr) or proofs == max_proofs)) continue;
        const rrs = try withSigs(g, r.authorities, rr);
        // The negative cap doubles as RFC 9077 §3's ceiling on aggressive use.
        const expires = @min(expires_ns, r.stored_ns + @as(i64, @min(rr.ttl, g.cfg.max_negative_ttl)) * std.time.ns_per_s);
        if (rr.rtype == .soa) {
            if (rr.name.eql(signer)) z.soa = .{ .rrs = rrs, .stored_ns = r.stored_ns, .expires_ns = expires };
            continue;
        }
        proofs += 1;
        const fact: graph.Reply = .{ .kind = .answer, .rcode = .no_error, .aa = true, .answers = rrs, .zone = signer, .stored_ns = r.stored_ns, .ttl = rr.ttl };
        const id = try g.publish(try g.keyFor(.rrset, rr.name, .nsec), rr.name, by, .{ .rrset = fact }, expires);
        const pos = z.position(g, rr.name);
        if (pos < z.nsecs.items.len and g.cell(z.nsecs.items[pos]).name.eql(rr.name)) z.nsecs.items[pos] = id else try z.nsecs.insert(g.gpa, pos, id);
    }
}

/// A range of one name (`owner NSEC \000.owner`, "black lies") denies
/// nothing but types at its owner.
fn minimal(rr: RR) bool {
    const next = rr.rdata.nsec.next_domain_name;
    return next.labels.len == rr.name.labels.len + 1 and next.labels[0].len == 1 and next.labels[0][0] == 0 and next.isSubdomainOf(rr.name);
}

/// `rr` followed by the signatures over it; four is a dual-algorithm
/// rollover's ceiling (RFC 6781 §4.1.4).
fn withSigs(g: *Graph, rrs: []const RR, rr: RR) ![]const RR {
    var keep: std.ArrayList(RR) = .empty;
    try keep.append(g.arena, rr);
    for (rrs) |s| if (keep.items.len <= 4 and s.rtype == .rrsig and s.name.eql(rr.name) and s.rdata.rrsig.type_covered == rr.rtype) try keep.append(g.arena, s);
    return keep.items;
}

/// Settle `rrset(name, type)` as a denial from indexed proofs, if the
/// closest zone holding any can prove one: a span covering the name with
/// the wildcard at its closest encloser matched (NODATA) or covered
/// (NXDOMAIN), an exact owner (NODATA), or a span whose next name descends
/// below it (an empty non-terminal, NODATA). The verdict is published with
/// the reply; nothing is re-verified. Never for a DS: that is the parent's
/// word at the cut alone (RFC 6840 §4.4), and it travels with the referral;
/// a span from before the delegation existed would judge it (dnssec/033).
/// Keys are only ever wanted positive.
pub fn deny(g: *Graph, id: CellId) !bool {
    const qtype = g.cell(id).key.rtype;
    if (g.cfg.trust_anchor == null or g.denial.zones.count() == 0 or qtype == .ds or qtype == .dnskey) return false;
    const name = g.cell(id).name;
    for (0..name.labels.len + 1) |i| {
        const zone: dns.Name = .{ .labels = name.labels[i..] };
        var buf: [dns.max_dotted_len + 1]u8 = undefined;
        const z = g.denial.zones.getPtr(zone.formatLower(&buf)) orelse continue;
        if (try denyIn(g, z, id, zone)) return true;
    }
    return false;
}

fn denyIn(g: *Graph, z: *const Zone, id: CellId, zone: dns.Name) !bool {
    const name = g.cell(id).name;
    const qtype = g.cell(id).key.rtype;
    const now = g.now();
    const soa = z.soa orelse return false;
    if (soa.expires_ns <= now) return false;
    var proofs: [2]CellId = undefined;
    var n: usize = 1;
    var nxdomain = false;
    if (z.span(g, name)) |cover| {
        proofs[0] = cover;
        if (dnssec.nsecProvesNameNonexistence(g.cell(cover).name, nsecOf(g, cover), name)) {
            const ce = dnssec.closestEncloser(name, g.cell(cover).name, nsecOf(g, cover).next_domain_name) orelse return false;
            var wc_buf: [dns.max_label_count + 1][]const u8 = undefined;
            const wildcard = dns.makeWildcardName(&wc_buf, ce) orelse return false;
            if (z.exact(g, wildcard)) |wc| {
                proofs[1] = wc;
            } else if (z.span(g, wildcard)) |wc| {
                proofs[1] = wc;
                nxdomain = true;
            } else return false;
            n += @intFromBool(proofs[1] != cover);
        }
    } else proofs[0] = z.exact(g, name) orelse return false;

    var expires = soa.expires_ns;
    var authorities: std.ArrayList(RR) = .empty;
    try aged(g, &authorities, soa.rrs, soa.stored_ns);
    for (proofs[0..n]) |p| {
        const c = g.cell(p);
        expires = @min(expires, c.expires_ns);
        try aged(g, &authorities, c.value.rrset.answers, c.value.rrset.stored_ns);
    }
    var budget: dnssec.ValidationBudget = .{};
    if (dnssec.validateNegativeProof(authorities.items, name, qtype, nxdomain, zone, &budget) != .secure) return false;

    var reply: graph.Reply = .{
        .kind = if (nxdomain) .nxdomain else .nodata,
        .rcode = if (nxdomain) .name_error else .no_error,
        .aa = true,
        .authorities = authorities.items,
        .zone = zone,
        .ede = .synthesized,
        .stored_ns = now,
    };
    reply.ttl = @min(g.replyTtl(reply, zone, name), @as(u32, @intCast(@divTrunc(expires - now, std.time.ns_per_s))));
    // The reply first, so the verdict lands on its bytes.
    try g.settle(id, .{ .rrset = reply }, g.replyExpiry(reply));
    const key = try g.keyFor(.secure, name, qtype);
    const sid = try g.newCell(key, name, g.cell(id).root, g.cell(id).depth);
    g.cell(sid).scratch.secure.target = id;
    try g.index.put(g.gpa, key, sid);
    try g.settle(sid, .{ .secure = .{ .status = .secure, .proven_until_ns = expires } }, expires);
    return true;
}

/// Append `rrs` with the TTL they have left.
fn aged(g: *Graph, out: *std.ArrayList(RR), rrs: []const RR, stored_ns: i64) !void {
    const age: u32 = @intCast(@divTrunc(g.now() - stored_ns, std.time.ns_per_s));
    for (rrs) |rr| {
        var a = rr;
        a.ttl = rr.ttl -| age;
        try out.append(g.arena, a);
    }
}
