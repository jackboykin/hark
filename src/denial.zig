//! RFC 8198 aggressive use. Every NSEC a secure negative carried is the
//! fact `rrset(owner, NSEC)`, its SOA the fact `rrset(zone, SOA)`; this
//! index orders the spans by owner within their signing zone, so a later
//! question inside a known span is denied from memory with the proofs
//! fetched by key. The index only finds candidates: the verdict is
//! `validateNegativeProof`'s, and a proof gone from the store fails closed.
const std = @import("std");
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");
const graph = @import("graph.zig");
const walk = @import("walk.zig");

const Graph = graph.Graph;
const CellId = graph.CellId;
const RR = dns.ResourceRecord;

/// One NSEC's geometry; the record lives in the store.
const Span = struct {
    owner: dns.Name,
    nsec: dns.NsecData,
    expires_ns: i64,
    buf: []align(8) u8,

    fn init(gpa: std.mem.Allocator, rr: RR, expires_ns: i64) !Span {
        const n = rr.rdata.nsec;
        const owner_len = std.mem.alignForward(usize, dns.nameFlatSize(rr.name), 8);
        const next_len = std.mem.alignForward(usize, dns.nameFlatSize(n.next_domain_name), 8);
        const buf = try gpa.alignedAlloc(u8, .fromByteUnits(8), owner_len + next_len + n.type_bit_maps.len);
        const owner = dns.writeNameFlat(buf[0..owner_len], rr.name, false);
        const next = dns.writeNameFlat(@alignCast(buf[owner_len..][0..next_len]), n.next_domain_name, false);
        const bits = buf[owner_len + next_len ..];
        @memcpy(bits, n.type_bit_maps);
        return .{ .owner = owner, .nsec = .{ .next_domain_name = next, .type_bit_maps = bits }, .expires_ns = expires_ns, .buf = buf };
    }
};

const Zone = struct {
    /// In canonical owner order.
    spans: std.ArrayList(Span) = .empty,

    /// Drop what has expired, so the neighbour of a name is a live proof.
    fn prune(z: *Zone, g: *Graph) void {
        var w: usize = 0;
        for (z.spans.items) |sp| if (sp.expires_ns > g.now()) {
            z.spans.items[w] = sp;
            w += 1;
        } else g.gpa.free(sp.buf);
        z.spans.shrinkRetainingCapacity(w);
    }

    /// Where `name` sorts among the owners.
    fn position(z: *const Zone, name: dns.Name) usize {
        var lo: usize = 0;
        var hi: usize = z.spans.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (dnssec.canonicalNameOrder(z.spans.items[mid].owner, name) == .lt) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    fn exact(z: *const Zone, g: *Graph, name: dns.Name) ?*const Span {
        const pos = z.position(name);
        if (pos == z.spans.items.len) return null;
        const sp = &z.spans.items[pos];
        return if (sp.owner.eql(name) and sp.expires_ns > g.now()) sp else null;
    }

    /// The live span whose range holds `name` (RFC 6840 §4.1 geometry); the
    /// last owner wraps to cover what sorts before the first.
    fn span(z: *const Zone, g: *Graph, name: dns.Name) ?*const Span {
        const n = z.spans.items.len;
        if (n == 0) return null;
        const pos = z.position(name);
        for ([_]usize{ if (pos > 0) pos - 1 else n - 1, n - 1 }) |i| {
            const sp = &z.spans.items[i];
            if (sp.expires_ns > g.now() and dnssec.nsecCovers(sp.owner, sp.nsec, name)) return sp;
        }
        return null;
    }
};

pub const Index = struct {
    zones: std.StringHashMapUnmanaged(Zone) = .empty,

    pub fn deinit(ix: *Index, gpa: std.mem.Allocator) void {
        var it = ix.zones.iterator();
        while (it.next()) |e| {
            for (e.value_ptr.spans.items) |sp| gpa.free(sp.buf);
            e.value_ptr.spans.deinit(gpa);
            gpa.free(e.key_ptr.*);
        }
        ix.zones.deinit(gpa);
    }
};

/// So the index cannot outgrow its facts.
pub fn evicted(g: *Graph, key: graph.Key) void {
    if (key.kind != .rrset or key.rtype != .nsec) return;
    const owner = dns.parseDottedName(g.scratch.allocator(), key.name) catch return;
    for (0..owner.labels.len + 1) |i| {
        var buf: [dns.max_dotted_len + 1]u8 = undefined;
        const zone: dns.Name = .{ .labels = owner.labels[i..] };
        const z = g.denial.zones.getPtr(zone.formatLower(&buf)) orelse continue;
        const pos = z.position(owner);
        if (pos < z.spans.items.len and z.spans.items[pos].owner.eql(owner)) {
            g.gpa.free(z.spans.items[pos].buf);
            _ = z.spans.orderedRemove(pos);
            return;
        }
    }
}

/// A proof carries at most this many NSECs (closest encloser, next closer,
/// wildcard); the rest is stuffing.
const max_proofs = 8;

/// A secure negative's SOA and NSECs, verified under `signer`, become
/// facts for as long as the verdict holds, their TTL runs and the negative
/// cap allows (RFC 8198 §5.4).
pub fn absorb(g: *Graph, by: CellId, signer: dns.Name, r: graph.Reply, expires_ns: i64) !void {
    var buf: [dns.max_dotted_len + 1]u8 = undefined;
    const gop = try g.denial.zones.getOrPut(g.gpa, signer.formatLower(&buf));
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
        gop.key_ptr.* = g.gpa.dupe(u8, gop.key_ptr.*) catch |e| {
            g.denial.zones.removeByPtr(gop.key_ptr);
            return e;
        };
    }
    const z = gop.value_ptr;
    z.prune(g);
    var proofs: usize = 0;
    for (r.authorities) |rr| {
        if ((rr.rtype != .nsec and rr.rtype != .soa) or !rr.name.isSubdomainOf(signer)) continue;
        if (rr.rtype == .soa and !rr.name.eql(signer)) continue;
        if (rr.rtype == .nsec and (minimal(rr) or proofs == max_proofs)) continue;
        const rrs = try withSigs(g, r.authorities, rr);
        // The negative cap doubles as RFC 9077 §3's ceiling on aggressive use.
        const expires = @min(expires_ns, r.stored_ns + @as(i64, @min(rr.ttl, g.cfg.max_negative_ttl)) * std.time.ns_per_s);
        const fact: graph.Reply = .{ .kind = .answer, .rcode = .no_error, .aa = true, .answers = rrs, .zone = signer, .stored_ns = r.stored_ns, .ttl = rr.ttl };
        try g.publish(try g.keyFor(.rrset, rr.name, rr.rtype), by, .{ .rrset = fact }, expires);
        if (rr.rtype == .soa) continue;
        proofs += 1;
        const sp = try Span.init(g.gpa, rr, expires);
        const pos = z.position(rr.name);
        if (pos < z.spans.items.len and z.spans.items[pos].owner.eql(rr.name)) {
            g.gpa.free(z.spans.items[pos].buf);
            z.spans.items[pos] = sp;
        } else z.spans.insert(g.gpa, pos, sp) catch |e| {
            g.gpa.free(sp.buf);
            return e;
        };
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
    try keep.append(g.scratch.allocator(), rr);
    for (rrs) |s| if (keep.items.len <= 4 and s.rtype == .rrsig and s.name.eql(rr.name) and s.rdata.rrsig.type_covered == rr.rtype) try keep.append(g.scratch.allocator(), s);
    return keep.items;
}

/// Settle `rrset(name, type)` as a denial from indexed proofs, if the
/// closest zone holding any can prove one: a span covering the name with
/// the wildcard at its closest encloser matched (NODATA) or covered
/// (NXDOMAIN), an exact owner (NODATA), or a span whose next name descends
/// below it (an empty non-terminal, NODATA). The verdict is stamped on the
/// reply; nothing is re-verified. Never for a DS: that is the parent's
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
    const soa = try g.peek(try g.keyFor(.rrset, zone, .soa)) orelse return false;
    var proofs: [2]*const Span = undefined;
    var n: usize = 1;
    var nxdomain = false;
    if (z.span(g, name)) |cover| {
        proofs[0] = cover;
        if (dnssec.nsecProvesNameNonexistence(cover.owner, cover.nsec, name)) {
            const ce = dnssec.closestEncloser(name, cover.owner, cover.nsec.next_domain_name) orelse return false;
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
    try aged(g, &authorities, soa.value.rrset.answers, soa.value.rrset.stored_ns);
    for (proofs[0..n]) |p| {
        const fact = try g.peek(try g.keyFor(.rrset, p.owner, .nsec)) orelse return false;
        expires = @min(expires, fact.expires_ns);
        try aged(g, &authorities, fact.value.rrset.answers, fact.value.rrset.stored_ns);
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
    reply.ttl = @min(walk.replyTtl(g, reply, zone, name), @as(u32, @intCast(@divTrunc(expires - now, std.time.ns_per_s))));
    try g.settle(id, .{ .rrset = reply }, walk.replyExpiry(reply));
    g.cell(id).blob.?.verdict.stamp(.{ .status = .secure, .proven_until_ns = expires }, expires);
    return true;
}

/// Append `rrs` with the TTL they have left.
fn aged(g: *Graph, out: *std.ArrayList(RR), rrs: []const RR, stored_ns: i64) !void {
    const age: u32 = @intCast(@divTrunc(g.now() - stored_ns, std.time.ns_per_s));
    for (rrs) |rr| {
        var a = rr;
        a.ttl = rr.ttl -| age;
        try out.append(g.scratch.allocator(), a);
    }
}
