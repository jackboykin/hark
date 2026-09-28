//! RFC 8198 aggressive use, NSEC only. Every NSEC a secure negative
//! carried is the fact `rrset(owner, NSEC)`, its SOA the fact
//! `rrset(zone, SOA)`; this index orders the spans by owner within their
//! signing zone, each holding the very bytes that were judged, so a later
//! question inside a known span is denied from memory and no later reply
//! can change what the span says. The index only finds candidates: the
//! verdict is `validateNegativeProof`'s.
const std = @import("std");
const dns = @import("dns.zig");
const proof = @import("proof.zig");
const graph = @import("graph.zig");
const walk = @import("walk.zig");

const store = @import("store.zig");

const Graph = graph.Graph;
const CellId = graph.CellId;
const RR = dns.ResourceRecord;

/// One NSEC's geometry, and the judged bytes it was cut from.
const Span = struct {
    owner: dns.Name,
    nsec: dns.NsecData,
    expires_ns: i64,
    buf: []align(8) u8,
    judged: *store.Blob,

    fn deinit(sp: Span, gpa: std.mem.Allocator, st: *store.Store) void {
        gpa.free(sp.buf);
        st.unref(sp.judged);
    }

    fn init(gpa: std.mem.Allocator, rr: RR, expires_ns: i64, judged: *store.Blob) !Span {
        const n = rr.rdata.nsec;
        const owner_len = std.mem.alignForward(usize, dns.nameFlatSize(rr.name), 8);
        const next_len = std.mem.alignForward(usize, dns.nameFlatSize(n.next_domain_name), 8);
        const buf = try gpa.alignedAlloc(u8, .fromByteUnits(8), owner_len + next_len + n.type_bit_maps.len);
        const owner = dns.writeNameFlat(buf[0..owner_len], rr.name, false);
        const next = dns.writeNameFlat(@alignCast(buf[owner_len..][0..next_len]), n.next_domain_name, false);
        const bits = buf[owner_len + next_len ..];
        @memcpy(bits, n.type_bit_maps);
        return .{ .owner = owner, .nsec = .{ .next_domain_name = next, .type_bit_maps = bits }, .expires_ns = expires_ns, .buf = buf, .judged = judged };
    }
};

const Zone = struct {
    /// In canonical owner order.
    spans: std.ArrayList(Span) = .empty,
    soa: ?struct { judged: *store.Blob, expires_ns: i64 } = null,

    /// Drop what has expired, so the neighbour of a name is a live proof.
    fn prune(z: *Zone, g: *Graph) void {
        if (z.soa) |soa| if (soa.expires_ns <= g.now()) z.release(g);
        var w: usize = 0;
        for (z.spans.items) |sp| if (sp.expires_ns > g.now()) {
            z.spans.items[w] = sp;
            w += 1;
        } else sp.deinit(g.gpa, &g.store);
        z.spans.shrinkRetainingCapacity(w);
    }

    fn release(z: *Zone, g: *Graph) void {
        if (z.soa) |soa| g.store.unref(soa.judged);
        z.soa = null;
    }

    /// Where `name` sorts among the owners.
    fn position(z: *const Zone, name: dns.Name) usize {
        var lo: usize = 0;
        var hi: usize = z.spans.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (proof.canonicalNameOrder(z.spans.items[mid].owner, name) == .lt) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    fn exact(z: *const Zone, g: *Graph, name: dns.Name) ?*const Span {
        const pos = z.position(name);
        if (pos == z.spans.items.len) return null;
        const sp = &z.spans.items[pos];
        return if (sp.owner.eql(name) and sp.expires_ns > g.bound(g.payer)) sp else null;
    }

    /// The span whose range holds `name` (RFC 6840 §4.1); the last owner
    /// wraps to cover what sorts before the first.
    fn span(z: *const Zone, g: *Graph, name: dns.Name) ?*const Span {
        const n = z.spans.items.len;
        if (n == 0) return null;
        const pos = z.position(name);
        for ([_]usize{ if (pos > 0) pos - 1 else n - 1, n - 1 }) |i| {
            const sp = &z.spans.items[i];
            if (sp.expires_ns > g.bound(g.payer) and proof.nsecCovers(sp.owner, sp.nsec, name)) return sp;
        }
        return null;
    }
};

pub const Index = struct {
    zones: std.StringHashMapUnmanaged(Zone) = .empty,

    pub fn deinit(ix: *Index, gpa: std.mem.Allocator, st: *store.Store) void {
        var it = ix.zones.iterator();
        while (it.next()) |e| {
            for (e.value_ptr.spans.items) |sp| sp.deinit(gpa, st);
            if (e.value_ptr.soa) |soa| st.unref(soa.judged);
            e.value_ptr.spans.deinit(gpa);
            gpa.free(e.key_ptr.*);
        }
        ix.zones.deinit(gpa);
    }
};

/// So the index cannot outgrow its facts, nor hold a replaced version.
pub fn evicted(g: *Graph, key: graph.Key) void {
    if (key.kind != .rrset or (key.rtype != .nsec and key.rtype != .soa)) return;
    const owner = dns.parseDottedName(g.scratch.allocator(), key.name) catch return;
    if (key.rtype == .soa) {
        var buf: [dns.max_dotted_len + 1]u8 = undefined;
        if (g.denial.zones.getPtr(owner.formatLower(&buf))) |z| z.release(g);
        return;
    }
    for (0..owner.labels.len + 1) |i| {
        var buf: [dns.max_dotted_len + 1]u8 = undefined;
        const zone: dns.Name = .{ .labels = owner.labels[i..] };
        const z = g.denial.zones.getPtr(zone.formatLower(&buf)) orelse continue;
        const pos = z.position(owner);
        if (pos < z.spans.items.len and z.spans.items[pos].owner.eql(owner)) {
            z.spans.items[pos].deinit(g.gpa, &g.store);
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
    var kb: graph.KeyBuf = undefined;
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
        const fact: graph.Reply = .{ .kind = .answer, .aa = true, .answers = rrs, .zone = signer, .stored_ns = r.stored_ns, .ttl = rr.ttl };
        const judged = (try g.publish(graph.Key.of(&kb, .rrset, rr.name, rr.rtype), by, .{ .rrset = fact }, expires) orelse continue).ref();
        if (rr.rtype == .soa) {
            z.release(g);
            z.soa = .{ .judged = judged, .expires_ns = expires };
            continue;
        }
        proofs += 1;
        const sp = Span.init(g.gpa, rr, expires, judged) catch |e| {
            g.store.unref(judged);
            return e;
        };
        const pos = z.position(rr.name);
        if (pos < z.spans.items.len and z.spans.items[pos].owner.eql(rr.name)) {
            z.spans.items[pos].deinit(g.gpa, &g.store);
            z.spans.items[pos] = sp;
        } else z.spans.insert(g.gpa, pos, sp) catch |e| {
            sp.deinit(g.gpa, &g.store);
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

/// `rr` followed by the signatures over it, already bounded by the walk.
fn withSigs(g: *Graph, rrs: []const RR, rr: RR) ![]const RR {
    var keep: std.ArrayList(RR) = .empty;
    try keep.append(g.scratch.allocator(), rr);
    for (rrs) |s| if (s.rtype == .rrsig and s.name.eql(rr.name) and s.rdata.rrsig.type_covered == rr.rtype) try keep.append(g.scratch.allocator(), s);
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
    const held = z.soa orelse return false;
    if (held.expires_ns <= g.bound(g.payer)) return false;
    var proofs: [2]*const Span = undefined;
    var n: usize = 1;
    var nxdomain = false;
    if (z.span(g, name)) |cover| {
        proofs[0] = cover;
        if (proof.nsecProvesNameNonexistence(cover.owner, cover.nsec, name)) {
            const ce = proof.closestEncloser(name, cover.owner, cover.nsec.next_domain_name) orelse return false;
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

    var expires = held.expires_ns;
    var authorities: std.ArrayList(RR) = .empty;
    const soa = (try store.Store.parse(g.scratch.allocator(), held.judged)).rrset;
    try aged(g, &authorities, soa.answers, soa.stored_ns);
    for (proofs[0..n]) |p| {
        expires = @min(expires, p.expires_ns);
        const fact = (try store.Store.parse(g.scratch.allocator(), p.judged)).rrset;
        try aged(g, &authorities, fact.answers, fact.stored_ns);
    }
    const budget = &g.payer.validation;
    if (proof.validateNegativeProof(authorities.items, name, qtype, nxdomain, zone, budget) != .secure) return false;

    var reply: graph.Reply = .{
        .kind = if (nxdomain) .nxdomain else .nodata,
        .aa = true,
        .authorities = authorities.items,
        .target = name,
        .zone = zone,
        .ede = .synthesized,
        .stored_ns = now,
    };
    reply.ttl = @min(walk.replyTtl(g, reply), @as(u32, @intCast(@divTrunc(expires - now, std.time.ns_per_s))));
    // RFC 2308 §5: the SOA's minimum may end it before its proofs do.
    const minimum = for (soa.answers) |rr| {
        if (rr.rtype == .soa) break rr.rdata.soa.minimum;
    } else 0;
    try g.settle(id, .{ .rrset = reply }, @min(expires, now + @as(i64, minimum) * std.time.ns_per_s));
    g.cell(id).blob.?.verdict.stamp(.{ .status = .secure, .proven_until_ns = expires }, expires, now);
    return true;
}

/// Append `rrs` with the TTL they have left.
fn aged(g: *Graph, out: *std.ArrayList(RR), rrs: []const RR, stored_ns: i64) !void {
    const age = walk.ageOf(stored_ns, g.now());
    for (rrs) |rr| {
        var a = rr;
        a.ttl = rr.ttl -| age;
        try out.append(g.scratch.allocator(), a);
    }
}
