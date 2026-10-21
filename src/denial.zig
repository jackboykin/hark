//! RFC 8198 aggressive use, NSEC only. Every NSEC a secure negative
//! carried is the fact `rrset(owner, NSEC)`, or `parental(owner, NSEC)`
//! where its zone delegates the owner; its SOA the fact
//! `rrset(zone, SOA)`. This index orders the spans by owner within their
//! signing zone, each holding the very bytes that were judged, so a later
//! question inside a known span is denied from memory and no later reply
//! can change what the span says. The index only finds candidates: the
//! verdict is `validateNegativeProof`'s.
const std = @import("std");
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");
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
    buf: []u8,
    judged: *store.Blob,

    fn deinit(sp: Span, gpa: std.mem.Allocator, st: *store.Store) void {
        gpa.free(sp.buf);
        st.unref(sp.judged);
    }

    fn init(gpa: std.mem.Allocator, rr: RR, expires_ns: i64, judged: *store.Blob) !Span {
        var folded: dns.Name.Buf = undefined;
        const n = rr.nsec(&folded);
        const owner = rr.name.wire;
        const next = n.next_domain_name.wire;
        const buf = try gpa.alloc(u8, owner.len + next.len + n.type_bit_maps.len);
        @memcpy(buf[0..owner.len], owner);
        @memcpy(buf[owner.len..][0..next.len], next);
        @memcpy(buf[owner.len + next.len ..], n.type_bit_maps);
        return .{
            .owner = .of(buf[0..owner.len]),
            .nsec = .{ .next_domain_name = .of(buf[owner.len..][0..next.len]), .type_bit_maps = buf[owner.len + next.len ..] },
            .expires_ns = expires_ns,
            .buf = buf,
            .judged = judged,
        };
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
            if (z.spans.items[mid].owner.order(name) == .lt) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    fn exact(z: *const Zone, g: *Graph, name: dns.Name) ?*const Span {
        const pos = z.position(name);
        if (pos == z.spans.items.len) return null;
        const sp = &z.spans.items[pos];
        return if (sp.owner.eql(name) and sp.expires_ns > g.instant()) sp else null;
    }

    /// The span whose range holds `name` (RFC 6840 §4.1); the last owner
    /// wraps to cover what sorts before the first.
    fn span(z: *const Zone, g: *Graph, name: dns.Name) ?*const Span {
        const n = z.spans.items.len;
        if (n == 0) return null;
        const pos = z.position(name);
        for ([_]usize{ if (pos > 0) pos - 1 else n - 1, n - 1 }) |i| {
            const sp = &z.spans.items[i];
            if (sp.expires_ns > g.instant() and proof.nsecCovers(sp.owner, sp.nsec, name)) return sp;
        }
        return null;
    }
};

pub const Index = struct {
    zones: std.array_hash_map.String(Zone) = .empty,

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

/// So the index cannot outgrow its facts: what goes is what was judged
/// from `blob`.
pub fn evicted(g: *Graph, key: graph.Key, blob: *store.Blob) void {
    if (key.rtype != .nsec and key.rtype != .soa) return;
    const owner: dns.Name = .of(key.name);
    if (key.rtype == .soa) {
        const i = g.denial.zones.getIndex(owner.wire) orelse return;
        const soa = g.denial.zones.values()[i].soa orelse return;
        if (soa.judged != blob) return;
        g.denial.zones.values()[i].release(g);
        dropIfEmpty(g, i);
        return;
    }
    var up: ?dns.Name = owner;
    while (up) |zone| : (up = zone.parent()) {
        const zi = g.denial.zones.getIndex(zone.wire) orelse continue;
        const z = &g.denial.zones.values()[zi];
        const pos = z.position(owner);
        if (pos < z.spans.items.len and z.spans.items[pos].judged == blob) {
            z.spans.items[pos].deinit(g.gpa, &g.store);
            _ = z.spans.orderedRemove(pos);
            dropIfEmpty(g, zi);
            return;
        }
    }
}

fn dropIfEmpty(g: *Graph, i: usize) void {
    const z = &g.denial.zones.values()[i];
    if (z.spans.items.len != 0 or z.soa != null) return;
    z.spans.deinit(g.gpa);
    const owned = g.denial.zones.keys()[i];
    g.denial.zones.swapRemoveAt(i);
    g.gpa.free(owned);
}

fn zoneFor(g: *Graph, key: []const u8) !*Zone {
    const gop = try g.denial.zones.getOrPut(g.gpa, key);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
        gop.key_ptr.* = g.gpa.dupe(u8, gop.key_ptr.*) catch |e| {
            g.denial.zones.swapRemoveAt(gop.index);
            return e;
        };
    }
    return gop.value_ptr;
}

/// A secure negative's SOA and NSECs become facts, each for as long as
/// its own proof holds (RFC 8198 §5.4). A flood never proved anything.
pub fn absorb(g: *Graph, signer: dns.Name, r: graph.Reply, proven_until: []const i64, keys_until: i64) !void {
    std.debug.assert(!proof.proofFlood(r.authorities));
    const zkey = signer.wire;
    defer if (g.denial.zones.getIndex(zkey)) |i| dropIfEmpty(g, i);
    if (g.denial.zones.getPtr(zkey)) |z| z.prune(g);
    for (r.authorities, 0..) |rr, i| {
        if ((rr.rtype != .nsec and rr.rtype != .soa) or !rr.name.isSubdomainOf(signer)) continue;
        if (rr.rtype == .soa and !rr.name.eql(signer)) continue;
        if (rr.rtype == .nsec and minimal(rr)) continue;
        const rrs = dnssec.setFrom(r.authorities, i);
        const expires = @min(proven_until[i], keys_until, r.stored_ns + @as(i64, rr.ttl) * std.time.ns_per_s);
        const fact: graph.Reply = .{ .kind = .answer, .aa = true, .answers = rrs, .zone = signer, .stored_ns = r.stored_ns, .ttl = rr.ttl };
        const kind: graph.Kind = if (rr.rtype == .nsec and delegated(rr, signer)) .parental else .rrset;
        // `fact` can re-enter `evicted` and drop this zone: look it up after.
        const judged = (try g.fact(graph.Key.of(kind, rr.name, rr.rtype), .{ .rrset = fact }, expires) orelse continue).ref();
        const z = zoneFor(g, zkey) catch |e| {
            g.store.unref(judged);
            return e;
        };
        if (rr.rtype == .soa) {
            z.release(g);
            z.soa = .{ .judged = judged, .expires_ns = expires };
            continue;
        }
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

/// Of the two NSECs at a cut, the child's is the one at its own apex,
/// whatever either bitmap claims.
fn delegated(rr: RR, zone: dns.Name) bool {
    var next: dns.Name.Buf = undefined;
    return !rr.name.eql(zone) and dns.typeBitmapContains(rr.nsec(&next).type_bit_maps, .ns);
}

/// A range of one name (`owner NSEC \000.owner`, "black lies") denies
/// nothing but types at its owner.
fn minimal(rr: RR) bool {
    var buf: dns.Name.Buf = undefined;
    const next = rr.nsec(&buf).next_domain_name;
    const up = next.parent() orelse return false;
    return std.mem.eql(u8, next.leaf(), "\x00") and up.eql(rr.name);
}

/// Never a DS: that is the parent's word at the cut alone (RFC 6840 §4.4),
/// and a proof from before the delegation would deny it (dnssec/033).
/// Never a DNSKEY: the chain of trust takes only keys (`trust.runDnskey`),
/// and a denial from memory would fail it without asking.
pub fn denies(g: *const Graph, qtype: dns.RType) bool {
    return g.cfg.trust_anchors != null and qtype != .ds and qtype != .dnskey;
}

/// Settle `rrset(name, type)` as a denial from indexed proofs, if the
/// closest zone holding any can prove one: a span covering the name with
/// the wildcard at its closest encloser matched (NODATA) or covered
/// (NXDOMAIN), an exact owner (NODATA), or a span whose next name descends
/// below it (an empty non-terminal, NODATA). The verdict is stamped on the
/// reply; nothing is re-verified.
pub fn deny(g: *Graph, id: CellId) !bool {
    if (g.denial.zones.count() == 0 or !denies(g, g.cell(id).key.rtype)) return false;
    const name = g.cell(id).name;
    var up: ?dns.Name = name;
    while (up) |zone| : (up = zone.parent()) {
        const z = g.denial.zones.getPtr(zone.wire) orelse continue;
        if (try denyIn(g, z, id, zone)) return true;
    }
    return false;
}

fn denyIn(g: *Graph, z: *const Zone, id: CellId, zone: dns.Name) !bool {
    const name = g.cell(id).name;
    const qtype = g.cell(id).key.rtype;
    const now = g.now();
    const held = z.soa orelse return false;
    if (held.expires_ns <= g.instant()) return false;
    var proofs: [2]*const Span = undefined;
    var n: usize = 1;
    var nxdomain = false;
    if (z.span(g, name)) |cover| {
        proofs[0] = cover;
        if (proof.nsecProvesNameNonexistence(cover.owner, cover.nsec, name)) {
            const ce = proof.closestEncloser(name, cover.owner, cover.nsec.next_domain_name) orelse return false;
            var wc_buf: dns.Name.Buf = undefined;
            const wildcard = dns.Name.child(&wc_buf, "*", ce) orelse return false;
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
    reply.ttl = @min(walk.replyTtl(reply), @as(u32, @intCast(@divTrunc(expires - now, std.time.ns_per_s))));
    // RFC 2308 §5: the SOA's minimum may end it before its proofs do.
    const minimum = for (soa.answers) |rr| {
        if (rr.rtype == .soa) break rr.soa().minimum;
    } else 0;
    try g.settle(id, .{ .rrset = reply }, @min(expires, now + @as(i64, minimum) * std.time.ns_per_s));
    g.cell(id).blob.?.verdict.stamp(.{ .status = .secure, .proven_until_ns = expires }, expires, now);
    try g.keep(id);
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

const testing = std.testing;

fn testGraph(ctx: *u8, now: *const i64, wall: *const i64) !Graph {
    const Stub = struct {
        fn send(_: *anyopaque, _: graph.Exchange) anyerror!void {}
        fn wake(_: *anyopaque, _: CellId, _: u32, _: i64) anyerror!void {}
    };
    return Graph.init(testing.allocator, testing.allocator, .{ .root_hints = &.{} }, .{ .ctx = ctx, .now_ns = now, .wall_sec = wall, .rng = @import("rand.zig").thread, .sendFn = Stub.send, .wakeFn = Stub.wake });
}

test "re-absorbing a spanless zone survives the store replacing its SOA" {
    var now: i64 = std.time.ns_per_s;
    var wall: i64 = 0;
    var ctx: u8 = 0;
    var g = try testGraph(&ctx, &now, &wall);
    defer g.deinit();

    const zone: dns.Name = .lit("example");
    const soa: RR = .fixture(.{ .name = zone, .rtype = .soa, .rclass = .in, .ttl = 3600, .rdata = .{ .soa = .{ .mname = zone, .rname = zone, .serial = 1, .refresh = 1, .retry = 1, .expire = 1, .minimum = 3600 } } });
    const reply: graph.Reply = .{ .kind = .nodata, .aa = true, .authorities = &.{soa}, .stored_ns = now, .zone = zone };

    try absorb(&g, zone, reply, &.{std.math.maxInt(i64)}, now + 3600 * std.time.ns_per_s);
    try testing.expectEqual(@as(usize, 1), g.denial.zones.count());

    try absorb(&g, zone, reply, &.{std.math.maxInt(i64)}, now + 3600 * std.time.ns_per_s);
    try testing.expectEqual(@as(usize, 1), g.denial.zones.count());
    try testing.expect(g.denial.zones.getPtr(zone.wire).?.soa != null);
}
