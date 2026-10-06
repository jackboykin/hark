//! RFC 8198 aggressive use, NSEC only. Every NSEC a secure negative
//! carried is the fact `rrset(owner, NSEC)`, its SOA the fact
//! `rrset(zone, SOA)`; this index orders the spans by owner within their
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

/// So the index cannot outgrow its facts, nor hold a replaced version.
pub fn evicted(g: *Graph, key: graph.Key) void {
    if (key.kind != .rrset or (key.rtype != .nsec and key.rtype != .soa)) return;
    const owner = dns.parseDottedName(g.scratch.allocator(), key.name) catch return;
    if (key.rtype == .soa) {
        var buf: [dns.max_dotted_len + 1]u8 = undefined;
        const i = g.denial.zones.getIndex(owner.formatLower(&buf)) orelse return;
        g.denial.zones.values()[i].release(g);
        dropIfEmpty(g, i);
        return;
    }
    for (0..owner.labels.len + 1) |i| {
        var buf: [dns.max_dotted_len + 1]u8 = undefined;
        const zone: dns.Name = .{ .labels = owner.labels[i..] };
        const zi = g.denial.zones.getIndex(zone.formatLower(&buf)) orelse continue;
        const z = &g.denial.zones.values()[zi];
        const pos = z.position(owner);
        if (pos < z.spans.items.len and z.spans.items[pos].owner.eql(owner)) {
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

/// A proof carries at most this many NSECs (closest encloser, next closer,
/// wildcard); the rest is stuffing.
const max_proofs = 8;

/// A secure negative's SOA and NSECs become facts, each for as long as
/// its own proof holds (RFC 8198 §5.4).
pub fn absorb(g: *Graph, signer: dns.Name, r: graph.Reply, proven_until: []const i64, keys_until: i64) !void {
    var kb: graph.KeyBuf = undefined;
    var buf: [dns.max_dotted_len + 1]u8 = undefined;
    const zkey = signer.formatLower(&buf);
    defer if (g.denial.zones.getIndex(zkey)) |i| dropIfEmpty(g, i);
    if (g.denial.zones.getPtr(zkey)) |z| z.prune(g);
    var proofs: usize = 0;
    for (r.authorities, 0..) |rr, i| {
        if ((rr.rtype != .nsec and rr.rtype != .soa) or !rr.name.isSubdomainOf(signer)) continue;
        if (rr.rtype == .soa and !rr.name.eql(signer)) continue;
        if (rr.rtype == .nsec and (minimal(rr) or proofs == max_proofs)) continue;
        const rrs = dnssec.setFrom(r.authorities, i);
        // The negative cap doubles as RFC 9077 §3's ceiling on aggressive use.
        const expires = @min(proven_until[i], keys_until, r.stored_ns + @as(i64, @min(rr.ttl, dns.max_negative_ttl)) * std.time.ns_per_s);
        const fact: graph.Reply = .{ .kind = .answer, .aa = true, .answers = rrs, .zone = signer, .stored_ns = r.stored_ns, .ttl = rr.ttl };
        // `fact` can re-enter `evicted` and drop this zone: look it up after.
        const judged = (try g.fact(graph.Key.of(&kb, .rrset, rr.name, rr.rtype), .{ .rrset = fact }, expires) orelse continue).ref();
        const z = zoneFor(g, zkey) catch |e| {
            g.store.unref(judged);
            return e;
        };
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

/// Never a DS: that is the parent's word at the cut alone (RFC 6840 §4.4),
/// and a proof from before the delegation would deny it (dnssec/033).
/// Never a DNSKEY: the chain of trust takes only keys (`trust.runDnskey`),
/// and a denial from memory would fail it without asking.
pub fn denies(g: *const Graph, qtype: dns.RType) bool {
    return g.cfg.trust_anchor != null and qtype != .ds and qtype != .dnskey;
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
    reply.ttl = @min(walk.replyTtl(reply), @as(u32, @intCast(@divTrunc(expires - now, std.time.ns_per_s))));
    // RFC 2308 §5: the SOA's minimum may end it before its proofs do.
    const minimum = for (soa.answers) |rr| {
        if (rr.rtype == .soa) break rr.rdata.soa.minimum;
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
    return Graph.init(testing.allocator, .{ .root_hints = &.{} }, .{ .ctx = ctx, .now_ns = now, .wall_sec = wall, .rng = @import("rand.zig").thread, .sendFn = Stub.send, .wakeFn = Stub.wake });
}

test "re-absorbing a spanless zone survives the store replacing its SOA" {
    var now: i64 = std.time.ns_per_s;
    var wall: i64 = 0;
    var ctx: u8 = 0;
    var g = try testGraph(&ctx, &now, &wall);
    defer g.deinit();
    g.attach();

    const zone: dns.Name = .{ .labels = &.{@as([]const u8, "example")} };
    const soa: RR = .{ .name = zone, .rtype = .soa, .rclass = .in, .ttl = 3600, .rdata = .{ .soa = .{ .mname = zone, .rname = zone, .serial = 1, .refresh = 1, .retry = 1, .expire = 1, .minimum = 3600 } } };
    const reply: graph.Reply = .{ .kind = .nodata, .aa = true, .authorities = &.{soa}, .stored_ns = now, .zone = zone };

    try absorb(&g, zone, reply, &.{std.math.maxInt(i64)}, now + 3600 * std.time.ns_per_s);
    try testing.expectEqual(@as(usize, 1), g.denial.zones.count());

    try absorb(&g, zone, reply, &.{std.math.maxInt(i64)}, now + 3600 * std.time.ns_per_s);
    try testing.expectEqual(@as(usize, 1), g.denial.zones.count());
    try testing.expect(g.denial.zones.getPtr("example").?.soa != null);
}
