//! RFC 8198 aggressive use of denials. Every NSEC a secure proof rested
//! on is the fact `rrset(owner, NSEC)`, or `span(owner, NSEC)` where its
//! zone delegates the owner; every NSEC3 the fact `span(owner, NSEC3)`;
//! a denial's SOA the fact `rrset(zone, SOA)`. This index orders the
//! spans within their signing zone, one chain to each parameter set, to
//! find the candidates that deny a later question from memory; the
//! verdict is `validateNegativeProof`'s.
const std = @import("std");
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");
const proof = @import("proof.zig");
const rrsig = @import("rrsig.zig");
const graph = @import("graph.zig");
const model = @import("model.zig");
const rand = @import("rand.zig");
const walk = @import("walk.zig");

const store = @import("store.zig");

const Graph = graph.Graph;
const CellId = model.CellId;
const RR = dns.ResourceRecord;

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

const Held = struct { judged: *store.Blob, expires_ns: i64 };

const Hash = proof.Hash;

const Hashed = struct {
    owner: Hash,
    next: Hash,
    expires_ns: i64,
    judged: *store.Blob,

    fn width(sp: Hashed) Hash {
        var out: Hash = undefined;
        var borrow: u1 = 0;
        var i = out.len;
        while (i > 0) : (i -= 1) {
            const x, const b1 = @subWithOverflow(sp.next[i - 1], sp.owner[i - 1]);
            out[i - 1], const b2 = @subWithOverflow(x, borrow);
            borrow = b1 | b2;
        }
        return out;
    }
};

/// The NSEC3 of one parameter set (RFC 5155 §8.2): nothing of another
/// may stand in a proof beside them.
const Chain = struct {
    params: proof.Nsec3Params,
    spans: std.ArrayList(Hashed) = .empty,

    /// A zone of fewer names is held whole. Past it, hashes scatter too
    /// thin for a read to land.
    const max_spans = 1024;

    fn deinit(c: *Chain, gpa: std.mem.Allocator, st: *store.Store) void {
        for (c.spans.items) |sp| st.unref(sp.judged);
        c.spans.deinit(gpa);
        gpa.free(c.params.salt);
    }

    fn position(c: *const Chain, hash: *const Hash) usize {
        var lo: usize = 0;
        var hi: usize = c.spans.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (std.mem.order(u8, &c.spans.items[mid].owner, hash) == .lt) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    fn exact(c: *const Chain, g: *Graph, hash: *const Hash) ?*const Hashed {
        const pos = c.position(hash);
        if (pos == c.spans.items.len) return null;
        const sp = &c.spans.items[pos];
        return if (std.mem.eql(u8, &sp.owner, hash) and sp.expires_ns > g.instant()) sp else null;
    }

    fn cover(c: *const Chain, g: *Graph, hash: *const Hash) ?*const Hashed {
        const n = c.spans.items.len;
        if (n == 0) return null;
        const pos = c.position(hash);
        const sp = &c.spans.items[if (pos > 0) pos - 1 else n - 1];
        const after = std.mem.order(u8, &sp.owner, hash) == .lt;
        const before = std.mem.order(u8, hash, &sp.next) == .lt;
        const wraps = std.mem.order(u8, &sp.owner, &sp.next) != .lt;
        const within = if (wraps) after or before else after and before;
        return if (within and sp.expires_ns > g.instant()) sp else null;
    }

    fn hashOf(c: *const Chain, name: dns.Name, allowance: *rrsig.ValidationBudget) ?Hash {
        return c.params.hash(name, allowance) catch null;
    }

    fn thinnest(c: *const Chain) usize {
        var thin: usize = 0;
        for (c.spans.items, 0..) |x, i| if (std.mem.order(u8, &x.width(), &c.spans.items[thin].width()) == .lt) {
            thin = i;
        };
        return thin;
    }

    /// Takes the caller's reference. Full, the chain keeps its widest.
    fn hold(c: *Chain, gpa: std.mem.Allocator, st: *store.Store, sp: Hashed) void {
        var pos = c.position(&sp.owner);
        if (pos < c.spans.items.len and std.mem.eql(u8, &c.spans.items[pos].owner, &sp.owner)) {
            st.unref(c.spans.items[pos].judged);
            c.spans.items[pos] = sp;
            return;
        }
        if (c.spans.items.len == max_spans) {
            const thin = c.thinnest();
            if (std.mem.order(u8, &sp.width(), &c.spans.items[thin].width()) != .gt) return st.unref(sp.judged);
            st.unref(c.spans.orderedRemove(thin).judged);
            pos = c.position(&sp.owner);
        }
        c.spans.insert(gpa, pos, sp) catch st.unref(sp.judged);
    }
};

const Zone = struct {
    spans: std.ArrayList(Span) = .empty,
    chains: std.ArrayList(Chain) = .empty,
    soa: ?Held = null,

    fn prune(z: *Zone, g: *Graph) void {
        if (z.soa) |soa| if (soa.expires_ns <= g.now()) z.release(g);
        var w: usize = 0;
        for (z.spans.items) |sp| if (sp.expires_ns > g.now()) {
            z.spans.items[w] = sp;
            w += 1;
        } else sp.deinit(g.store.gpa, &g.store);
        z.spans.shrinkRetainingCapacity(w);
        for (z.chains.items) |*c| {
            w = 0;
            for (c.spans.items) |sp| if (sp.expires_ns > g.now()) {
                c.spans.items[w] = sp;
                w += 1;
            } else g.store.unref(sp.judged);
            c.spans.shrinkRetainingCapacity(w);
        }
        z.dropEmptyChains(g.store.gpa, &g.store);
    }

    fn dropEmptyChains(z: *Zone, gpa: std.mem.Allocator, st: *store.Store) void {
        var i = z.chains.items.len;
        while (i > 0) : (i -= 1) if (z.chains.items[i - 1].spans.items.len == 0) {
            var gone = z.chains.swapRemove(i - 1);
            gone.deinit(gpa, st);
        };
    }

    fn chain(z: *Zone, gpa: std.mem.Allocator, params: proof.Nsec3Params) !*Chain {
        for (z.chains.items) |*c| if (c.params.eql(params)) return c;
        const owned = try gpa.dupe(u8, params.salt);
        errdefer gpa.free(owned);
        try z.chains.append(gpa, .{ .params = .{ .salt = owned, .iterations = params.iterations } });
        return &z.chains.items[z.chains.items.len - 1];
    }

    fn release(z: *Zone, g: *Graph) void {
        if (z.soa) |soa| g.store.unref(soa.judged);
        z.soa = null;
    }

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

    fn span(z: *const Zone, g: *Graph, name: dns.Name) ?*const Span {
        const n = z.spans.items.len;
        if (n == 0) return null;
        const pos = z.position(name);
        // The owner just before `name`, or the last owner, whose range wraps to
        // cover what sorts before the first.
        for ([_]usize{ if (pos > 0) pos - 1 else n - 1, n - 1 }) |i| {
            const sp = &z.spans.items[i];
            if (sp.expires_ns > g.instant() and proof.nsecCovers(sp.owner, sp.nsec, name)) return sp;
        }
        return null;
    }
};

pub const Index = struct {
    zones: std.array_hash_map.Custom([]const u8, Zone, rand.Keyed, true) = .empty,

    pub fn deinit(ix: *Index, gpa: std.mem.Allocator, st: *store.Store) void {
        var it = ix.zones.iterator();
        while (it.next()) |e| {
            for (e.value_ptr.spans.items) |sp| sp.deinit(gpa, st);
            for (e.value_ptr.chains.items) |*c| c.deinit(gpa, st);
            e.value_ptr.chains.deinit(gpa);
            if (e.value_ptr.soa) |soa| st.unref(soa.judged);
            e.value_ptr.spans.deinit(gpa);
            gpa.free(e.key_ptr.*);
        }
        ix.zones.deinit(gpa);
    }
};

pub fn evicted(g: *Graph, blob: *store.Blob) void {
    const key = blob.key();
    if (key.rtype != .nsec and key.rtype != .soa and key.rtype != .nsec3) return;
    const owner: dns.Name = .of(key.name);
    if (key.rtype == .nsec3) return evictedHashed(g, blob, owner);
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
            z.spans.items[pos].deinit(g.store.gpa, &g.store);
            _ = z.spans.orderedRemove(pos);
            dropIfEmpty(g, zi);
            return;
        }
    }
}

fn evictedHashed(g: *Graph, blob: *store.Blob, owner: dns.Name) void {
    const hash = proof.nsec3OwnerHash(owner) orelse return;
    const zi = g.denial.zones.getIndex((owner.parent() orelse return).wire) orelse return;
    const z = &g.denial.zones.values()[zi];
    for (z.chains.items) |*c| {
        const pos = c.position(&hash);
        if (pos == c.spans.items.len or c.spans.items[pos].judged != blob) continue;
        g.store.unref(c.spans.orderedRemove(pos).judged);
        z.dropEmptyChains(g.store.gpa, &g.store);
        return dropIfEmpty(g, zi);
    }
}

fn dropIfEmpty(g: *Graph, i: usize) void {
    const z = &g.denial.zones.values()[i];
    if (z.spans.items.len != 0 or z.chains.items.len != 0 or z.soa != null) return;
    z.chains.deinit(g.store.gpa);
    z.spans.deinit(g.store.gpa);
    const owned = g.denial.zones.keys()[i];
    g.denial.zones.swapRemoveAt(i);
    g.store.gpa.free(owned);
}

fn zoneFor(g: *Graph, key: []const u8) !*Zone {
    const gop = try g.denial.zones.getOrPut(g.store.gpa, key);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
        gop.key_ptr.* = g.store.gpa.dupe(u8, gop.key_ptr.*) catch |e| {
            g.denial.zones.swapRemoveAt(gop.index);
            return e;
        };
    }
    return gop.value_ptr;
}

pub fn absorb(g: *Graph, signer: dns.Name, r: model.Reply, proven_until: []const i64, keys_until: i64) !void {
    std.debug.assert(!proof.proofFlood(r.authorities));
    const zkey = signer.wire;
    defer if (g.denial.zones.getIndex(zkey)) |i| dropIfEmpty(g, i);
    if (g.denial.zones.getPtr(zkey)) |z| z.prune(g);
    var sets: dnssec.Sets = .{ .rrs = r.authorities };
    while (sets.next()) |rrs| {
        // A set is one fact. The index holds one span an owner, so of a set
        // of several NSEC the last stands.
        var last: ?RR = null;
        for (rrs) |x| if (x.rtype != .rrsig and !(x.rtype == .nsec and minimal(x))) {
            last = x;
        };
        const rr = last orelse continue;
        if ((rr.rtype != .nsec and rr.rtype != .soa and rr.rtype != .nsec3) or !rr.name.isSubdomainOf(signer)) continue;
        if (rr.rtype == .soa and !rr.name.eql(signer)) continue;
        const hashed: ?Hash = if (rr.rtype == .nsec3) chained(rr, signer) orelse continue else null;
        const expires = @min(proven_until[sets.at], keys_until, r.stored_ns + @as(i64, rr.ttl) * std.time.ns_per_s);
        const fact: model.Reply = .{ .kind = .answer, .aa = true, .answers = rrs, .zone = signer, .stored_ns = r.stored_ns, .ttl = rr.ttl };
        const kind: model.Kind = if (hashed != null or (rr.rtype == .nsec and delegated(rr, signer))) .span else .rrset;
        // `fact` can re-enter `evicted` and drop this zone: look it up only after.
        const judged = (try g.fact(model.Key.of(kind, rr.name, rr.rtype), .{ .rrset = fact }, expires) orelse continue).ref();
        const z = zoneFor(g, zkey) catch |e| {
            g.store.unref(judged);
            return e;
        };
        if (rr.rtype == .soa) {
            z.release(g);
            z.soa = .{ .judged = judged, .expires_ns = expires };
            continue;
        }
        if (hashed) |owner| {
            const n3 = rr.nsec3();
            const c = z.chain(g.store.gpa, .{ .salt = n3.salt, .iterations = n3.iterations }) catch |e| {
                g.store.unref(judged);
                return e;
            };
            c.hold(g.store.gpa, &g.store, .{ .owner = owner, .next = n3.next_hashed_owner[0..@sizeOf(Hash)].*, .expires_ns = expires, .judged = judged });
            continue;
        }
        const sp = Span.init(g.store.gpa, rr, expires, judged) catch |e| {
            g.store.unref(judged);
            return e;
        };
        const pos = z.position(rr.name);
        if (pos < z.spans.items.len and z.spans.items[pos].owner.eql(rr.name)) {
            z.spans.items[pos].deinit(g.store.gpa, &g.store);
            z.spans.items[pos] = sp;
        } else z.spans.insert(g.store.gpa, pos, sp) catch |e| {
            sp.deinit(g.store.gpa, &g.store);
            return e;
        };
    }
}

fn chained(rr: RR, zone: dns.Name) ?Hash {
    if (!(rr.name.parent() orelse return null).eql(zone) or rr.nsec3().next_hashed_owner.len != @sizeOf(Hash)) return null;
    return proof.supportedNsec3OwnerHash(rr, zone);
}

fn delegated(rr: RR, zone: dns.Name) bool {
    var next: dns.Name.Buf = undefined;
    return !rr.name.eql(zone) and dns.typeBitmapContains(rr.nsec(&next).type_bit_maps, .ns);
}

/// `owner NSEC \000.owner` ("black lies") spans one name and denies only
/// types at its owner, so it is no use as a range.
fn minimal(rr: RR) bool {
    var buf: dns.Name.Buf = undefined;
    const next = rr.nsec(&buf).next_domain_name;
    const up = next.parent() orelse return false;
    return std.mem.eql(u8, next.leaf(), "\x00") and up.eql(rr.name);
}

/// Never DS: only the parent may deny it at a cut (RFC 6840 §4.4), and a
/// proof from before the delegation existed would. Never DNSKEY: a denial
/// from memory would fail the chain of trust without asking.
pub fn denies(g: *const Graph, qtype: dns.RType) bool {
    return g.cfg.trust_anchors != null and qtype != .ds and qtype != .dnskey;
}

pub const Read = struct { reply: model.Reply, expires_ns: i64, proven_until_ns: i64 };

const Asked = struct {
    g: *Graph,
    arena: std.mem.Allocator,
    name: dns.Name,
    qtype: dns.RType,
    allowance: *rrsig.ValidationBudget,
};

pub fn deny(g: *Graph, id: CellId) !bool {
    const r = try read(g, g.scratch.allocator(), g.cell(id).name, g.cell(id).key.rtype) orelse return false;
    try g.settle(id, .{ .rrset = r.reply }, r.expires_ns);
    g.cell(id).blob.?.verdict.stamp(.{ .status = .secure, .proven_until_ns = r.proven_until_ns }, r.proven_until_ns, g.now());
    g.keep(id);
    return true;
}

pub fn read(g: *Graph, arena: std.mem.Allocator, name: dns.Name, qtype: dns.RType) !?Read {
    if (g.denial.zones.count() == 0 or !denies(g, qtype)) return null;
    if (try g.skips(.read, .of(.rrset, name, qtype))) return null;
    // Never the question's budget: a miss leaves the fetch all of it.
    var hashes: rrsig.Hashes = .{};
    var allowance: rrsig.ValidationBudget = .{ .max_sig_verify = 0, .max_nsec3_blocks = read_blocks, .hashes = &hashes };
    const q: Asked = .{ .g = g, .arena = arena, .name = name, .qtype = qtype, .allowance = &allowance };
    var up: ?dns.Name = name;
    while (up) |zone| : (up = zone.parent()) {
        const z = g.denial.zones.getPtr(zone.wire) orelse continue;
        if (try denyUnder(&q, z, zone)) |r| return r;
        if (try expand(&q, z, zone)) |r| return r;
    }
    return null;
}

/// A denial carries its zone's SOA (RFC 2308 §3), so none is read without one held.
fn denyUnder(q: *const Asked, z: *const Zone, zone: dns.Name) !?Read {
    const soa = z.soa orelse return null;
    if (soa.expires_ns <= q.g.instant()) return null;
    if (try denyIn(q, z, soa, zone)) |r| return r;
    for (z.chains.items) |*c| if (try denyHashed(q, c, soa, zone)) |r| return r;
    return null;
}

/// RFC 8198 §5.3: a wildcard's own set, held judged under its own name,
/// answers a name that nothing closer matches.
fn expand(q: *const Asked, z: *const Zone, zone: dns.Name) !?Read {
    const g = q.g;
    var up = q.name.parent();
    while (up) |encloser| : (up = encloser.parent()) {
        if (encloser.depth() < zone.depth()) break;
        var buf: dns.Name.Buf = undefined;
        const wildcard = dns.Name.child(&buf, "*", encloser) orelse continue;
        const alias = if (walk.cnameAnswers(q.qtype)) g.proven(.of(.rrset, wildcard, .cname)) else null;
        const source = g.proven(.of(.rrset, wildcard, q.qtype)) orelse alias orelse continue;
        if (z.span(g, q.name)) |cover| {
            if (try expandOver(q, zone, source, encloser, .{ .judged = cover.judged, .expires_ns = cover.expires_ns })) |r| return r;
        }
        for (z.chains.items) |*c| {
            const hash = c.hashOf(q.name.ancestor(encloser.depth() + 1), q.allowance) orelse return null;
            const cover = c.cover(g, &hash) orelse continue;
            if (try expandOver(q, zone, source, encloser, .{ .judged = cover.judged, .expires_ns = cover.expires_ns })) |r| return r;
        }
    }
    return null;
}

fn expandOver(q: *const Asked, zone: dns.Name, source: *store.Blob, encloser: dns.Name, cover: Held) !?Read {
    const now = q.g.now();
    const held = (try store.Store.parse(q.arena, source)).rrset;
    if (held.kind != .answer and held.kind != .alias) return null;
    var signed = false;
    var answers: std.ArrayList(RR) = .empty;
    for (held.answers) |rr| {
        if (rr.name.depth() != encloser.depth() + 1 or !rr.name.isSubdomainOf(encloser)) return null;
        if (rr.rtype == .rrsig) {
            // A source counts only as this zone signed it at this wildcard.
            if (!rr.rrsig().signer_name.eql(zone) or rr.rrsig().labels != encloser.depth()) return null;
            signed = true;
        }
        var at = rr;
        at.name = q.name;
        at.ttl = rr.ttl -| walk.ageOf(held.stored_ns, now);
        try answers.append(q.arena, at);
    }
    if (!signed) return null;
    var authorities: std.ArrayList(RR) = .empty;
    const spans = (try store.Store.parse(q.arena, cover.judged)).rrset;
    try aged(q, &authorities, spans.answers, spans.stored_ns);
    if (proof.proveNoCloserMatch(authorities.items, q.name, encloser.depth(), zone, q.allowance) != .secure) return null;

    const expires = @min(source.end(), cover.expires_ns);
    var reply: model.Reply = .{ .kind = held.kind, .aa = true, .answers = answers.items, .authorities = authorities.items, .target = held.target, .zone = zone, .ede = .synthesized, .stored_ns = now };
    reply.ttl = @min(walk.replyTtl(reply), @as(u32, @intCast(@divTrunc(expires - now, std.time.ns_per_s))));
    return .{ .reply = reply, .expires_ns = expires, .proven_until_ns = expires };
}

/// SHA-1 blocks one read may hash.
const read_blocks = 128;

/// RFC 5155 §8.4 to §8.7 over one chain.
fn denyHashed(q: *const Asked, c: *const Chain, soa: Held, zone: dns.Name) !?Read {
    const g = q.g;
    var closer = c.hashOf(q.name, q.allowance) orelse return null;
    if (c.exact(g, &closer)) |at| return weigh(q, zone, soa, &.{.{ .judged = at.judged, .expires_ns = at.expires_ns }}, false);
    var up = q.name.parent();
    const encloser, const exists = while (up) |a| : (up = a.parent()) {
        if (a.depth() < zone.depth()) return null;
        const hash = c.hashOf(a, q.allowance) orelse return null;
        if (c.exact(g, &hash)) |at| break .{ a, at };
        closer = hash;
    } else return null;
    const gap = c.cover(g, &closer) orelse return null;
    var wc_buf: dns.Name.Buf = undefined;
    const wildcard = dns.Name.child(&wc_buf, "*", encloser) orelse return null;
    const hash = c.hashOf(wildcard, q.allowance) orelse return null;
    const nxdomain = c.exact(g, &hash) == null;
    const wild = c.exact(g, &hash) orelse c.cover(g, &hash) orelse return null;
    var proofs: [3]Held = undefined;
    var n: usize = 0;
    for ([_]*const Hashed{ exists, gap, wild }, 0..) |sp, i| {
        if (i == 2 and sp == gap) continue;
        proofs[n] = .{ .judged = sp.judged, .expires_ns = sp.expires_ns };
        n += 1;
    }
    return weigh(q, zone, soa, proofs[0..n], nxdomain);
}

fn denyIn(q: *const Asked, z: *const Zone, soa: Held, zone: dns.Name) !?Read {
    const g = q.g;
    var proofs: [2]*const Span = undefined;
    var n: usize = 1;
    var nxdomain = false;
    if (z.span(g, q.name)) |cover| {
        proofs[0] = cover;
        if (proof.nsecProvesNameNonexistence(cover.owner, cover.nsec, q.name)) {
            const ce = proof.closestEncloser(q.name, cover.owner, cover.nsec.next_domain_name) orelse return null;
            var wc_buf: dns.Name.Buf = undefined;
            const wildcard = dns.Name.child(&wc_buf, "*", ce) orelse return null;
            if (z.exact(g, wildcard)) |wc| {
                proofs[1] = wc;
            } else if (z.span(g, wildcard)) |wc| {
                proofs[1] = wc;
                nxdomain = true;
            } else return null;
            n += @intFromBool(proofs[1] != cover);
        }
    } else proofs[0] = z.exact(g, q.name) orelse return null;
    var held: [2]Held = undefined;
    for (held[0..n], proofs[0..n]) |*h, p| h.* = .{ .judged = p.judged, .expires_ns = p.expires_ns };
    return weigh(q, zone, soa, held[0..n], nxdomain);
}

fn weigh(q: *const Asked, zone: dns.Name, held: Held, proofs: []const Held, nxdomain: bool) !?Read {
    const now = q.g.now();
    var expires = held.expires_ns;
    var authorities: std.ArrayList(RR) = .empty;
    const soa = (try store.Store.parse(q.arena, held.judged)).rrset;
    try aged(q, &authorities, soa.answers, soa.stored_ns);
    for (proofs) |p| {
        expires = @min(expires, p.expires_ns);
        const fact = (try store.Store.parse(q.arena, p.judged)).rrset;
        try aged(q, &authorities, fact.answers, fact.stored_ns);
    }
    if (proof.validateNegativeProof(authorities.items, q.name, q.qtype, nxdomain, zone, q.allowance) != .secure) return null;

    var reply: model.Reply = .{
        .kind = if (nxdomain) .nxdomain else .nodata,
        .aa = true,
        .authorities = authorities.items,
        .target = q.name,
        .zone = zone,
        .ede = .synthesized,
        .stored_ns = now,
    };
    reply.ttl = @min(walk.replyTtl(reply), @as(u32, @intCast(@divTrunc(expires - now, std.time.ns_per_s))));
    // RFC 2308 §5: the SOA minimum may end the denial before its proofs do.
    const minimum = for (soa.answers) |rr| {
        if (rr.rtype == .soa) break rr.soa().minimum;
    } else 0;
    return .{ .reply = reply, .expires_ns = @min(expires, now + @as(i64, minimum) * std.time.ns_per_s), .proven_until_ns = expires };
}

fn aged(q: *const Asked, out: *std.ArrayList(RR), rrs: []const RR, stored_ns: i64) !void {
    const age = walk.ageOf(stored_ns, q.g.now());
    for (rrs) |rr| {
        var a = rr;
        a.ttl = rr.ttl -| age;
        try out.append(q.arena, a);
    }
}

const testing = std.testing;

test "a read pays for a name's hash once" {
    var hashes: rrsig.Hashes = .{};
    var allowance: rrsig.ValidationBudget = .{ .max_sig_verify = 0, .max_nsec3_blocks = read_blocks, .hashes = &hashes };
    const c: Chain = .{ .params = .{ .salt = "s", .iterations = 10 } };
    const first = c.hashOf(.lit("a.example"), &allowance).?;
    const spent = allowance.nsec3_blocks_spent;
    const again = try c.params.hash(.lit("a.example"), &allowance);
    try testing.expectEqualSlices(u8, &first, &again);
    try testing.expectEqual(spent, allowance.nsec3_blocks_spent);
    const salted: proof.Nsec3Params = .{ .salt = "t", .iterations = 10 };
    _ = try salted.hash(.lit("a.example"), &allowance);
    try testing.expect(allowance.nsec3_blocks_spent > spent);
}

test "a chain dearer than a read's allowance goes unhashed" {
    var allowance: rrsig.ValidationBudget = .{ .max_sig_verify = 0, .max_nsec3_blocks = read_blocks };
    const cheap: Chain = .{ .params = .{ .salt = "", .iterations = 10 } };
    const dear: Chain = .{ .params = .{ .salt = "", .iterations = 200 } };
    try testing.expect(cheap.hashOf(.lit("a.example"), &allowance) != null);
    try testing.expectEqual(null, dear.hashOf(.lit("a.example"), &allowance));
}

test "a span is as wide as it reaches round the ring, and the narrowest is found by that" {
    const blob: *store.Blob = undefined;
    var c: Chain = .{ .params = .{ .salt = "", .iterations = 0 } };
    defer c.spans.deinit(testing.allocator);
    const ends = [_][2]u8{ .{ 0x10, 0x40 }, .{ 0x40, 0x48 }, .{ 0x48, 0xf0 }, .{ 0xf0, 0x10 } };
    for (ends) |e| {
        var sp: Hashed = .{ .owner = @splat(0), .next = @splat(0), .expires_ns = 0, .judged = blob };
        sp.owner[0] = e[0];
        sp.next[0] = e[1];
        try c.spans.append(testing.allocator, sp);
    }
    try testing.expectEqual(1, c.thinnest());
    try testing.expectEqual(0x20, c.spans.items[3].width()[0]);
    try testing.expectEqual(0xa8, c.spans.items[2].width()[0]);
}

fn testGraph(ctx: *u8, now: *const i64, wall: *const i64) !Graph {
    const Stub = struct {
        fn send(_: *anyopaque, _: graph.Exchange) graph.Error!graph.Exposure {
            return .none;
        }
        fn wake(_: *anyopaque, _: CellId, _: u32, _: i64) graph.Error!void {}
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
    const reply: model.Reply = .{ .kind = .nodata, .aa = true, .authorities = &.{soa}, .stored_ns = now, .zone = zone };

    try absorb(&g, zone, reply, &.{std.math.maxInt(i64)}, now + 3600 * std.time.ns_per_s);
    try testing.expectEqual(@as(usize, 1), g.denial.zones.count());

    try absorb(&g, zone, reply, &.{std.math.maxInt(i64)}, now + 3600 * std.time.ns_per_s);
    try testing.expectEqual(@as(usize, 1), g.denial.zones.count());
    try testing.expect(g.denial.zones.getPtr(zone.wire).?.soa != null);
}
