//! The chain of trust as cells: `ds(zone)`, `dnskey(zone)` and
//! `secure(rrset)`. The verdicts are decided here; the verification itself
//! is dnssec.zig's.
const std = @import("std");
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");
const proof = @import("proof.zig");
const rrsig = @import("rrsig.zig");
const graph = @import("graph.zig");
const denial = @import("denial.zig");
const walk = @import("walk.zig");

const Graph = graph.Graph;
const CellId = graph.CellId;
const OptionalCellId = graph.OptionalCellId;
const Failure = graph.Failure;
const RR = dns.ResourceRecord;

/// `absent`, for `ds` and `dnskey` only: the parent's signed denial shows no
/// delegation, so the name is no zone. Bogus is not a value: it fails.
pub const Proof = enum(u8) { secure, insecure, absent };

pub const Chain = struct {
    status: Proof,
    records: []const RR = &.{},
    proven_until_ns: i64 = std.math.maxInt(i64),
};

pub const DsScratch = struct {
    parent: OptionalCellId = .none,
    keys: OptionalCellId = .none,
    rrset: OptionalCellId = .none,
    signer: OptionalCellId = .none,
    fault: ?Fault = null,
    probe: Probe = .{},
};
pub const DnskeyScratch = struct { ds: OptionalCellId = .none, rrset: OptionalCellId = .none };
pub const AheadScratch = struct {
    budget: *graph.Budget = undefined,
    rrset: OptionalCellId = .none,
    judge: OptionalCellId = .none,
};
pub const SecureScratch = struct {
    target: CellId = 0,
    target_gen: u32 = 0,
    zone_ds: OptionalCellId = .none,
    key: OptionalCellId = .none,
    fetched: bool = false,
    status: Proof = .secure,
    next: u8 = 0,
    expires: i64 = std.math.maxInt(i64),
    proven: i64 = std.math.maxInt(i64),
    /// The claim at `next` must be signed by a zone shallower than this: the
    /// deeper signers it named are proven no zone.
    below: u8 = no_bound,
    /// Per proof claim, the depth of the zone its set verified under.
    proved: [max_proof_claims]u8 = @splat(unproved),
    proved_until: [max_proof_claims]i64 = @splat(std.math.maxInt(i64)),
    fault: ?Fault = null,
    probe: Probe = .{},
};

const no_bound = std.math.maxInt(u8);
const unproved = std.math.maxInt(u8);

const Fault = union(enum) {
    bogus,
    input: CellId,
    unreachable_authority,
    no_cut,

    fn failure(f: Fault, g: *Graph) ?Failure {
        return switch (f) {
            .bogus => null,
            .input => |i| g.cell(i).failure().?,
            .unreachable_authority => .unreachable_authority,
            .no_cut => no_cut,
        };
    }
};

const bogus: Failure = .{ .code = .dnssec_bogus };
const no_cut: Failure = .{ .code = .dnssec_bogus, .text = "no insecure cut proven" };

/// Bogus bytes leave the store now: their TTL was the forger's to set (RFC
/// 4035 §4.7). Not when a budget stopped the judgement: nothing was proven,
/// and a zone draining its own budget must not evict a victim's bytes.
fn failBogus(g: *Graph, id: CellId, rid: CellId) !void {
    if (g.payer.validationStop()) |why| return g.fail(id, why);
    if (g.limit(g.payer) == null) {
        const b = g.cell(rid).blob.?;
        b.shorten(g.now());
        g.store.drop(b);
    }
    try g.fail(id, bogus);
}

/// A bogus DS or keyset is remembered (RFC 9520 §3.4): judging it again per
/// question is KeyTrap's lever.
fn failChain(g: *Graph, id: CellId, rid: CellId) !void {
    if (g.payer.validationStop() == null and g.limit(g.payer) == null) try g.remember(g.cell(id).key, bogus);
    try failBogus(g, id, rid);
}

fn capExpiry(g: *Graph, cap: rrsig.Cap, stored_ns: i64) i64 {
    const ns = std.time.ns_per_s;
    return @min(stored_ns + @as(i64, cap.original_ttl) * ns, g.now() + @as(i64, cap.window_s) * ns);
}

pub fn runDs(g: *Graph, id: CellId) !void {
    const zone = g.cell(id).name;
    const s = g.cell(id).scratch.ds;
    const anchors = g.cfg.trust_anchors orelse return g.settle(id, .{ .ds = .{ .status = .insecure } }, std.math.maxInt(i64));
    const parent_name = zone.parent() orelse {
        const rrs = try g.scratch.allocator().alloc(RR, anchors.len);
        for (rrs, anchors) |*rr, ds| rr.* = try .init(g.scratch.allocator(), .{ .name = zone, .rtype = .ds, .rclass = .in, .ttl = 0, .rdata = .{ .ds = ds } });
        return g.settle(id, .{ .ds = .{ .status = .secure, .records = rrs } }, std.math.maxInt(i64));
    };
    const parent_zone = switch (try walk.start(g, id, zone, parent_name, &s.parent)) {
        .pending => return,
        .none => return g.fail(id, .unreachable_authority),
        .failed => |why| return g.fail(id, why),
        .cut => |cid| g.cell(cid).state.fact.cut.zone,
    };
    if (s.keys == .none) s.keys = .wrap(try g.demand(id, graph.Key.of(.dnskey, parent_zone, .a), parent_zone) orelse
        return g.fail(id, .unreachable_authority));
    const parent_keys = g.cell(s.keys.unwrap().?);
    if (!parent_keys.settled()) return;
    if (parent_keys.failure()) |why| return g.fail(id, why);
    switch (parent_keys.state.fact.dnskey.status) {
        // `absent`: the walked parent is no zone, so a zone above it signs
        // this DS. `judgeDs` finds which.
        .secure, .absent => {},
        .insecure => return g.settle(id, .{ .ds = .{ .status = .insecure } }, parent_keys.expires()),
    }
    if (s.rrset == .none) s.rrset = .wrap(try g.demand(id, graph.Key.of(.rrset, zone, .ds), zone) orelse
        return g.fail(id, .unreachable_authority));
    const rs = g.cell(s.rrset.unwrap().?);
    if (!rs.settled()) return;
    if (s.fault == null) {
        s.fault = try judgeDs(g, id, s, zone, rs) orelse return;
        if (g.payer.validationStop()) |why| return g.fail(id, why);
    }
    switch (try s.probe.run(g, id, parent_zone, parent_name)) {
        .pending => {},
        .stopped => |why| try g.fail(id, why),
        .insecure => |until| {
            try g.keep(s.rrset.unwrap().?);
            try g.settle(id, .{ .ds = .{ .status = .insecure } }, until);
        },
        // Remembered: otherwise every probe below judges this zone again,
        // doubling per label.
        .none => if (s.fault.?.failure(g)) |why| try g.failRemembered(id, why) else try failChain(g, id, s.rrset.unwrap().?),
    }
}

fn judgeDs(g: *Graph, id: CellId, s: *DsScratch, zone: dns.Name, rs: *const graph.Cell) !?Fault {
    if (rs.failure() != null) return .{ .input = s.rrset.unwrap().? };
    const r = rs.state.fact.rrset;
    const keys = while (true) {
        var below: usize = no_bound;
        if (s.signer.unwrap()) |kid| {
            const keys = g.cell(kid);
            if (!keys.settled()) return null;
            if (keys.failure() != null) return .{ .input = kid };
            // A signer proven no zone holds nothing: retry with the next one up.
            if (r.kind != .answer or keys.state.fact.dnskey.status != .absent) break keys;
            below = keys.name.depth();
        }
        const signer = switch (r.kind) {
            .answer => dnssec.signerBelow(r.answers, zone, .ds, below),
            .nodata, .nxdomain => proof.denialZone(r.authorities, zone),
            // A hidden-cut probe may land on a name that is an alias, not a cut.
            .alias => return .no_cut,
            .yxdomain => null,
        } orelse return .bogus;
        if (!proof.isProperAncestor(signer, zone)) return .bogus;
        s.signer = .wrap(try g.demand(id, graph.Key.of(.dnskey, signer, .a), signer) orelse
            return .unreachable_authority);
    };
    const signer = keys.name;
    const budget = &g.payer.validation;
    const clock = graph.Tally.clock(&g.tally.verify_ns);
    defer clock.stop();
    const now = g.wallNow();
    switch (r.kind) {
        .answer => {
            const sig = (try dnssec.validateRrset(g.scratch.allocator(), r.answers, zone, .ds, false, keys.state.fact.dnskey.records, now, budget, &g.verify_memo) orelse
                return .bogus).sig;
            g.authenticUntil(s.rrset.unwrap().?, capExpiry(g, .of(sig, now), r.stored_ns));
            const status: Proof = if (dnssec.anySupportedDs(r.answers)) .secure else .insecure;
            try g.keep(s.rrset.unwrap().?);
            try g.settle(id, .{ .ds = .{ .status = status, .records = r.answers } }, @min(rs.expires(), keys.expires()));
        },
        .nodata, .nxdomain => {
            for (r.authorities) |rr| if ((rr.rtype == .nsec or rr.rtype == .nsec3) and !rr.name.isSubdomainOf(signer))
                return .bogus;
            const cap = try dnssec.verifyAuthorityProofSigs(g.scratch.allocator(), r.authorities, keys.state.fact.dnskey.records, now, budget, &g.verify_memo) orelse
                return .bogus;
            g.authenticUntil(s.rrset.unwrap().?, capExpiry(g, cap, r.stored_ns));
            const until = @min(rs.expires(), keys.expires());
            switch (proof.classifyDelegation(r.authorities, zone, signer, budget)) {
                .unsigned => {
                    try g.keep(s.rrset.unwrap().?);
                    try g.settle(id, .{ .ds = .{ .status = .insecure } }, until);
                },
                // A signed denial of the DS that shows no delegation either: no zone.
                .unproven => switch (proof.validateNegativeProof(r.authorities, zone, .ds, r.kind == .nxdomain, signer, budget)) {
                    .secure => {
                        try g.keep(s.rrset.unwrap().?);
                        try g.settle(id, .{ .ds = .{ .status = .absent, .records = r.authorities } }, until);
                    },
                    .unchecked, .insecure, .bogus => try g.fail(id, g.payer.validationStop() orelse no_cut),
                },
                .bogus => try g.fail(id, g.payer.validationStop() orelse no_cut),
            }
        },
        .alias, .yxdomain => unreachable,
    }
    return null;
}

pub fn runAhead(g: *Graph, id: CellId) !void {
    const s = g.cell(id).scratch.ahead;
    const name = g.cell(id).name;
    if (s.judge == .none) s.judge = .wrap(switch (g.cell(id).key.rtype) {
        .dnskey => try g.demand(id, graph.Key.of(.dnskey, name, .a), name),
        .ds => try g.demand(id, graph.Key.of(.ds, name, .a), name),
        else => try demandSecure(g, id, s.rrset.unwrap() orelse return g.settle(id, .ahead, g.now())),
    } orelse return g.settle(id, .ahead, g.now()));
    if (g.cell(s.judge.unwrap().?).settled()) try g.settle(id, .ahead, g.now());
}

pub fn signedDown(g: *Graph, zone: dns.Name) !bool {
    var z = zone;
    while (true) {
        if (try g.peek(graph.Key.of(.ds, z, .a))) |f| return f.value.ds.status == .secure;
        if (z.isRoot()) return true;
        const ds = try g.peek(graph.Key.of(.rrset, z, .ds)) orelse return false;
        if (ds.value.rrset.kind != .answer or !dnssec.anySupportedDs(ds.value.rrset.answers)) return false;
        const above = ds.value.rrset.zone;
        if (!proof.isProperAncestor(above, z)) return false;
        z = above;
    }
}

pub fn runDnskey(g: *Graph, id: CellId) !void {
    const zone = g.cell(id).name;
    const s = g.cell(id).scratch.dnskey;
    if (s.ds == .none) s.ds = .wrap(try g.demand(id, graph.Key.of(.ds, zone, .a), zone) orelse
        return g.fail(id, .unreachable_authority));
    // Looks redundant with the demand below, but this one runs before the
    // DS settles: a zone likely to be signed gets its keys fetched alongside.
    if (s.rrset == .none and try signedDown(g, zone))
        s.rrset = .wrap(try g.demand(id, graph.Key.of(.rrset, zone, .dnskey), zone));
    const ds = g.cell(s.ds.unwrap().?);
    if (!ds.settled()) return;
    if (ds.failure()) |why| return g.fail(id, why);
    if (ds.state.fact.ds.status != .secure) return g.settle(id, .{ .dnskey = .{ .status = ds.state.fact.ds.status } }, ds.expires());
    if (s.rrset == .none) s.rrset = .wrap(try g.demand(id, graph.Key.of(.rrset, zone, .dnskey), zone) orelse
        return g.fail(id, .unreachable_authority));
    const rs = g.cell(s.rrset.unwrap().?);
    if (!rs.settled()) return;
    if (rs.failure()) |why| return g.fail(id, why);
    const r = rs.state.fact.rrset;
    if (r.kind != .answer) return failChain(g, id, s.rrset.unwrap().?);
    var ds_data: std.ArrayList(dns.DsData) = .empty;
    for (ds.state.fact.ds.records) |rr| if (rr.rtype == .ds) try ds_data.append(g.scratch.allocator(), rr.ds());
    const budget = &g.payer.validation;
    const clock = graph.Tally.clock(&g.tally.verify_ns);
    defer clock.stop();
    const now = g.wallNow();
    const sig = try dnssec.validateDnskeyRrset(g.scratch.allocator(), r.answers, ds_data.items, zone, now, budget, &g.verify_memo) orelse
        return failChain(g, id, s.rrset.unwrap().?);
    g.authenticUntil(s.rrset.unwrap().?, capExpiry(g, .of(sig, now), r.stored_ns));
    const keys = try dnssec.usableKeys(g.scratch.allocator(), r.answers, ds_data.items);
    try g.keep(s.rrset.unwrap().?);
    try g.settle(id, .{ .dnskey = .{ .status = .secure, .records = keys } }, @min(rs.expires(), ds.expires()));
}

pub fn demandSecure(g: *Graph, by: CellId, rid: CellId) !?CellId {
    const t = g.cell(rid);
    std.debug.assert(t.state == .fact);
    const key = graph.Key.of(.secure, t.name, t.key.rtype);
    if (g.indexed(key)) |sid| {
        const c = g.cell(sid);
        const same = c.scratch.secure.target == rid and c.scratch.secure.target_gen == g.gen(rid);
        if (same and (!c.settled() or g.fresh(sid))) return g.join(by, sid);
    }
    const sid = try g.newCell(key, t.name, g.as_of);
    g.cell(sid).scratch.secure.* = .{ .target = rid, .target_gen = g.gen(rid) };
    try g.pin(sid, by);
    if (t.blob) |b| if (b.verdict.standing(g.instant())) |v| {
        try g.settle(sid, .{ .secure = v }, b.verdict.until_ns);
        return sid;
    };
    try g.pin(rid, sid);
    try g.enqueue(sid);
    return sid;
}

pub fn runSecure(g: *Graph, id: CellId) !void {
    const s = g.cell(id).scratch.secure;
    const t = g.cell(s.target);
    const zone = t.state.fact.rrset.zone;
    if (s.zone_ds == .none) s.zone_ds = .wrap(try g.demand(id, graph.Key.of(.ds, zone, .a), zone) orelse
        return g.fail(id, .unreachable_authority));
    const zd = g.cell(s.zone_ds.unwrap().?);
    if (!zd.settled()) return;
    if (zd.failure()) |why| return g.fail(id, why);
    switch (zd.state.fact.ds.status) {
        .secure, .absent => {},
        .insecure => return g.settle(id, .{ .secure = .{ .status = .insecure } }, zd.expires()),
    }
    while (true) {
        if (s.fault == null) {
            s.fault = try judge(g, id, s, t, @min(t.expires(), zd.expires())) orelse return;
            if (g.payer.validationStop()) |why| return g.fail(id, why);
        }
        const c = Claims.at(&t.state.fact.rrset, t.key.rtype, s.next);
        const r = &t.state.fact.rrset;
        // A proof may sit below an insecure cut only where the data it speaks
        // for does: the name denied, if that is the zone's, else its own owner.
        const deepest = if (c.is == .proof and r.target.isSubdomainOf(zone)) proof.deepestApex(r.target, t.key.rtype) else proof.deepestApex(c.owner, c.rtype);
        switch (try s.probe.run(g, id, zone, deepest)) {
            .pending => return,
            .stopped => |why| return g.fail(id, why),
            .insecure => |until| {
                s.expires = @min(s.expires, until);
                s.status = .insecure;
                s.next += 1;
                s.below = no_bound;
                s.fault = null;
                s.probe = .{};
            },
            .none => return if (s.fault.?.failure(g)) |why| g.fail(id, why) else failBogus(g, id, s.target),
        }
    }
}

fn judge(g: *Graph, id: CellId, s: *SecureScratch, t: *const graph.Cell, until: i64) !?Fault {
    const r = &t.state.fact.rrset;
    const qtype = t.key.rtype;
    const zd = g.cell(s.zone_ds.unwrap().?).state.fact.ds;
    // A name proven no zone belongs to the zone whose denial proved it.
    const within = if (zd.status == .absent) proof.denialZone(zd.records, r.zone).? else r.zone;
    if (!s.fetched) {
        if (flooded(r, qtype)) {
            try failBogus(g, id, s.target);
            return null;
        }
        s.fetched = true;
        var it: Claims = .{ .r = r, .qtype = qtype };
        while (it.next()) |c| {
            const signer = signerOf(r, c, within, no_bound) orelse continue;
            const key = graph.Key.of(.dnskey, signer, .a);
            if (!g.holds(key) and g.indexed(key) == null) try g.fetchKeys(signer);
        }
    }
    const budget = &g.payer.validation;
    const clock = graph.Tally.clock(&g.tally.verify_ns);
    defer clock.stop();
    const now = g.wallNow();
    var it: Claims = .{ .r = r, .qtype = qtype };
    while (it.next()) |c| {
        if (c.slot < s.next) continue;
        const fault: ?Fault = f: switch (c.is) {
            .synthesised => |x| {
                const target = try dns.substituteSuffix(g.scratch.allocator(), c.owner, x.dname.name, x.dname.dname()) orelse break :f .bogus;
                break :f if (target.eql(x.cname.cname())) null else .bogus;
            },
            .rrset, .proof, .denial => {
                const signer = signerOf(r, c, within, s.below) orelse break :f .bogus;
                if (!keysOf(g, s.key, signer)) s.key = .wrap(try g.demand(id, graph.Key.of(.dnskey, signer, .a), signer));
                const kid = s.key.unwrap() orelse break :f .unreachable_authority;
                const kc = g.cell(kid);
                if (!kc.settled()) {
                    s.next = c.slot;
                    return null;
                }
                if (kc.failure() != null) break :f .{ .input = kid };
                s.expires = @min(s.expires, kc.expires());
                const keys = kc.state.fact.dnskey;
                switch (keys.status) {
                    .secure => {},
                    .insecure => {
                        // Insecure keys above a zone whose DS is secure contradict that DS.
                        if (!signer.isSubdomainOf(r.zone)) break :f .bogus;
                        s.status = .insecure;
                        break :f null;
                    },
                    // The signer is proven no zone. A set may be signed by one
                    // above it; a denial naming it is forged.
                    .absent => {
                        if (c.is == .denial) break :f .bogus;
                        s.below = signer.depth();
                        continue :f c.is;
                    },
                }
                if (c.is == .denial) {
                    const own = try verifiedProofs(g, r, qtype, s, signer);
                    switch (proof.validateNegativeProof(own.rrs, c.owner, c.rtype, r.kind == .nxdomain, signer, budget)) {
                        .secure => {
                            var only = r.*;
                            only.authorities = own.rrs;
                            try denial.absorb(g, signer, only, own.until, kc.expires());
                        },
                        .insecure => s.status = .insecure,
                        .bogus, .unchecked => break :f .bogus,
                    }
                    break :f null;
                }
                const records = if (c.is == .proof) r.authorities else r.answers;
                const v = try dnssec.validateRrset(g.scratch.allocator(), records, c.owner, c.rtype, c.is == .proof, keys.records, now, budget, &g.verify_memo) orelse
                    break :f .bogus;
                const verified = v.sig;
                const cap = capExpiry(g, .of(verified, now), r.stored_ns);
                s.expires = @min(s.expires, cap);
                s.proven = @min(s.proven, cap);
                if (c.is == .proof) {
                    s.proved[c.slot] = signer.depth();
                    s.proved_until[c.slot] = cap;
                    if (v.unweighed) try keepWeighed(g, s.target, r, &c, signer, now);
                    break :f null;
                }
                if (verified.labels < rrsig.signedLabels(c.owner)) {
                    const own = try verifiedProofs(g, r, qtype, s, verified.signer_name);
                    switch (proof.proveNoCloserMatch(own.rrs, c.owner, verified.labels, verified.signer_name, budget)) {
                        .secure => {},
                        .insecure => s.status = .insecure,
                        .bogus, .unchecked => break :f .bogus,
                    }
                }
                if (v.unweighed) try keepWeighed(g, s.target, r, &c, signer, now);
                break :f null;
            },
        };
        if (fault) |why| {
            s.next = c.slot;
            return why;
        }
        s.below = no_bound;
    }
    const chain: Chain = if (s.status == .secure) .{ .status = .secure, .proven_until_ns = s.proven } else .{ .status = .insecure };
    if (s.status == .secure) g.authenticUntil(s.target, s.proven);
    try g.settle(id, .{ .secure = chain }, @min(until, s.expires));
    return null;
}

fn keysOf(g: *Graph, key: OptionalCellId, signer: dns.Name) bool {
    const kid = key.unwrap() orelse return false;
    return g.cell(kid).name.eql(signer);
}

const max_claims = 2 * graph.max_links + 2 + max_proof_claims;
/// `Claims` yields proof claims first, so their slots stay below this and
/// may index `proved`.
const max_proof_claims = proof.max_proof_records + 1;

fn flooded(r: *const graph.Reply, qtype: dns.RType) bool {
    if (proof.proofFlood(r.authorities)) return true;
    var it: Claims = .{ .r = r, .qtype = qtype };
    var n: usize = 0;
    var proofs: usize = 0;
    while (it.next()) |c| {
        n += 1;
        proofs += @intFromBool(c.is == .proof);
        if (n > max_claims or proofs > max_proof_claims) return true;
    }
    return false;
}

const Claims = struct {
    r: *const graph.Reply,
    qtype: dns.RType,
    p: usize = 0,
    i: usize = 0,
    slot: u8 = 0,
    ended: bool = false,

    const Claim = struct {
        slot: u8,
        owner: dns.Name,
        rtype: dns.RType,
        head: usize,
        is: union(enum) {
            rrset,
            proof,
            synthesised: struct { cname: RR, dname: RR },
            denial,
        },
    };

    fn next(it: *Claims) ?Claim {
        const auth = it.r.authorities;
        while (it.p < auth.len) {
            const i = it.p;
            it.p += 1;
            const rr = auth[i];
            switch (rr.rtype) {
                .nsec, .nsec3, .soa => if (firstOfRrset(auth, i)) return it.claim(rr.name, rr.rtype, i, .proof),
                else => {},
            }
        }
        const answers = it.r.answers;
        while (it.i < answers.len) {
            const i = it.i;
            it.i += 1;
            const rr = answers[i];
            if (rr.rtype == .rrsig or !firstOfRrset(answers, i)) continue;
            var dname: ?RR = null;
            if (rr.rtype == .cname) for (answers) |d| {
                if (d.rtype == .dname and synthesisedUnder(rr, d) and (dname == null or d.name.depth() > dname.?.name.depth())) dname = d;
            };
            if (dname) |d| return it.claim(rr.name, rr.rtype, i, .{ .synthesised = .{ .cname = rr, .dname = d } });
            return it.claim(rr.name, rr.rtype, i, .rrset);
        }
        if (it.ended) return null;
        it.ended = true;
        return switch (it.r.kind) {
            .nodata, .nxdomain => it.claim(it.r.target, it.qtype, 0, .denial),
            .answer, .alias, .yxdomain => null,
        };
    }

    fn claim(it: *Claims, owner: dns.Name, rtype: dns.RType, head: usize, is: @FieldType(Claim, "is")) Claim {
        std.debug.assert(it.slot <= max_claims);
        defer it.slot += 1;
        return .{ .slot = it.slot, .owner = owner, .rtype = rtype, .head = head, .is = is };
    }

    fn at(r: *const graph.Reply, qtype: dns.RType, slot: u8) Claim {
        var it: Claims = .{ .r = r, .qtype = qtype };
        while (it.next()) |c| if (c.slot == slot) return c;
        unreachable;
    }
};

fn signerOf(r: *const graph.Reply, c: Claims.Claim, within: dns.Name, below: u8) ?dns.Name {
    const signer = switch (c.is) {
        .rrset => dnssec.signerBelow(r.answers, c.owner, c.rtype, below),
        .proof => dnssec.signerBelow(r.authorities, c.owner, c.rtype, below),
        .denial => proof.denialZone(r.authorities, r.target),
        .synthesised => null,
    } orelse return null;
    if (!proof.deepestApex(c.owner, c.rtype).isSubdomainOf(signer)) return null;
    if (c.is == .rrset and !signer.isSubdomainOf(within)) return null;
    return signer;
}

const Probe = struct {
    cell: OptionalCellId = .none,
    depth: u8 = 0,

    fn run(p: *Probe, g: *Graph, id: CellId, above: dns.Name, deepest: dns.Name) !union(enum) { pending, insecure: i64, none, stopped: Failure } {
        while (true) {
            if (p.cell.unwrap()) |pid| {
                const c = g.cell(pid);
                if (!c.settled()) return .pending;
                if (c.failure()) |why| {
                    if (why.cause == .asker) return .{ .stopped = why };
                } else if (c.state.fact.ds.status == .insecure) return .{ .insecure = c.expires() };
                p.cell = .none;
            }
            p.depth = @max(p.depth, above.depth()) + 1;
            if (p.depth > deepest.depth()) return .none;
            const candidate = deepest.ancestor(p.depth);
            p.cell = .wrap(try g.demand(id, graph.Key.of(.ds, candidate, .a), candidate) orelse return .{ .stopped = .unreachable_authority });
        }
    }
};

fn verifiedProofs(g: *Graph, r: *const graph.Reply, qtype: dns.RType, s: *const SecureScratch, signer: dns.Name) !struct { rrs: []const RR, until: []const i64 } {
    const a = g.scratch.allocator();
    var keep: std.ArrayList(RR) = .empty;
    var until: std.ArrayList(i64) = .empty;
    var it: Claims = .{ .r = r, .qtype = qtype };
    while (it.next()) |c| {
        // Proof claims come first, and all are judged before any claim that
        // reads them. Sets excused or passed under insecure keys stay out.
        if (c.is != .proof) break;
        if (s.proved[c.slot] != signer.depth() or !c.owner.isSubdomainOf(signer)) continue;
        for (dnssec.setAt(r.authorities, c.owner, c.rtype)) |rr| if (rr.rtype != .rrsig or rr.rrsig().signer_name.eql(signer)) {
            try keep.append(a, rr);
            try until.append(a, s.proved_until[c.slot]);
        };
    }
    return .{ .rrs = keep.items, .until = until.items };
}

/// Drops the signatures the verifier did not weigh before a verdict is
/// stamped on the bytes. Only signatures go, so claim slots do not move.
fn keepWeighed(g: *Graph, target: CellId, r: *const graph.Reply, c: *const Claims.Claim, zone: dns.Name, now: u32) !void {
    const section = if (c.is == .proof) r.authorities else r.answers;
    const set = dnssec.setFrom(section, c.head);
    var keep: std.ArrayList(RR) = try .initCapacity(g.scratch.allocator(), section.len);
    keep.appendSliceAssumeCapacity(section[0..c.head]);
    for (set) |rr| if (rr.rtype != .rrsig) keep.appendAssumeCapacity(rr);
    var w: dnssec.Weighed = .{ .rrs = set, .owner = c.owner, .rtype = c.rtype, .zone = zone, .now = now, .unexpanded = c.is == .proof };
    while (w.next()) |i| keep.appendAssumeCapacity(set[i]);
    keep.appendSliceAssumeCapacity(section[c.head + set.len ..]);
    var narrowed = r.*;
    if (c.is == .proof) narrowed.authorities = keep.items else narrowed.answers = keep.items;
    try g.narrow(target, narrowed);
}

fn synthesisedUnder(rr: RR, dname: RR) bool {
    return rr.rtype == .cname and rr.name.depth() > dname.name.depth() and rr.name.isSubdomainOf(dname.name);
}

/// Assumes `bindSets` order: a set's records are adjacent.
fn firstOfRrset(rrs: []const RR, i: usize) bool {
    return i == 0 or rrs[i - 1].rtype != rrs[i].rtype or !rrs[i - 1].name.eql(rrs[i].name);
}

/// On a denial only the NSEC or NSEC3 proof is kept: the child's NS in a
/// denial's authority would read as a referral.
pub fn referralDs(g: *Graph, msg: dns.Message, zone: dns.Name, child: dns.Name) !?graph.Reply {
    const ds = dnssec.setAt(msg.authorities, child, .ds);
    if (ds.len > 0) {
        var reply: graph.Reply = .{ .kind = .answer, .aa = true, .answers = ds, .zone = zone, .stored_ns = g.now() };
        reply.ttl = walk.replyTtl(reply);
        return reply;
    }
    var ttl: u32 = std.math.maxInt(u32);
    var proofs: std.ArrayList(RR) = .empty;
    for (msg.authorities) |rr| switch (dnssec.covers(rr)) {
        .nsec, .nsec3 => {
            try proofs.append(g.scratch.allocator(), rr);
            if (rr.rtype != .rrsig) ttl = @min(ttl, rr.ttl);
        },
        else => {},
    };
    if (proofs.items.len == 0) return null;
    return .{ .kind = .nodata, .aa = true, .authorities = proofs.items, .target = child, .zone = zone, .stored_ns = g.now(), .ttl = ttl };
}
