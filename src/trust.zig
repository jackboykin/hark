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
const store = @import("store.zig");
const walk = @import("walk.zig");

const Graph = graph.Graph;
const CellId = graph.CellId;
const OptionalCellId = graph.OptionalCellId;
const Failure = graph.Failure;
const RR = dns.ResourceRecord;

/// Proven signed or unsigned; for `ds` and `dnskey`, also proven no zone
/// at all, by the parent's signed denial of a delegation. Bogus is no
/// fact: it fails.
pub const Proof = enum(u8) { secure, insecure, absent };

/// A verdict and what it rests on: the verified DS set or keys, or for a
/// DS proven absent, the signed denial that proves it.
pub const Chain = struct {
    status: Proof,
    records: []const RR = &.{},
    /// `secure` only: where the signatures' validity ends (`rrsig.ttlCap`).
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
pub const KeysScratch = struct {
    /// The payer of the walk that met the delegation, shared.
    budget: *graph.Budget = undefined,
    keys: OptionalCellId = .none,
};
pub const SecureScratch = struct {
    /// The rrset version under judgement; ids recycle, so its generation too.
    target: CellId = 0,
    target_gen: u32 = 0,
    /// `ds(zone)`: is the answering zone expected to sign at all.
    zone_ds: OptionalCellId = .none,
    /// `dnskey(signer)` of the claim at `next`, held one at a time: the
    /// rest are fetched alongside by `keys` roots.
    key: OptionalCellId = .none,
    /// The reply was checked for a flood and its signers' keys fetched.
    fetched: bool = false,
    /// Insecure once a claim before `next` sits below a proven insecure cut.
    status: Proof = .secure,
    /// The claim judged next, or the one faulted awaiting its probe.
    next: u8 = 0,
    /// The lifetime the claims before `next` allow.
    expires: i64 = std.math.maxInt(i64),
    /// Where the signatures of the claims before `next` stop proving.
    proven: i64 = std.math.maxInt(i64),
    /// Bit per claim slot: a proof set whose signature verified. Only
    /// these feed a derivation (`verifiedProofs`).
    verified: std.bit_set.Integer(max_claims + 1) = .empty,
    fault: ?Fault = null,
    probe: Probe = .{},
};

/// A failed input stays pinned, its failure readable, until this cell
/// settles.
const Fault = union(enum) {
    bogus,
    input: CellId,
    no_chain,
    no_cut,

    fn failure(f: Fault, g: *Graph) ?Failure {
        return switch (f) {
            .bogus => null,
            .input => |i| g.cell(i).failure().?,
            .no_chain => no_chain,
            .no_cut => no_cut,
        };
    }
};

const no_chain: Failure = .{ .code = .dnssec_bogus, .text = "no chain" };
const refused: Failure = .{ .code = .dnssec_bogus, .text = "zone failed validation" };
/// Verified, and still no proof of the insecure cut asked about.
const no_cut: Failure = .{ .code = .dnssec_bogus, .text = "no insecure cut proven" };

/// Proven bogus, the bytes end with the verdict: their TTL was the forger's
/// to set (RFC 4035 §4.7). If `claim` is the CNAME at the name, its copy
/// in the alias goes too. With the validation budget spent nothing was
/// proven: the stop is the limit's, named, and a zone draining its own
/// budget must not drop a victim's bytes.
fn failBogus(g: *Graph, id: CellId, rid: CellId, claim: ?Claims.Claim) !void {
    if (budgetSpent(g)) |why| return g.fail(id, why);
    if (!g.spent(g.payer)) {
        const t = g.cell(rid);
        t.expires_ns = @min(t.expires_ns, g.now());
        if (t.blob) |b| g.store.drop(t.key, b);
        if (claim) |c| if (c.is == .rrset and c.rtype == .cname and c.owner.eql(t.name)) try dropAlias(g, t);
    }
    try g.fail(id, .{ .code = .dnssec_bogus });
}

fn dropAlias(g: *Graph, t: *const graph.Cell) !void {
    var kb: graph.KeyBuf = undefined;
    const key = graph.Key.of(&kb, .rrset, t.name, .cname);
    const failed = t.state.fact.rrset.answers;
    if (g.index.get(key)) |id| {
        const c = g.cell(id);
        if (c.state == .fact and provesNoMore(c.state.fact.rrset.answers, failed)) c.expires_ns = @min(c.expires_ns, g.now());
    }
    const e = g.store.any(key) orelse return;
    const v = try store.Store.parse(g.scratch.allocator(), e.blob);
    if (provesNoMore(v.rrset.answers, failed)) g.store.drop(key, e.blob);
}

fn provesNoMore(alias: []const RR, failed: []const RR) bool {
    return for (alias) |rr| {
        const had = for (failed) |f| {
            if (f.rtype == rr.rtype and f.name.eql(rr.name) and sameRdata(f, rr)) break true;
        } else false;
        if (!had) break false;
    } else true;
}

/// An alias holds only a CNAME and its signatures.
fn sameRdata(a: RR, b: RR) bool {
    return switch (a.rdata) {
        .cname => |t| t.eql(b.rdata.cname),
        .rrsig => |s| {
            const o = b.rdata.rrsig;
            return s.type_covered == o.type_covered and s.algorithm == o.algorithm and s.labels == o.labels and
                s.original_ttl == o.original_ttl and s.sig_expiration == o.sig_expiration and s.sig_inception == o.sig_inception and
                s.key_tag == o.key_tag and s.signer_name.eql(o.signer_name) and std.mem.eql(u8, s.signature, o.signature);
        },
        else => false,
    };
}

/// The validation budget spent is the asker's limit, never bogus. A query
/// budget or deadline is named only where an input failed on it.
fn budgetSpent(g: *Graph) ?Failure {
    const b = &g.payer.validation;
    if (b.nsec3Exhausted()) return .{ .code = .unsupported_nsec3_iterations, .text = "nsec3 budget spent", .cause = .asker };
    if (b.exhausted()) return .{ .code = .other, .text = "validation budget spent", .cause = .asker };
    return null;
}

/// A zone's DS or keys proven bogus: demanding them again is refused for
/// `servfail_ttl`, since judging them again per question is KeyTrap's lever
/// (RFC 9520 §3.4).
fn failChain(g: *Graph, id: CellId, rid: CellId) !void {
    if (!g.spent(g.payer)) try g.remember(g.cell(id).key, refused);
    try failBogus(g, id, rid, null);
}

fn capExpiry(g: *Graph, cap: u32) i64 {
    return g.now() + @as(i64, cap) * std.time.ns_per_s;
}

/// `ds(zone)`: the anchor at the root; below it, `rrset(zone, DS)` judged
/// under the keys of whatever signed it, a proper ancestor of the zone:
/// the walked parent may hide a cut on its own servers, or fold one (901).
/// A signed set with a usable algorithm is secure, a proven absence or
/// unusable set insecure. Bytes that prove nothing, or a failed input, are
/// insecure only below a proven insecure cut between the walked parent
/// and the zone; otherwise the bytes are bogus or the failure stands. An
/// insecure parent is inherited, and so is a failed one.
pub fn runDs(g: *Graph, id: CellId) !void {
    var kb: graph.KeyBuf = undefined;
    const zone = g.cell(id).name;
    const s = g.cell(id).scratch.ds;
    const anchor = g.cfg.trust_anchor orelse return g.settle(id, .{ .ds = .{ .status = .insecure } }, std.math.maxInt(i64));
    if (zone.labels.len == 0) {
        const rr: RR = .{ .name = zone, .rtype = .ds, .rclass = .in, .ttl = 0, .rdata = .{ .ds = anchor } };
        return g.settle(id, .{ .ds = .{ .status = .secure, .records = try g.scratch.allocator().dupe(RR, &.{rr}) } }, std.math.maxInt(i64));
    }
    const parent_name: dns.Name = .{ .labels = zone.labels[1..] };
    const parent_zone = switch (try walk.start(g, id, zone, parent_name, &s.parent)) {
        .pending => return,
        .none => return g.fail(id, no_chain),
        .failed => |why| return g.fail(id, why),
        .cut => |cid| g.cell(cid).state.fact.cut.zone,
    };
    if (s.keys == .none) s.keys = .wrap(try g.demand(id, graph.Key.of(&kb, .dnskey, parent_zone, .a), parent_zone) orelse
        return g.fail(id, no_chain));
    const parent_keys = g.cell(s.keys.unwrap().?);
    if (!parent_keys.settled()) return;
    if (parent_keys.failure()) |why| return g.fail(id, why);
    switch (parent_keys.state.fact.dnskey.status) {
        .secure => {},
        .insecure => return g.settle(id, .{ .ds = .{ .status = .insecure } }, parent_keys.expires_ns),
        // The walk's parent proven no zone: nothing speaks for the child.
        .absent => return g.fail(id, no_chain),
    }
    if (s.rrset == .none) s.rrset = .wrap(try g.demand(id, graph.Key.of(&kb, .rrset, zone, .ds), zone) orelse
        return g.fail(id, no_chain));
    const rs = g.cell(s.rrset.unwrap().?);
    if (!rs.settled()) return;
    if (s.fault == null) {
        s.fault = try judgeDs(g, id, s, zone, rs) orelse return;
        if (budgetSpent(g)) |why| return g.fail(id, why);
    }
    switch (try s.probe.run(g, id, parent_zone, parent_name)) {
        .pending => {},
        .cut_short => try g.fail(id, no_chain),
        .stopped => |why| try g.fail(id, why),
        .insecure => |until| try g.settle(id, .{ .ds = .{ .status = .insecure } }, until),
        .none => if (s.fault.?.failure(g)) |why| try g.fail(id, why) else try failChain(g, id, s.rrset.unwrap().?),
    }
}

fn judgeDs(g: *Graph, id: CellId, s: *DsScratch, zone: dns.Name, rs: *const graph.Cell) !?Fault {
    var kb: graph.KeyBuf = undefined;
    if (rs.failure() != null) return .{ .input = s.rrset.unwrap().? };
    const r = rs.state.fact.rrset;
    const signer = switch (r.kind) {
        .answer => if (dnssec.findRrsigAt(r.answers, zone, .ds)) |sig| sig.signer_name else null,
        .nodata, .nxdomain => proof.authoritySigner(r.authorities),
        // A name that is no cut may alias (a hidden-cut probe).
        .alias => return .no_cut,
        .yxdomain => null,
    } orelse return .bogus;
    if (!proof.isProperAncestor(signer, zone)) return .bogus;
    if (s.signer == .none) s.signer = .wrap(try g.demand(id, graph.Key.of(&kb, .dnskey, signer, .a), signer) orelse
        return .no_chain);
    const keys = g.cell(s.signer.unwrap().?);
    if (!keys.settled()) return null;
    if (keys.failure() != null) return .{ .input = s.signer.unwrap().? };
    const budget = &g.payer.validation;
    const clock = graph.Tally.clock(&g.tally.verify_ns);
    defer clock.stop();
    const now = g.wallNow();
    switch (r.kind) {
        .answer => {
            const sig = dnssec.validateRrset(r.answers, zone, .ds, keys.state.fact.dnskey.records, now, budget, &g.verify_memo) orelse
                return .bogus;
            g.authenticUntil(s.rrset.unwrap().?, capExpiry(g, rrsig.ttlCap(sig, now)));
            const status: Proof = if (dnssec.anySupportedDs(r.answers)) .secure else .insecure;
            try g.settle(id, .{ .ds = .{ .status = status, .records = r.answers } }, @min(rs.expires_ns, keys.expires_ns));
        },
        .nodata, .nxdomain => {
            // RFC 4034 §3.1.3.
            for (r.authorities) |rr| if ((rr.rtype == .nsec or rr.rtype == .nsec3) and !rr.name.isSubdomainOf(signer))
                return .bogus;
            var cap: u32 = std.math.maxInt(u32);
            if (dnssec.verifyAuthorityProofSigs(r.authorities, keys.state.fact.dnskey.records, now, budget, &g.verify_memo, &cap) != .secure)
                return .bogus;
            g.authenticUntil(s.rrset.unwrap().?, capExpiry(g, cap));
            const until = @min(rs.expires_ns, keys.expires_ns);
            switch (proof.classifyDelegation(r.authorities, zone, signer, budget)) {
                .unsigned => try g.settle(id, .{ .ds = .{ .status = .insecure } }, until),
                // A signed denial of the DS showing no delegation: no zone.
                .unproven => switch (proof.validateNegativeProof(r.authorities, zone, .ds, r.kind == .nxdomain, signer, budget)) {
                    .secure => try g.settle(id, .{ .ds = .{ .status = .absent, .records = r.authorities } }, until),
                    else => try g.fail(id, budgetSpent(g) orelse no_cut),
                },
                .bogus => try g.fail(id, budgetSpent(g) orelse no_cut),
            }
        },
        .alias, .yxdomain => unreachable,
    }
    return null;
}

/// `keys(zone)`: a root with no fact of its own, holding `dnskey(zone)`
/// until it settles, so the chain of trust overlaps the walk below
/// (Unbound's prefetch-key).
pub fn runKeys(g: *Graph, id: CellId) !void {
    var kb: graph.KeyBuf = undefined;
    const s = g.cell(id).scratch.keys;
    const zone = g.cell(id).name;
    if (s.keys == .none) s.keys = .wrap(try g.demand(id, graph.Key.of(&kb, .dnskey, zone, .a), zone) orelse
        return g.settle(id, .keys, g.now()));
    if (g.cell(s.keys.unwrap().?).settled()) try g.settle(id, .keys, g.now());
}

/// Every cut from `zone` up is proven secure or, unproven yet, delegated
/// with a DS, to the root or to a cut proven secure.
pub fn signedDown(g: *Graph, zone: dns.Name) !bool {
    var kb: graph.KeyBuf = undefined;
    var z = zone;
    while (true) {
        if (try g.peek(graph.Key.of(&kb, .ds, z, .a))) |f| return f.value.ds.status == .secure;
        if (z.labels.len == 0) return true;
        const ds = try g.peek(graph.Key.of(&kb, .rrset, z, .ds)) orelse return false;
        if (ds.value.rrset.kind != .answer) return false;
        // The DS came from the zone above, whichever cut lies between.
        const above = ds.value.rrset.zone;
        if (!proof.isProperAncestor(above, z)) return false;
        z = above;
    }
}

/// `dnskey(zone)`: `rrset(zone, DNSKEY)` verified under `ds(zone)`.
pub fn runDnskey(g: *Graph, id: CellId) !void {
    var kb: graph.KeyBuf = undefined;
    const zone = g.cell(id).name;
    const s = g.cell(id).scratch.dnskey;
    if (s.ds == .none) s.ds = .wrap(try g.demand(id, graph.Key.of(&kb, .ds, zone, .a), zone) orelse
        return g.fail(id, no_chain));
    // Signed all the way down, proven or not yet, says the keys will be
    // needed: fetch them alongside the proof instead of a round trip per
    // level after it.
    if (s.rrset == .none and try signedDown(g, zone))
        s.rrset = .wrap(try g.demand(id, graph.Key.of(&kb, .rrset, zone, .dnskey), zone));
    const ds = g.cell(s.ds.unwrap().?);
    if (!ds.settled()) return;
    if (ds.failure()) |why| return g.fail(id, why);
    if (ds.state.fact.ds.status != .secure) return g.settle(id, .{ .dnskey = .{ .status = ds.state.fact.ds.status } }, ds.expires_ns);
    if (s.rrset == .none) s.rrset = .wrap(try g.demand(id, graph.Key.of(&kb, .rrset, zone, .dnskey), zone) orelse
        return g.fail(id, no_chain));
    const rs = g.cell(s.rrset.unwrap().?);
    if (!rs.settled()) return;
    if (rs.failure()) |why| return g.fail(id, why);
    const r = rs.state.fact.rrset;
    if (r.kind != .answer) return failChain(g, id, s.rrset.unwrap().?);
    var ds_data: std.ArrayList(dns.DsData) = .empty;
    for (ds.state.fact.ds.records) |rr| if (rr.rtype == .ds) try ds_data.append(g.scratch.allocator(), rr.rdata.ds);
    const budget = &g.payer.validation;
    const clock = graph.Tally.clock(&g.tally.verify_ns);
    defer clock.stop();
    const now = g.wallNow();
    const sig = dnssec.validateDnskeyRrset(r.answers, ds_data.items, zone, now, budget, &g.verify_memo) catch
        return failChain(g, id, s.rrset.unwrap().?);
    g.authenticUntil(s.rrset.unwrap().?, capExpiry(g, rrsig.ttlCap(sig, now)));
    const keys = try dnssec.usableKeys(g.scratch.allocator(), r.answers, ds_data.items);
    try g.settle(id, .{ .dnskey = .{ .status = .secure, .records = keys } }, @min(rs.expires_ns, ds.expires_ns));
}

/// The judgement of one rrset version; a fresh cell per version, since
/// the verdict is about those bytes; one already stamped on them settles
/// the cell without a rule.
pub fn demandSecure(g: *Graph, by: CellId, rid: CellId) !?CellId {
    var kb: graph.KeyBuf = undefined;
    const t = g.cell(rid);
    std.debug.assert(t.state == .fact);
    const key = graph.Key.of(&kb, .secure, t.name, t.key.rtype);
    if (g.index.get(key)) |sid| {
        const c = g.cell(sid);
        const same = c.scratch.secure.target == rid and c.scratch.secure.target_gen == t.gen;
        if (same and (!c.settled() or g.serves(sid))) return g.join(by, sid);
    }
    const sid = try g.newCell(key, t.name);
    g.cell(sid).scratch.secure.* = .{ .target = rid, .target_gen = t.gen };
    try g.pin(sid, by);
    if (t.blob) |b| if (b.verdict.serves(g.bound(g.payer))) {
        try g.settle(sid, .{ .secure = b.verdict.chain() }, b.verdict.until_ns);
        return sid;
    };
    try g.pin(rid, sid);
    try g.ready.append(g.gpa, sid);
    return sid;
}

/// `secure(rrset)`: nothing to prove where `ds` says the answering zone
/// is unsigned; otherwise each claim the reply makes is judged on its own.
/// A claim that proves nothing may sit below a hidden insecure cut, which
/// only its DS can say (RFC 4035 §4.3, §5.2); else the reply is bogus.
pub fn runSecure(g: *Graph, id: CellId) !void {
    var kb: graph.KeyBuf = undefined;
    const s = g.cell(id).scratch.secure;
    const t = g.cell(s.target);
    const zone = t.state.fact.rrset.zone;
    if (s.zone_ds == .none) s.zone_ds = .wrap(try g.demand(id, graph.Key.of(&kb, .ds, zone, .a), zone) orelse
        return g.fail(id, no_chain));
    const zd = g.cell(s.zone_ds.unwrap().?);
    if (!zd.settled()) return;
    if (zd.failure()) |why| return g.fail(id, why);
    switch (zd.state.fact.ds.status) {
        // Proven no zone, a folded child: its claims are judged as any
        // (RFC 6840 §4.1).
        .secure, .absent => {},
        .insecure => return g.settle(id, .{ .secure = .{ .status = .insecure } }, zd.expires_ns),
    }
    while (true) {
        if (s.fault == null) {
            s.fault = try judge(g, id, s, t, @min(t.expires_ns, zd.expires_ns)) orelse return;
            if (budgetSpent(g)) |why| return g.fail(id, why);
        }
        const c = Claims.at(&t.state.fact.rrset, t.key.rtype, s.next);
        // A proof is excused only where the data it speaks for is: the
        // name denied, while that is the zone's; else its own owner.
        const r = &t.state.fact.rrset;
        const deepest = if (c.is == .proof and r.target.isSubdomainOf(zone)) proof.deepestApex(r.target, t.key.rtype) else proof.deepestApex(c.owner, c.rtype);
        switch (try s.probe.run(g, id, zone, deepest)) {
            .pending => return,
            .cut_short => return g.fail(id, no_chain),
            .stopped => |why| return g.fail(id, why),
            .insecure => |until| {
                s.expires = @min(s.expires, until);
                s.status = .insecure;
                s.next += 1;
                s.fault = null;
                s.probe = .{};
            },
            .none => return if (s.fault.?.failure(g)) |why| g.fail(id, why) else failBogus(g, id, s.target, c),
        }
    }
}

/// Judge the claims from `s.next` on, settling once the last proves
/// itself; a claim that proves nothing is the fault returned.
fn judge(g: *Graph, id: CellId, s: *SecureScratch, t: *const graph.Cell, until: i64) !?Fault {
    var kb: graph.KeyBuf = undefined;
    const r = &t.state.fact.rrset;
    const qtype = t.key.rtype;
    // A zone proven no cut belongs to the zone that proved it (a folded
    // child's parent).
    const zd = g.cell(s.zone_ds.unwrap().?).state.fact.ds;
    const within = if (zd.status == .absent) proof.authoritySigner(zd.records).? else r.zone;
    if (!s.fetched) {
        if (flooded(r, qtype)) {
            try failBogus(g, id, s.target, null);
            return null;
        }
        s.fetched = true;
        var it: Claims = .{ .r = r, .qtype = qtype };
        while (it.next()) |c| {
            const signer = signerOf(r, c, within) orelse continue;
            const key = graph.Key.of(&kb, .dnskey, signer, .a);
            if (!g.holds(key) and !g.index.contains(key)) try g.fetchKeys(id, signer);
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
                const target = try dns.substituteSuffix(g.scratch.allocator(), c.owner, x.dname.name, x.dname.rdata.dname) orelse break :f .bogus;
                break :f if (target.eql(x.cname.rdata.cname)) null else .bogus;
            },
            .rrset, .proof, .denial => {
                const signer = signerOf(r, c, within) orelse break :f .bogus;
                if (!keysOf(g, s.key, signer)) s.key = .wrap(try g.demand(id, graph.Key.of(&kb, .dnskey, signer, .a), signer));
                const kid = s.key.unwrap() orelse break :f .no_chain;
                const kc = g.cell(kid);
                if (!kc.settled()) {
                    s.next = c.slot;
                    return null;
                }
                if (kc.failure() != null) break :f .{ .input = kid };
                s.expires = @min(s.expires, kc.expires_ns);
                const keys = kc.state.fact.dnskey;
                switch (keys.status) {
                    .secure => {},
                    .insecure => {
                        // Insecure keys above a secure zone contradict its DS.
                        if (!signer.isSubdomainOf(r.zone)) break :f .bogus;
                        s.status = .insecure;
                        break :f null;
                    },
                    // The signer is proven no zone: its signature is forged.
                    .absent => break :f .bogus,
                }
                if (c.is == .denial) {
                    const own = try verifiedProofs(g, r, qtype, s.verified, signer);
                    switch (proof.validateNegativeProof(own, c.owner, c.rtype, r.kind == .nxdomain, signer, budget)) {
                        .secure => {
                            var only = r.*;
                            only.authorities = own;
                            try denial.absorb(g, id, signer, only, @min(until, kc.expires_ns, s.proven));
                        },
                        .insecure => s.status = .insecure,
                        .bogus, .unchecked => break :f .bogus,
                    }
                    break :f null;
                }
                const records = if (c.is == .proof) r.authorities else r.answers;
                const verified = dnssec.validateRrset(records, c.owner, c.rtype, keys.records, now, budget, &g.verify_memo) orelse
                    break :f .bogus;
                const cap = capExpiry(g, rrsig.ttlCap(verified, now));
                s.expires = @min(s.expires, cap);
                s.proven = @min(s.proven, cap);
                if (c.is == .proof) {
                    // Proof material is served under its own owner, never
                    // expanded (RFC 4035 §3.1.3.3).
                    if (verified.labels != rrsig.signedLabels(c.owner)) break :f .bogus;
                    s.verified.set(c.slot);
                    break :f null;
                }
                if (verified.labels < rrsig.signedLabels(c.owner)) {
                    const own = try verifiedProofs(g, r, qtype, s.verified, verified.signer_name);
                    switch (proof.proveNoCloserMatch(own, c.owner, verified.labels, verified.signer_name, budget)) {
                        .secure => {},
                        .insecure => s.status = .insecure,
                        .bogus, .unchecked => break :f .bogus,
                    }
                }
                break :f null;
            },
        };
        if (fault) |why| {
            s.next = c.slot;
            return why;
        }
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

/// The most claims a reply `classify` keeps can make: a CNAME and a DNAME
/// set per link, the data at the end, a denial, one SOA and a proof's
/// worth of NSEC or NSEC3. More is refused unread.
const max_claims = 2 * graph.max_links + 2 + 1 + proof.max_proof_records;

fn flooded(r: *const graph.Reply, qtype: dns.RType) bool {
    if (proof.proofFlood(r.authorities)) return true;
    var it: Claims = .{ .r = r, .qtype = qtype };
    var n: usize = 0;
    while (it.next()) |_| {
        n += 1;
        if (n > max_claims) return true;
    }
    return false;
}

/// What a reply claims, one set at a time: the authority's NSEC, NSEC3 and
/// SOA sets, the answer's RRsets in order, then a negative's denial.
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
        is: union(enum) {
            rrset,
            proof,
            /// Proven by the derivation from the DNAME (RFC 6672 §5.3.1).
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
                .nsec, .nsec3, .soa => if (firstOfRrset(auth, i)) return it.claim(rr.name, rr.rtype, .proof),
                else => {},
            }
        }
        const answers = it.r.answers;
        while (it.i < answers.len) {
            const i = it.i;
            it.i += 1;
            const rr = answers[i];
            if (rr.rtype == .rrsig or !firstOfRrset(answers, i)) continue;
            // A CNAME under a DNAME of the reply is its synthesis (RFC 6672
            // §2.4); of several, the deepest, as classify takes.
            var dname: ?RR = null;
            if (rr.rtype == .cname) for (answers) |d| {
                if (d.rtype == .dname and synthesisedUnder(rr, d) and (dname == null or d.name.labels.len > dname.?.name.labels.len)) dname = d;
            };
            if (dname) |d| return it.claim(rr.name, rr.rtype, .{ .synthesised = .{ .cname = rr, .dname = d } });
            return it.claim(rr.name, rr.rtype, .rrset);
        }
        if (it.ended) return null;
        it.ended = true;
        return switch (it.r.kind) {
            .nodata, .nxdomain => it.claim(it.r.target, it.qtype, .denial),
            else => null,
        };
    }

    fn claim(it: *Claims, owner: dns.Name, rtype: dns.RType, is: @FieldType(Claim, "is")) Claim {
        std.debug.assert(it.slot <= max_claims);
        defer it.slot += 1;
        return .{ .slot = it.slot, .owner = owner, .rtype = rtype, .is = is };
    }

    fn at(r: *const graph.Reply, qtype: dns.RType, slot: u8) Claim {
        var it: Claims = .{ .r = r, .qtype = qtype };
        while (it.next()) |c| if (c.slot == slot) return c;
        unreachable;
    }
};

/// The zone a claim's signature names, if it may speak for the owner
/// (RFC 4034 §3.1.3): an RRset's only from within `within`; a denial's,
/// which may come from above, is `proof.denialZone`'s.
fn signerOf(r: *const graph.Reply, c: Claims.Claim, within: dns.Name) ?dns.Name {
    const signer = switch (c.is) {
        .rrset => (dnssec.findRrsigAt(r.answers, c.owner, c.rtype) orelse return null).signer_name,
        .proof => (dnssec.findRrsigAt(r.authorities, c.owner, c.rtype) orelse return null).signer_name,
        .denial => proof.denialZone(r.authorities, r.target) orelse return null,
        .synthesised => return null,
    };
    if (!proof.deepestApex(c.owner, c.rtype).isSubdomainOf(signer)) return null;
    if (c.is == .rrset and !signer.isSubdomainOf(within)) return null;
    return signer;
}

/// `ds(candidate)` one label at a time below `above`, down to `deepest`,
/// for a proven insecure cut; each candidate is asked once.
const Probe = struct {
    cell: OptionalCellId = .none,
    depth: u8 = 0,

    /// `stopped`: a candidate failed on an asker's own limit, so no
    /// candidate below it was ruled out.
    fn run(p: *Probe, g: *Graph, id: CellId, above: dns.Name, deepest: dns.Name) !union(enum) { pending, insecure: i64, none, cut_short, stopped: Failure } {
        var kb: graph.KeyBuf = undefined;
        while (true) {
            if (p.cell.unwrap()) |pid| {
                const c = g.cell(pid);
                if (!c.settled()) return .pending;
                if (c.failure()) |why| {
                    if (why.cause == .asker) return .{ .stopped = why };
                } else if (c.state.fact.ds.status == .insecure) return .{ .insecure = c.expires_ns };
                p.cell = .none;
            }
            p.depth = @max(p.depth, @as(u8, @intCast(above.labels.len))) + 1;
            if (p.depth > deepest.labels.len) return .none;
            const candidate: dns.Name = .{ .labels = deepest.labels[deepest.labels.len - p.depth ..] };
            p.cell = .wrap(try g.demand(id, graph.Key.of(&kb, .ds, candidate, .a), candidate) orelse return .cut_short);
        }
    }
};

/// The proof sets `signer` signed that verified as claims, with their
/// signatures: what a derivation in its zone may read. A set excused below
/// an insecure cut or passed under insecure keys proved nothing, so it is
/// left out. Proof claims come first, so all are judged.
fn verifiedProofs(g: *Graph, r: *const graph.Reply, qtype: dns.RType, verified: @FieldType(SecureScratch, "verified"), signer: dns.Name) ![]const RR {
    const rrs = r.authorities;
    var keep: std.ArrayList(RR) = .empty;
    var it: Claims = .{ .r = r, .qtype = qtype };
    while (it.next()) |c| {
        if (c.is != .proof) break;
        if (!verified.isSet(c.slot)) continue;
        const set = dnssec.setAt(rrs, c.owner, c.rtype);
        const sig = dnssec.findRrsigAt(set, c.owner, c.rtype) orelse continue;
        if (!sig.signer_name.eql(signer)) continue;
        try keep.appendSlice(g.scratch.allocator(), set);
    }
    return keep.items;
}

fn synthesisedUnder(rr: RR, dname: RR) bool {
    return rr.rtype == .cname and rr.name.labels.len > dname.name.labels.len and rr.name.isSubdomainOf(dname.name);
}

/// A reply's sets sit together: a record heads its set unless the one
/// before is of it.
fn firstOfRrset(rrs: []const RR, i: usize) bool {
    return i == 0 or rrs[i - 1].rtype != rrs[i].rtype or !rrs[i - 1].name.eql(rrs[i].name);
}

/// What a referral from `zone` says about `rrset(child, DS)`: the signed
/// DS set, or a denial carrying the referral's NSEC or NSEC3 proof and
/// nothing else of it: the child's NS in a denial's authority reads as a
/// referral to a stub.
pub fn referralDs(g: *Graph, msg: dns.Message, zone: dns.Name, child: dns.Name) !graph.Reply {
    const ds = dnssec.setAt(msg.authorities, child, .ds);
    if (ds.len > 0) {
        var reply: graph.Reply = .{ .kind = .answer, .aa = true, .answers = ds, .zone = zone, .stored_ns = g.now() };
        reply.ttl = walk.replyTtl(g, reply);
        return reply;
    }
    var ttl: u32 = std.math.maxInt(u32);
    var proofs: std.ArrayList(RR) = .empty;
    for (msg.authorities) |rr| switch (if (rr.rtype == .rrsig) rr.rdata.rrsig.type_covered else rr.rtype) {
        .nsec, .nsec3 => {
            try proofs.append(g.scratch.allocator(), rr);
            if (rr.rtype != .rrsig) ttl = @min(ttl, rr.ttl);
        },
        else => {},
    };
    // No proof is no fact to keep.
    if (proofs.items.len == 0) ttl = 0;
    return .{ .kind = .nodata, .aa = true, .authorities = proofs.items, .target = child, .zone = zone, .stored_ns = g.now(), .ttl = ttl };
}
