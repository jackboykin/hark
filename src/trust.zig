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

/// Proven signed, or proven unsigned. Bogus is no fact: it fails.
pub const Proof = enum(u8) { secure, insecure };

/// A verdict and what it rests on: the verified DS set or keys.
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
pub const SecureScratch = struct {
    /// The rrset version under judgement; ids recycle, so its generation too.
    target: CellId = 0,
    target_gen: u32 = 0,
    /// `ds(zone)`: is the answering zone expected to sign at all.
    zone_ds: OptionalCellId = .none,
    /// `dnskey(signer)` per RRset group, in section order.
    keys: [max_groups]OptionalCellId = @splat(.none),
    fault: ?Fault = null,
    probe: Probe = .{},
};
const max_groups = 8;

const Fault = union(enum) { bogus, failed: Failure };

/// A verdict is about one version of its inputs and lives exactly as long
/// as they do. Bogus is no verdict that lives (RFC 4035 §4.3): it fails.
const no_chain: Failure = .{ .code = .dnssec_bogus, .text = "no chain" };
const refused: Failure = .{ .code = .dnssec_bogus, .text = "zone failed validation" };
/// Verified, and still no proof of the insecure cut asked about.
const no_cut: Failure = .{ .code = .dnssec_bogus, .text = "no insecure cut proven" };

/// Proven bogus, the bytes end with the verdict: their TTL was the forger's
/// to set (RFC 4035 §4.7). With the budget spent nothing was proven, and a
/// zone draining its own budget must not drop a victim's bytes.
fn failBogus(g: *Graph, id: CellId, rid: CellId) !void {
    if (budgetSpent(g)) |why| return g.fail(id, why);
    if (!g.spent(g.payer)) {
        const t = g.cell(rid);
        t.expires_ns = @min(t.expires_ns, g.now());
        if (t.blob) |b| g.store.drop(t.key, b);
    }
    try g.fail(id, .{ .code = .dnssec_bogus });
}

fn budgetSpent(g: *Graph) ?Failure {
    const b = &g.payer.validation;
    if (b.nsec3Exhausted()) return .{ .code = .unsupported_nsec3_iterations, .text = "nsec3 budget spent" };
    if (b.exhausted()) return .{ .code = .dnssec_bogus, .text = "validation budget spent" };
    return null;
}

/// A zone's DS or keys proven bogus: demanding them again is refused for
/// `servfail_ttl`, since judging them again per question is KeyTrap's lever
/// (RFC 9520 §3.4).
fn failChain(g: *Graph, id: CellId, rid: CellId) !void {
    if (!g.spent(g.payer)) try g.remember(g.cell(id).key, refused);
    try failBogus(g, id, rid);
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
    if (parent_keys.state.fact.dnskey.status != .secure) return g.settle(id, .{ .ds = .{ .status = parent_keys.state.fact.dnskey.status } }, parent_keys.expires_ns);
    if (s.rrset == .none) s.rrset = .wrap(try g.demand(id, graph.Key.of(&kb, .rrset, zone, .ds), zone) orelse
        return g.fail(id, no_chain));
    const rs = g.cell(s.rrset.unwrap().?);
    if (!rs.settled()) return;
    if (s.fault == null) {
        s.fault = if (rs.failure()) |why| .{ .failed = why } else try judgeDs(g, id, s, zone, rs) orelse return;
        if (budgetSpent(g)) |why| return g.fail(id, why);
    }
    switch (try s.probe.run(g, id, parent_zone, parent_name)) {
        .pending => {},
        .cut_short => try g.fail(id, no_chain),
        .insecure => |until| try g.settle(id, .{ .ds = .{ .status = .insecure } }, until),
        .none => switch (s.fault.?) {
            .bogus => try failChain(g, id, s.rrset.unwrap().?),
            .failed => |why| try g.fail(id, why),
        },
    }
}

fn judgeDs(g: *Graph, id: CellId, s: *DsScratch, zone: dns.Name, rs: *const graph.Cell) !?Fault {
    var kb: graph.KeyBuf = undefined;
    const r = rs.state.fact.rrset;
    const signer = switch (r.kind) {
        .answer => if (dnssec.findRrsigAt(r.answers, zone, .ds)) |sig| sig.signer_name else null,
        .nodata, .nxdomain => proof.authoritySigner(r.authorities),
        // A name that is no cut may alias (a hidden-cut probe).
        .alias => return .{ .failed = no_cut },
        .yxdomain => null,
    } orelse return .bogus;
    if (!proof.isProperAncestor(signer, zone)) return .bogus;
    if (s.signer == .none) s.signer = .wrap(try g.demand(id, graph.Key.of(&kb, .dnskey, signer, .a), signer) orelse
        return .{ .failed = no_chain });
    const keys = g.cell(s.signer.unwrap().?);
    if (!keys.settled()) return null;
    if (keys.failure()) |why| return .{ .failed = why };
    const budget = &g.payer.validation;
    const clock = graph.Tally.clock(&g.tally.verify_ns);
    defer clock.stop();
    const now = g.wallNow();
    const expires = @min(rs.expires_ns, keys.expires_ns);
    switch (r.kind) {
        .answer => {
            const sig = dnssec.validateRrset(r.answers, zone, .ds, keys.state.fact.dnskey.records, now, budget, &g.verify_memo) orelse
                return .bogus;
            const status: Proof = if (dnssec.anySupportedDs(r.answers)) .secure else .insecure;
            try g.settle(id, .{ .ds = .{ .status = status, .records = r.answers } }, @min(expires, capExpiry(g, rrsig.ttlCap(sig, now))));
        },
        .nodata, .nxdomain => {
            // RFC 4034 §3.1.3.
            for (r.authorities) |rr| if ((rr.rtype == .nsec or rr.rtype == .nsec3) and !rr.name.isSubdomainOf(signer))
                return .bogus;
            var cap: u32 = std.math.maxInt(u32);
            if (dnssec.verifyAuthorityProofSigs(r.authorities, keys.state.fact.dnskey.records, now, budget, &g.verify_memo, &cap) != .secure)
                return .bogus;
            switch (proof.classifyDelegation(r.authorities, zone, signer, budget)) {
                .unsigned => try g.settle(id, .{ .ds = .{ .status = .insecure } }, @min(expires, capExpiry(g, cap))),
                // A proven non-cut, or no proof: the bytes are sound.
                .unproven, .bogus => try g.fail(id, budgetSpent(g) orelse no_cut),
            }
        },
        .alias, .yxdomain => unreachable,
    }
    return null;
}

pub const KeysScratch = struct {
    /// The payer of the walk that met the delegation, shared.
    budget: *graph.Budget = undefined,
    keys: OptionalCellId = .none,
};

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
    const keys = try dnssec.usableKeys(g.scratch.allocator(), r.answers, ds_data.items);
    try g.settle(id, .{ .dnskey = .{ .status = .secure, .records = keys } }, @min(@min(rs.expires_ns, ds.expires_ns), capExpiry(g, rrsig.ttlCap(sig, now))));
}

/// The judgement of one rrset version; a fresh cell per version, since
/// the verdict is about those bytes; one already stamped on them settles
/// the cell without a rule.
pub fn demandSecure(g: *Graph, by: CellId, rid: CellId) !CellId {
    var kb: graph.KeyBuf = undefined;
    const t = g.cell(rid);
    const key = graph.Key.of(&kb, .secure, t.name, t.key.rtype);
    if (g.index.get(key)) |sid| {
        const c = g.cell(sid);
        const same = c.scratch.secure.target == rid and c.scratch.secure.target_gen == t.gen;
        if (same and (!c.settled() or g.serves(sid))) {
            try g.pin(sid, by);
            return sid;
        }
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
/// is unsigned; otherwise every RRset group verifies under its signer's
/// keys (owner within signer within zone), a wildcard expansion also
/// proves no closer match, and a negative proves itself under whatever
/// zone signed the authority section. Bytes that prove nothing may sit
/// below a hidden insecure cut, an unsigned child folded onto its signed
/// parent's servers, which only its DS can say (RFC 4035 §4.3, §5.2);
/// else bogus.
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
    if (zd.state.fact.ds.status != .secure) return g.settle(id, .{ .secure = .{ .status = zd.state.fact.ds.status } }, zd.expires_ns);
    const expires = @min(t.expires_ns, zd.expires_ns);
    if (s.fault == null) {
        s.fault = try judge(g, id, s, t, expires) orelse return;
        if (budgetSpent(g)) |why| return g.fail(id, why);
    }
    switch (try s.probe.run(g, id, zone, proof.deepestApex(t.name, t.key.rtype))) {
        .pending => {},
        .cut_short => try g.fail(id, no_chain),
        .insecure => |until| try g.settle(id, .{ .secure = .{ .status = .insecure } }, @min(expires, until)),
        .none => switch (s.fault.?) {
            .bogus => try failBogus(g, id, s.target),
            .failed => |why| try g.fail(id, why),
        },
    }
}

fn judge(g: *Graph, id: CellId, s: *SecureScratch, t: *const graph.Cell, until: i64) !?Fault {
    var kb: graph.KeyBuf = undefined;
    const r = t.state.fact.rrset;
    const zone = r.zone;
    var expires = until;
    const budget = &g.payer.validation;
    const now = g.wallNow();
    var cap: u32 = std.math.maxInt(u32);
    switch (r.kind) {
        .answer, .alias, .yxdomain => {
            // Pass one demands every signer's keys, pass two verifies. A
            // CNAME synthesised under the DNAME before it is proven by the
            // derivation (RFC 6672 §5.3.1).
            var groups: usize = 0;
            var pending = false;
            var prev_dname: ?RR = null;
            for (r.answers, 0..) |rr, i| {
                if (rr.rtype == .rrsig or !firstOfRrset(r.answers, i)) continue;
                if (groups >= max_groups) return .{ .failed = .{ .code = .dnssec_bogus, .text = "too many rrsets" } };
                defer groups += 1;
                defer prev_dname = if (rr.rtype == .dname) rr else null;
                if (synthesisedUnder(rr, prev_dname)) continue;
                const sig = dnssec.findRrsigAt(r.answers, rr.name, rr.rtype) orelse return .bogus;
                // RFC 4034 §3.1.3; a signer above the answering zone
                // authenticates nothing here.
                if (!proof.deepestApex(rr.name, rr.rtype).isSubdomainOf(sig.signer_name) or !sig.signer_name.isSubdomainOf(zone)) return .bogus;
                if (s.keys[groups] == .none) s.keys[groups] = .wrap(try g.demand(id, graph.Key.of(&kb, .dnskey, sig.signer_name, .a), sig.signer_name) orelse
                    return .{ .failed = no_chain });
                pending = pending or !g.cell(s.keys[groups].unwrap().?).settled();
            }
            if (pending) return null;
            const clock = graph.Tally.clock(&g.tally.verify_ns);
            defer clock.stop();
            // Signatures alone: a claim about an empty set.
            if (groups == 0) return .bogus;
            var status: Proof = .secure;
            groups = 0;
            prev_dname = null;
            for (r.answers, 0..) |rr, i| {
                if (rr.rtype == .rrsig or !firstOfRrset(r.answers, i)) continue;
                defer groups += 1;
                defer prev_dname = if (rr.rtype == .dname) rr else null;
                if (synthesisedUnder(rr, prev_dname)) {
                    const target = try dns.substituteSuffix(g.scratch.allocator(), rr.name, prev_dname.?.name, prev_dname.?.rdata.dname) orelse return .bogus;
                    if (!target.eql(rr.rdata.cname)) return .bogus;
                    continue;
                }
                const kc = g.cell(s.keys[groups].unwrap().?);
                if (kc.failure()) |why| return .{ .failed = why };
                expires = @min(expires, kc.expires_ns);
                if (kc.state.fact.dnskey.status == .insecure) {
                    status = .insecure;
                    continue;
                }
                const verified = dnssec.validateRrset(r.answers, rr.name, rr.rtype, kc.state.fact.dnskey.records, now, budget, &g.verify_memo) orelse
                    return .bogus;
                cap = @min(cap, rrsig.ttlCap(verified, now));
                if (verified.labels < rrsig.signedLabels(rr.name)) {
                    if (dnssec.verifyAuthorityProofSigs(r.authorities, kc.state.fact.dnskey.records, now, budget, &g.verify_memo, &cap) != .secure) return .bogus;
                    switch (proof.proveNoCloserMatch(r.authorities, rr.name, verified.labels, verified.signer_name, budget)) {
                        .secure => {},
                        .insecure => status = .insecure,
                        .bogus, .unchecked => return .bogus,
                    }
                }
            }
            try g.settle(id, .{ .secure = .{ .status = status, .proven_until_ns = if (status == .secure) capExpiry(g, cap) else std.math.maxInt(i64) } }, @min(expires, capExpiry(g, cap)));
        },
        .nodata, .nxdomain => {
            const signer = proof.authoritySigner(r.authorities) orelse return .bogus;
            if (!proof.deepestApex(t.name, t.key.rtype).isSubdomainOf(signer)) return .bogus;
            if (s.keys[0] == .none) s.keys[0] = .wrap(try g.demand(id, graph.Key.of(&kb, .dnskey, signer, .a), signer) orelse
                return .{ .failed = no_chain });
            const kc = g.cell(s.keys[0].unwrap().?);
            if (!kc.settled()) return null;
            const clock = graph.Tally.clock(&g.tally.verify_ns);
            defer clock.stop();
            if (kc.failure()) |why| return .{ .failed = why };
            expires = @min(expires, kc.expires_ns);
            if (kc.state.fact.dnskey.status == .insecure) {
                if (!signer.isSubdomainOf(zone)) return .bogus;
                try g.settle(id, .{ .secure = .{ .status = .insecure } }, expires);
                return null;
            }
            if (dnssec.verifyAuthorityProofSigs(r.authorities, kc.state.fact.dnskey.records, now, budget, &g.verify_memo, &cap) != .secure) return .bogus;
            switch (proof.validateNegativeProof(r.authorities, t.name, t.key.rtype, r.kind == .nxdomain, signer, budget)) {
                .secure => {
                    expires = @min(expires, capExpiry(g, cap));
                    try denial.absorb(g, id, signer, r, expires);
                    try g.settle(id, .{ .secure = .{ .status = .secure, .proven_until_ns = capExpiry(g, cap) } }, expires);
                },
                .insecure => try g.settle(id, .{ .secure = .{ .status = .insecure } }, @min(expires, capExpiry(g, cap))),
                .bogus, .unchecked => return .bogus,
            }
        },
    }
    return null;
}

/// `ds(candidate)` one label at a time below `above`, down to `deepest`,
/// for a proven insecure cut; each candidate is asked once.
const Probe = struct {
    cell: OptionalCellId = .none,
    depth: u8 = 0,

    fn run(p: *Probe, g: *Graph, id: CellId, above: dns.Name, deepest: dns.Name) !union(enum) { pending, insecure: i64, none, cut_short } {
        var kb: graph.KeyBuf = undefined;
        while (true) {
            if (p.cell.unwrap()) |pid| {
                const c = g.cell(pid);
                if (!c.settled()) return .pending;
                if (c.failure() == null and c.state.fact.ds.status == .insecure) return .{ .insecure = c.expires_ns };
                p.cell = .none;
            }
            p.depth = @max(p.depth, @as(u8, @intCast(above.labels.len))) + 1;
            if (p.depth > deepest.labels.len) return .none;
            const candidate: dns.Name = .{ .labels = deepest.labels[deepest.labels.len - p.depth ..] };
            p.cell = .wrap(try g.demand(id, graph.Key.of(&kb, .ds, candidate, .a), candidate) orelse return .cut_short);
        }
    }
};

/// A CNAME directly under the DNAME group before it.
fn synthesisedUnder(rr: RR, prev_dname: ?RR) bool {
    const d = prev_dname orelse return false;
    return rr.rtype == .cname and rr.name.labels.len > d.name.labels.len and rr.name.isSubdomainOf(d.name);
}

fn firstOfRrset(rrs: []const RR, i: usize) bool {
    for (rrs[0..i]) |p| if (p.rtype == rrs[i].rtype and p.name.eql(rrs[i].name)) return false;
    return true;
}

/// What a referral from `zone` says about `rrset(child, DS)`: the signed
/// DS set, or a denial carrying the authority section as proof. Only
/// proof material gives it a TTL.
pub fn referralDs(g: *Graph, msg: dns.Message, zone: dns.Name, child: dns.Name) !graph.Reply {
    var keep: std.ArrayList(RR) = .empty;
    var ttl: u32 = std.math.maxInt(u32);
    var any = false;
    for (msg.authorities) |rr| if (rr.name.eql(child) and (rr.rtype == .ds or (rr.rtype == .rrsig and rr.rdata.rrsig.type_covered == .ds))) {
        try keep.append(g.scratch.allocator(), rr);
        if (rr.rtype == .ds) {
            ttl = @min(ttl, rr.ttl);
            any = true;
        }
    };
    // Signatures over no DS are no answer.
    if (any) return .{ .kind = .answer, .rcode = .no_error, .aa = true, .answers = keep.items, .zone = zone, .stored_ns = g.now(), .ttl = ttl };
    ttl = 0;
    for (msg.authorities) |rr| if (rr.rtype == .nsec or rr.rtype == .nsec3) {
        ttl = if (ttl == 0) rr.ttl else @min(ttl, rr.ttl);
    };
    return .{ .kind = .nodata, .rcode = .no_error, .aa = true, .authorities = msg.authorities, .zone = zone, .stored_ns = g.now(), .ttl = ttl };
}
