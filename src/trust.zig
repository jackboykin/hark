//! The chain of trust as cells: `ds(zone)`, `dnskey(zone)` and
//! `secure(rrset)`. The verdicts are decided here; the verification itself
//! is dnssec.zig's.
const std = @import("std");
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");
const graph = @import("graph.zig");
const denial = @import("denial.zig");

const Graph = graph.Graph;
const CellId = graph.CellId;
const Failure = graph.Failure;
const RR = dns.ResourceRecord;
const Status = dnssec.SecurityStatus;

/// A verdict and what it rests on: the verified DS set or keys.
pub const Chain = struct {
    status: Status,
    records: []const RR = &.{},
    /// `secure` only: where the signatures' validity ends (`rrsigTtlCap`).
    proven_until_ns: i64 = std.math.maxInt(i64),
};

pub const DsScratch = struct { parent: ?CellId = null, keys: ?CellId = null, rrset: ?CellId = null, signer: ?CellId = null };
pub const DnskeyScratch = struct { ds: ?CellId = null, rrset: ?CellId = null };
pub const SecureScratch = struct {
    /// The rrset version under judgement; ids recycle, so its generation too.
    target: CellId = 0,
    target_gen: u32 = 0,
    /// `ds(zone)`: is the answering zone expected to sign at all.
    zone_ds: ?CellId = null,
    /// `dnskey(signer)` per RRset group, in section order.
    keys: [max_groups]?CellId = @splat(null),
    /// Hidden-cut probe: `ds(candidate)` one label at a time.
    probe: ?CellId = null,
    probe_depth: u8 = 0,
};
const max_groups = 8;

/// A verdict is about one version of its inputs and lives exactly as long
/// as they do. Bogus is no verdict that lives (RFC 4035 §4.3): it fails.
const no_chain: Failure = .{ .code = .dnssec_bogus, .text = "no chain" };
const refused: Failure = .{ .code = .dnssec_bogus, .text = "zone failed validation" };
/// Verified, and still no proof of the insecure cut asked about.
const no_cut: Failure = .{ .code = .dnssec_bogus, .text = "no insecure cut proven" };

/// Proven bogus, the bytes end with the verdict: their TTL was the forger's
/// to set (RFC 4035 §4.7), and the stamp keeps serve-stale off them. With
/// the budget spent nothing was proven: the cell is shared, and a zone
/// draining its own budget must not mark a victim's bytes.
fn failBogus(g: *Graph, id: CellId, rid: CellId) !void {
    if (g.cell(id).budget.validation.exhausted()) return g.fail(id, .{ .code = .dnssec_bogus, .text = "validation budget spent" });
    const t = g.cell(rid);
    t.expires_ns = @min(t.expires_ns, g.now());
    if (t.blob) |b| {
        b.verdict.stamp(.{ .status = .bogus }, g.now());
        g.store.shorten(t.key, b, g.now());
    }
    try g.fail(id, .{ .code = .dnssec_bogus });
}

/// A zone's DS or keys proven bogus: its chain work is refused for
/// `servfail_ttl`, since judging them again per question is KeyTrap's lever
/// (RFC 9520 §3.4).
fn failChain(g: *Graph, id: CellId, rid: CellId) !void {
    if (!g.cell(id).budget.validation.exhausted()) try g.remember(chainKey(g, id));
    try failBogus(g, id, rid);
}

fn capExpiry(g: *Graph, cap: u32) i64 {
    return g.now() + @as(i64, cap) * std.time.ns_per_s;
}

/// One per zone, whether `ds` or `dnskey` failed.
fn chainKey(g: *Graph, id: CellId) graph.Key {
    return .{ .kind = .ds, .name = g.cell(id).key.name };
}

/// `ds(zone)`: the anchor at the root; below it, `rrset(zone, DS)` judged
/// under the keys of whatever signed it, a proper ancestor of the zone:
/// the walked parent may hide a signed cut on its own servers, or fold
/// one (901). A signed set with a usable algorithm is secure, a proven
/// absence or unusable set insecure, anything else bogus. An insecure
/// parent is inherited, and so is a failed one.
pub fn runDs(g: *Graph, id: CellId) !void {
    const zone = g.cell(id).name;
    const s = g.cell(id).scratch.ds;
    const anchor = g.cfg.trust_anchor orelse return g.settle(id, .{ .ds = .{ .status = .insecure } }, std.math.maxInt(i64));
    if (zone.labels.len == 0) {
        const rr: RR = .{ .name = zone, .rtype = .ds, .rclass = .in, .ttl = 0, .rdata = .{ .ds = anchor } };
        return g.settle(id, .{ .ds = .{ .status = .secure, .records = try g.scratch.allocator().dupe(RR, &.{rr}) } }, std.math.maxInt(i64));
    }
    if (g.refusing(chainKey(g, id))) return g.fail(id, refused);
    const parent_name: dns.Name = .{ .labels = zone.labels[1..] };
    if (s.parent == null) s.parent = try g.demand(id, try g.keyFor(.cut, parent_name, .a), parent_name, g.cell(id).depth) orelse
        return g.fail(id, no_chain);
    const parent = g.cell(s.parent.?);
    if (!parent.settled) return;
    if (parent.failure) |why| return g.fail(id, why);
    const parent_zone = parent.value.cut.zone;
    if (s.keys == null) s.keys = try g.demand(id, try g.keyFor(.dnskey, parent_zone, .a), parent_zone, g.cell(id).depth) orelse
        return g.fail(id, no_chain);
    const parent_keys = g.cell(s.keys.?);
    if (!parent_keys.settled) return;
    if (parent_keys.failure) |why| return g.fail(id, why);
    if (parent_keys.value.dnskey.status != .secure) return g.settle(id, .{ .ds = .{ .status = parent_keys.value.dnskey.status } }, parent_keys.expires_ns);
    if (s.rrset == null) s.rrset = try g.demand(id, try g.keyFor(.rrset, zone, .ds), zone, g.cell(id).depth) orelse
        return g.fail(id, no_chain);
    const rs = g.cell(s.rrset.?);
    if (!rs.settled) return;
    if (rs.failure) |why| return g.fail(id, why);
    const r = rs.value.rrset;
    const signer = switch (r.kind) {
        .answer => if (dnssec.findRrsigAt(r.answers, zone, .ds)) |sig| sig.signer_name else null,
        .nodata, .nxdomain => dnssec.authoritySigner(r.authorities),
        // A name that is no cut may alias (a hidden-cut probe).
        .alias => return g.fail(id, no_cut),
        .yxdomain => null,
    } orelse return failChain(g, id, s.rrset.?);
    if (!dnssec.isProperAncestor(signer, zone)) return failChain(g, id, s.rrset.?);
    if (s.signer == null) s.signer = try g.demand(id, try g.keyFor(.dnskey, signer, .a), signer, g.cell(id).depth) orelse
        return g.fail(id, no_chain);
    const keys = g.cell(s.signer.?);
    if (!keys.settled) return;
    if (keys.failure) |why| return g.fail(id, why);
    if (keys.value.dnskey.status != .secure) return failChain(g, id, s.rrset.?);
    const budget = &g.cell(id).budget.validation;
    const clock = graph.Tally.clock(&g.tally.verify_ns);
    defer clock.stop();
    const now = g.wallNow();
    const expires = @min(rs.expires_ns, keys.expires_ns);
    switch (r.kind) {
        .answer => {
            const sig = dnssec.validateRrset(r.answers, zone, .ds, keys.value.dnskey.records, now, budget) orelse
                return failChain(g, id, s.rrset.?);
            const status: Status = if (dnssec.anySupportedDs(r.answers)) .secure else .insecure;
            try g.settle(id, .{ .ds = .{ .status = status, .records = r.answers } }, @min(expires, capExpiry(g, dnssec.rrsigTtlCap(sig, now))));
        },
        .nodata, .nxdomain => {
            // RFC 4034 §3.1.3.
            for (r.authorities) |rr| if ((rr.rtype == .nsec or rr.rtype == .nsec3) and !rr.name.isSubdomainOf(signer))
                return failChain(g, id, s.rrset.?);
            var cap: u32 = std.math.maxInt(u32);
            if (dnssec.verifyAuthorityProofSigs(r.authorities, keys.value.dnskey.records, now, budget, &cap) != .secure)
                return failChain(g, id, s.rrset.?);
            switch (dnssec.classifyDelegation(r.authorities, zone, signer, budget)) {
                .insecure => try g.settle(id, .{ .ds = .{ .status = .insecure } }, @min(expires, capExpiry(g, cap))),
                // A proven non-cut, or no proof: the bytes are sound.
                else => try g.fail(id, no_cut),
            }
        },
        .alias, .yxdomain => unreachable,
    }
}

/// `dnskey(zone)`: `rrset(zone, DNSKEY)` verified under `ds(zone)`.
pub fn runDnskey(g: *Graph, id: CellId) !void {
    const zone = g.cell(id).name;
    const s = g.cell(id).scratch.dnskey;
    if (g.refusing(chainKey(g, id))) return g.fail(id, refused);
    if (s.ds == null) s.ds = try g.demand(id, try g.keyFor(.ds, zone, .a), zone, g.cell(id).depth) orelse
        return g.fail(id, no_chain);
    // A DS on record, proven or not, says the keys will be needed: fetch
    // them alongside the proof instead of a round trip per level after it.
    if (s.rrset == null) if (try g.peek(try g.keyFor(.rrset, zone, .ds))) |f| if (f.value.rrset.kind == .answer) {
        s.rrset = try g.demand(id, try g.keyFor(.rrset, zone, .dnskey), zone, g.cell(id).depth);
    };
    const ds = g.cell(s.ds.?);
    if (!ds.settled) return;
    if (ds.failure) |why| return g.fail(id, why);
    if (ds.value.ds.status != .secure) return g.settle(id, .{ .dnskey = .{ .status = ds.value.ds.status } }, ds.expires_ns);
    if (s.rrset == null) s.rrset = try g.demand(id, try g.keyFor(.rrset, zone, .dnskey), zone, g.cell(id).depth) orelse
        return g.fail(id, no_chain);
    const rs = g.cell(s.rrset.?);
    if (!rs.settled) return;
    if (rs.failure) |why| return g.fail(id, why);
    const r = rs.value.rrset;
    if (r.kind != .answer) return failChain(g, id, s.rrset.?);
    var ds_data: std.ArrayList(dns.DsData) = .empty;
    for (ds.value.ds.records) |rr| if (rr.rtype == .ds) try ds_data.append(g.scratch.allocator(), rr.rdata.ds);
    const budget = &g.cell(id).budget.validation;
    const clock = graph.Tally.clock(&g.tally.verify_ns);
    defer clock.stop();
    const now = g.wallNow();
    const sig = dnssec.validateDnskeyRrset(r.answers, ds_data.items, zone, now, budget) catch
        return failChain(g, id, s.rrset.?);
    try g.settle(id, .{ .dnskey = .{ .status = .secure, .records = r.answers } }, @min(@min(rs.expires_ns, ds.expires_ns), capExpiry(g, dnssec.rrsigTtlCap(sig, now))));
}

/// The judgement of one rrset version; a fresh cell per version, since
/// the verdict is about those bytes; one already stamped on them settles
/// the cell without a rule.
pub fn demandSecure(g: *Graph, by: CellId, rid: CellId) !CellId {
    const t = g.cell(rid);
    const key = try g.keyFor(.secure, t.name, t.key.rtype);
    const budget = g.cell(by).budget;
    if (g.index.get(key)) |sid| {
        const c = g.cell(sid);
        const same = c.scratch.secure.target == rid and c.scratch.secure.target_gen == t.gen;
        if (same and (!c.settled or c.expires_ns > g.bound(budget) or (c.budget == budget and g.fresh(sid)))) {
            try g.pin(sid, by);
            return sid;
        }
    }
    const sid = try g.newCell(key, t.name, g.cell(by).budget, g.cell(by).depth);
    g.cell(sid).scratch.secure.* = .{ .target = rid, .target_gen = t.gen };
    try g.pin(sid, by);
    if (t.blob) |b| if (b.verdict.until_ns > g.bound(budget)) {
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
/// zone signed the authority section. An unsigned authoritative reply
/// from a signed zone may sit below a hidden insecure cut, probed one
/// label at a time.
pub fn runSecure(g: *Graph, id: CellId) !void {
    const s = g.cell(id).scratch.secure;
    const t = g.cell(s.target);
    const r = t.value.rrset;
    const zone = r.zone;
    const depth = g.cell(id).depth;
    if (s.zone_ds == null) s.zone_ds = try g.demand(id, try g.keyFor(.ds, zone, .a), zone, depth) orelse
        return g.fail(id, no_chain);
    const zd = g.cell(s.zone_ds.?);
    if (!zd.settled) return;
    if (zd.failure) |why| return g.fail(id, why);
    if (zd.value.ds.status != .secure) return g.settle(id, .{ .secure = .{ .status = zd.value.ds.status } }, zd.expires_ns);
    var expires = @min(t.expires_ns, zd.expires_ns);
    const budget = &g.cell(id).budget.validation;
    const now = g.wallNow();
    var cap: u32 = std.math.maxInt(u32);
    // An unsigned AA reply from a zone expected to sign: the answering
    // zone may be an unsigned child folded onto the parent's servers
    // (tld-servers.ru on the ru servers), which only its DS can say.
    if (r.aa and !hasSignature(r)) switch (try probeHiddenCut(g, id, s, zone, t, depth)) {
        .pending => return,
        .insecure => |until| return g.settle(id, .{ .secure = .{ .status = .insecure } }, @min(expires, until)),
        .none => {},
    };
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
                if (groups >= max_groups) return g.fail(id, .{ .code = .dnssec_bogus, .text = "too many rrsets" });
                defer groups += 1;
                defer prev_dname = if (rr.rtype == .dname) rr else null;
                if (synthesisedUnder(rr, prev_dname)) continue;
                const sig = dnssec.findRrsigAt(r.answers, rr.name, rr.rtype) orelse return failBogus(g, id, s.target);
                // RFC 4034 §3.1.3; a signer above the answering zone
                // authenticates nothing here.
                if (!rr.name.isSubdomainOf(sig.signer_name) or !sig.signer_name.isSubdomainOf(zone)) return failBogus(g, id, s.target);
                if (s.keys[groups] == null) s.keys[groups] = try g.demand(id, try g.keyFor(.dnskey, sig.signer_name, .a), sig.signer_name, depth) orelse
                    return g.fail(id, no_chain);
                pending = pending or !g.cell(s.keys[groups].?).settled;
            }
            if (pending) return;
            const clock = graph.Tally.clock(&g.tally.verify_ns);
            defer clock.stop();
            // Signatures alone: a claim about an empty set.
            if (groups == 0) return failBogus(g, id, s.target);
            var status: Status = .secure;
            groups = 0;
            prev_dname = null;
            for (r.answers, 0..) |rr, i| {
                if (rr.rtype == .rrsig or !firstOfRrset(r.answers, i)) continue;
                defer groups += 1;
                defer prev_dname = if (rr.rtype == .dname) rr else null;
                if (synthesisedUnder(rr, prev_dname)) {
                    const target = try dns.substituteSuffix(g.scratch.allocator(), rr.name, prev_dname.?.name, prev_dname.?.rdata.dname) orelse return failBogus(g, id, s.target);
                    if (!target.eql(rr.rdata.cname)) return failBogus(g, id, s.target);
                    continue;
                }
                const kc = g.cell(s.keys[groups].?);
                if (kc.failure) |why| return g.fail(id, why);
                if (kc.value.dnskey.status != .secure) return failBogus(g, id, s.target);
                expires = @min(expires, kc.expires_ns);
                const verified = dnssec.validateRrset(r.answers, rr.name, rr.rtype, kc.value.dnskey.records, now, budget) orelse
                    return failBogus(g, id, s.target);
                cap = @min(cap, dnssec.rrsigTtlCap(verified, now));
                var verdict: Status = .secure;
                if (verified.labels < dnssec.signedLabels(rr.name)) {
                    if (dnssec.verifyAuthorityProofSigs(r.authorities, kc.value.dnskey.records, now, budget, &cap) != .secure) return failBogus(g, id, s.target);
                    verdict = dnssec.proveNoCloserMatch(r.authorities, rr.name, verified.labels, verified.signer_name, budget);
                    if (verdict == .bogus or verdict == .unchecked) return failBogus(g, id, s.target);
                }
                status = dnssec.weakest(status, verdict);
            }
            try g.settle(id, .{ .secure = .{ .status = status, .proven_until_ns = if (status == .secure) capExpiry(g, cap) else std.math.maxInt(i64) } }, @min(expires, capExpiry(g, cap)));
        },
        .nodata, .nxdomain => {
            const signer = dnssec.authoritySigner(r.authorities) orelse return failBogus(g, id, s.target);
            if (s.keys[0] == null) s.keys[0] = try g.demand(id, try g.keyFor(.dnskey, signer, .a), signer, depth) orelse
                return g.fail(id, no_chain);
            const kc = g.cell(s.keys[0].?);
            if (!kc.settled) return;
            const clock = graph.Tally.clock(&g.tally.verify_ns);
            defer clock.stop();
            if (kc.failure) |why| return g.fail(id, why);
            if (kc.value.dnskey.status != .secure) return failBogus(g, id, s.target);
            expires = @min(expires, kc.expires_ns);
            if (dnssec.verifyAuthorityProofSigs(r.authorities, kc.value.dnskey.records, now, budget, &cap) != .secure) return failBogus(g, id, s.target);
            switch (dnssec.validateNegativeProof(r.authorities, t.name, t.key.rtype, r.kind == .nxdomain, signer, budget)) {
                .secure => {
                    expires = @min(expires, capExpiry(g, cap));
                    try denial.absorb(g, id, signer, r, expires);
                    try g.settle(id, .{ .secure = .{ .status = .secure, .proven_until_ns = capExpiry(g, cap) } }, expires);
                },
                .insecure => try g.settle(id, .{ .secure = .{ .status = .insecure } }, @min(expires, capExpiry(g, cap))),
                .bogus, .unchecked => try failBogus(g, id, s.target),
            }
        },
    }
}

/// `ds(candidate)` one label at a time below `zone`, down to the name for
/// a positive, or to the SOA owner for a negative. Once (`probe_depth`).
fn probeHiddenCut(g: *Graph, id: CellId, s: *SecureScratch, zone: dns.Name, t: *const graph.Cell, depth: u8) !union(enum) { pending, insecure: i64, none } {
    var deepest = t.name;
    if (t.value.rrset.kind == .nodata or t.value.rrset.kind == .nxdomain) {
        deepest = zone;
        for (t.value.rrset.authorities) |rr| if (rr.rtype == .soa and t.name.isSubdomainOf(rr.name) and rr.name.isSubdomainOf(zone)) {
            deepest = rr.name;
        };
    }
    while (true) {
        if (s.probe) |pid| {
            const p = g.cell(pid);
            if (!p.settled) return .pending;
            if (p.failure == null and p.value.ds.status == .insecure) return .{ .insecure = p.expires_ns };
            s.probe = null;
        }
        s.probe_depth = @max(s.probe_depth, @as(u8, @intCast(zone.labels.len))) + 1;
        if (s.probe_depth > deepest.labels.len) return .none;
        const candidate: dns.Name = .{ .labels = deepest.labels[deepest.labels.len - s.probe_depth ..] };
        s.probe = try g.demand(id, try g.keyFor(.ds, candidate, .a), candidate, depth) orelse return .none;
    }
}

/// A CNAME directly under the DNAME group before it.
fn synthesisedUnder(rr: RR, prev_dname: ?RR) bool {
    const d = prev_dname orelse return false;
    return rr.rtype == .cname and rr.name.labels.len > d.name.labels.len and rr.name.isSubdomainOf(d.name);
}

fn hasSignature(r: graph.Reply) bool {
    for (r.answers) |rr| if (rr.rtype == .rrsig) return true;
    for (r.authorities) |rr| if (rr.rtype == .rrsig) return true;
    return false;
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
    for (msg.authorities) |rr| if (rr.name.eql(child) and (rr.rtype == .ds or (rr.rtype == .rrsig and rr.rdata.rrsig.type_covered == .ds))) {
        try keep.append(g.scratch.allocator(), rr);
        if (rr.rtype == .ds) ttl = @min(ttl, rr.ttl);
    };
    if (keep.items.len > 0) return .{ .kind = .answer, .rcode = .no_error, .aa = true, .answers = keep.items, .zone = zone, .stored_ns = g.now(), .ttl = ttl };
    ttl = 0;
    for (msg.authorities) |rr| if (rr.rtype == .nsec or rr.rtype == .nsec3) {
        ttl = if (ttl == 0) rr.ttl else @min(ttl, rr.ttl);
    };
    return .{ .kind = .nodata, .rcode = .no_error, .aa = true, .authorities = msg.authorities, .zone = zone, .stored_ns = g.now(), .ttl = ttl };
}
