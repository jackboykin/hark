//! Model-based denial fuzzing. Smith draws a small signed zone and its honest
//! NSEC or NSEC3 chain, then as attacker picks which genuine records reach
//! the validator and what the query claims. The zone is the oracle: a verdict
//! contradicting it is a replay hole, and an honest proof failing to verify
//! is a SERVFAIL on a real zone.
const std = @import("std");
const testing = std.testing;
const Smith = testing.Smith;
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");

const apex = "example";
const alphabet = [_][]const u8{ "a", "b", "*", "A" };
const qtypes = [_]dns.RType{ .a, .ns, .cname, .soa, .txt, .dname, .ds, .aaaa };
const max_names = 6;
const max_depth = 3;
const max_chain = 32;

const Types = packed struct(u8) {
    a: bool = false,
    ns: bool = false,
    cname: bool = false,
    soa: bool = false,
    dname: bool = false,
    ds: bool = false,
    _: u2 = 0,

    fn has(t: Types, qtype: dns.RType) bool {
        return switch (qtype) {
            .a => t.a,
            .ns => t.ns,
            .cname => t.cname,
            .soa => t.soa,
            .dname => t.dname,
            .ds => t.ds,
            else => false,
        };
    }
    fn delegation(t: Types) bool {
        return t.ns and !t.soa;
    }
};

// What one owner may hold: a delegation only NS(+DS), a CNAME nothing else.
const shapes = [_]Types{ .{ .a = true }, .{ .cname = true }, .{ .ns = true }, .{ .ns = true, .ds = true }, .{ .dname = true }, .{ .dname = true, .a = true } };

const Entry = struct {
    labels: [max_depth + 1][]const u8,
    depth: usize,
    types: Types,

    fn name(e: *const Entry) dns.Name {
        return .{ .labels = e.labels[0..e.depth] };
    }
};

const Truth = enum { positive, nodata, nxdomain, referral };

const Zone = struct {
    entries: [max_chain]Entry,
    n: usize,
    nsec3: bool,
    optout: bool,
    salt: [8]u8,
    salt_len: usize,
    iterations: u16,
    recs: [max_chain]dns.ResourceRecord,
    n_recs: usize,
    hashes: [max_chain][20]u8,
    enc: [max_chain][32]u8,
    owner_labels: [max_chain][2][]const u8,
    bitmaps: [max_chain][9]u8,

    fn find(z: *const Zone, name: dns.Name) ?*const Entry {
        for (z.entries[0..z.n]) |*e| if (e.name().eql(name)) return e;
        return null;
    }

    /// Opt-Out signers leave unsigned delegations out of the chain.
    fn omitted(z: *const Zone, e: *const Entry) bool {
        return z.nsec3 and z.optout and e.types.delegation() and !e.types.ds;
    }

    fn inChain(z: *const Zone, name: dns.Name) bool {
        const e = z.find(name) orelse return false;
        return !z.omitted(e);
    }

    /// A proper ancestor that ends this zone's authority. Omitted delegations
    /// don't count: to the validator that cut is invisible.
    fn cutAbove(z: *const Zone, name: dns.Name) bool {
        for (1..name.labels.len) |k| {
            const e = z.find(.{ .labels = name.labels[k..] }) orelse continue;
            if ((e.types.dname or e.types.delegation()) and !z.omitted(e)) return true;
        }
        return false;
    }

    fn closestEncloser(z: *const Zone, name: dns.Name) dns.Name {
        for (1..name.labels.len) |k| {
            const anc = dns.Name{ .labels = name.labels[k..] };
            if (z.inChain(anc)) return anc;
        }
        return name;
    }

    fn truth(z: *const Zone, qname: dns.Name, qtype: dns.RType) Truth {
        for (1..qname.labels.len) |k| {
            const e = z.find(.{ .labels = qname.labels[k..] }) orelse continue;
            if (e.types.dname or e.types.delegation()) return .referral;
        }
        if (z.find(qname)) |e| return answerAt(e.types, qtype);
        var wl: [dns.max_label_count + 1][]const u8 = undefined;
        const wc = dns.makeWildcardName(&wl, z.closestEncloser(qname)).?;
        if (z.find(wc)) |e| return answerAt(e.types, qtype);
        return .nxdomain;
    }

    fn answerAt(t: Types, qtype: dns.RType) Truth {
        if (t.delegation() and qtype != .ds) return .referral;
        if (t.soa and qtype == .ds) return .referral;
        return if (t.has(qtype) or t.cname) .positive else .nodata;
    }

    /// The chain record that speaks for `name`: owner match or the span
    /// around it. A circular chain leaves no name out.
    fn relevant(z: *const Zone, name: dns.Name) usize {
        var h: [20]u8 = undefined;
        if (z.nsec3) h = dnssec.nsec3Hash(name, z.salt[0..z.salt_len], z.iterations) catch unreachable;
        for (z.recs[0..z.n_recs], 0..) |rr, i| {
            if (z.nsec3) {
                const owner = &z.hashes[i];
                const next = rr.rdata.nsec3.next_hashed_owner;
                if (std.mem.eql(u8, owner, &h) or between(std.mem.order(u8, owner, &h), std.mem.order(u8, &h, next), std.mem.order(u8, owner, next))) return i;
            } else {
                const next = rr.rdata.nsec.next_domain_name;
                if (rr.name.eql(name) or between(dnssec.canonicalNameOrder(rr.name, name), dnssec.canonicalNameOrder(name, next), dnssec.canonicalNameOrder(rr.name, next))) return i;
            }
        }
        unreachable;
    }

    fn coverer(z: *const Zone, name: dns.Name) ?dns.Nsec3Data {
        if (!z.nsec3 or z.inChain(name)) return null;
        return z.recs[z.relevant(name)].rdata.nsec3;
    }

    /// The only honest source of an `.insecure` verdict.
    fn optoutCovered(z: *const Zone, name: dns.Name) bool {
        return (z.coverer(name) orelse return false).flags == 1;
    }

    /// The ancestor-or-self of `name` one label below its closest encloser.
    fn nextCloser(z: *const Zone, name: dns.Name) dns.Name {
        const ce = z.closestEncloser(name);
        return .{ .labels = name.labels[name.labels.len - @min(ce.labels.len + 1, name.labels.len) ..] };
    }
};

fn between(lo_vs_x: std.math.Order, x_vs_hi: std.math.Order, lo_vs_hi: std.math.Order) bool {
    return if (lo_vs_hi == .lt) lo_vs_x == .lt and x_vs_hi == .lt else lo_vs_x == .lt or x_vs_hi == .lt;
}

fn genName(s: *Smith, labels: *[max_depth + 1][]const u8) dns.Name {
    const d = s.valueRangeAtMost(u8, 0, max_depth);
    for (labels[0..d]) |*l| l.* = alphabet[s.index(alphabet.len)];
    labels[d] = apex;
    return .{ .labels = labels[0 .. d + 1] };
}

fn bitmap(buf: *[9]u8, t: Types, chain: dns.RType) []const u8 {
    buf.* = [_]u8{ 0, 7, 0, 0, 0, 0, 0, 0, 0 };
    inline for (.{ .a, .ns, .cname, .soa, .dname, .ds }) |rt| if (t.has(rt)) set(buf, rt);
    set(buf, .rrsig);
    set(buf, chain);
    return buf;
}

fn set(buf: *[9]u8, rt: dns.RType) void {
    const n = @backingInt(rt);
    buf[2 + n / 8] |= @as(u8, 0x80) >> @intCast(n % 8);
}

fn draw(z: *Zone, s: *Smith) void {
    var raw: [max_names + 1]Entry = undefined;
    raw[0] = .{ .labels = .{ apex, "", "", "" }, .depth = 1, .types = .{ .soa = true, .ns = true, .dname = s.boolWeighted(15, 1) } };
    var n: usize = 1;
    names: for (0..s.valueRangeAtMost(u8, 1, max_names)) |_| {
        var e: Entry = undefined;
        e.depth = s.valueRangeAtMost(u8, 1, max_depth) + 1;
        for (e.labels[0 .. e.depth - 1]) |*l| l.* = alphabet[s.index(alphabet.len)];
        e.labels[e.depth - 1] = apex;
        e.types = shapes[s.index(shapes.len)];
        for (raw[0..n]) |o| if (o.name().eql(e.name())) continue :names;
        raw[n] = e;
        n += 1;
    }

    // Names under a cut or DNAME are occluded: the zone never serves them.
    z.n = 0;
    outer: for (raw[0..n]) |e| {
        for (1..e.depth) |k| for (raw[0..n]) |o| {
            if (o.name().eql(.{ .labels = e.name().labels[k..] }) and (o.types.dname or o.types.delegation())) continue :outer;
        };
        z.entries[z.n] = e;
        z.n += 1;
    }
    // Empty non-terminals exist too; NSEC3 chains give them records.
    for (0..z.n) |i| {
        const e = z.entries[i];
        for (1..e.depth) |k| {
            const anc = dns.Name{ .labels = e.name().labels[k..] };
            if (anc.labels.len == 1) break;
            if (z.find(anc) != null) continue;
            z.entries[z.n] = .{ .labels = undefined, .depth = anc.labels.len, .types = .{} };
            @memcpy(z.entries[z.n].labels[0..anc.labels.len], anc.labels);
            z.n += 1;
        }
    }

    z.nsec3 = s.boolWeighted(1, 1);
    z.optout = z.nsec3 and s.boolWeighted(1, 1);
    z.salt_len = s.valueRangeAtMost(u8, 0, z.salt.len);
    s.bytes(z.salt[0..z.salt_len]);
    z.iterations = s.valueRangeAtMost(u16, 0, 2);
    const all_optout = z.optout and s.boolWeighted(1, 1);

    // Hashes are entry-indexed here and record-indexed once sorted.
    var ehash: [max_chain][20]u8 = undefined;
    var order: [max_chain]usize = undefined;
    z.n_recs = 0;
    for (0..z.n) |i| {
        const e = &z.entries[i];
        if (z.nsec3) ehash[i] = dnssec.nsec3Hash(e.name(), z.salt[0..z.salt_len], z.iterations) catch unreachable;
        if (z.omitted(e) or (!z.nsec3 and @as(u8, @bitCast(e.types)) == 0)) continue;
        order[z.n_recs] = i;
        z.n_recs += 1;
    }
    const Ctx = struct { z: *Zone, ehash: *[max_chain][20]u8 };
    std.mem.sort(usize, order[0..z.n_recs], Ctx{ .z = z, .ehash = &ehash }, struct {
        fn lt(c: Ctx, a: usize, b: usize) bool {
            if (c.z.nsec3) return std.mem.order(u8, &c.ehash[a], &c.ehash[b]) == .lt;
            return dnssec.canonicalNameOrder(c.z.entries[a].name(), c.z.entries[b].name()) == .lt;
        }
    }.lt);
    for (order[0..z.n_recs], 0..) |i, r| z.hashes[r] = ehash[i];

    for (order[0..z.n_recs], 0..) |i, r| {
        const e = &z.entries[i];
        const nr = (r + 1) % z.n_recs;
        if (!z.nsec3) {
            z.recs[r] = .{ .name = e.name(), .rtype = .nsec, .rclass = .in, .ttl = 300, .rdata = .{ .nsec = .{
                .next_domain_name = z.entries[order[nr]].name(),
                .type_bit_maps = bitmap(&z.bitmaps[r], e.types, .nsec),
            } } };
            continue;
        }
        z.owner_labels[r] = .{ dns.base32HexEncode(&z.enc[r], &z.hashes[r]), apex };
        // RFC 5155 §7.1: the flag marks spans hiding an unsigned delegation.
        var optout = all_optout;
        for (z.entries[0..z.n], 0..) |*o, j| if (z.omitted(o)) {
            if (between(std.mem.order(u8, &z.hashes[r], &ehash[j]), std.mem.order(u8, &ehash[j], &z.hashes[nr]), std.mem.order(u8, &z.hashes[r], &z.hashes[nr]))) optout = true;
        };
        z.recs[r] = .{ .name = .{ .labels = &z.owner_labels[r] }, .rtype = .nsec3, .rclass = .in, .ttl = 300, .rdata = .{ .nsec3 = .{
            .hash_algorithm = .sha1,
            .flags = @intFromBool(optout),
            .iterations = z.iterations,
            .salt = z.salt[0..z.salt_len],
            .next_hashed_owner = &z.hashes[nr],
            .type_bit_maps = bitmap(&z.bitmaps[r], e.types, .nsec3),
        } } };
    }
}

/// What an honest server sends for `qname`: whatever speaks for it, each
/// ancestor, and the closest encloser's wildcard.
fn honest(z: *const Zone, qname: dns.Name, mask: *[max_chain]bool) void {
    @memset(mask, false);
    for (0..qname.labels.len) |k| mask[z.relevant(.{ .labels = qname.labels[k..] })] = true;
    var wl: [dns.max_label_count + 1][]const u8 = undefined;
    mask[z.relevant(dns.makeWildcardName(&wl, z.closestEncloser(qname)).?)] = true;
}

const Section = struct {
    recs: [max_chain]dns.ResourceRecord = undefined,
    n: usize = 0,

    fn pick(sec: *Section, z: *const Zone, s: *Smith, mask: *const [max_chain]bool, exact: bool) []const dns.ResourceRecord {
        sec.n = 0;
        for (z.recs[0..z.n_recs], 0..) |rr, i| {
            const keep = if (exact) mask[i] else if (mask[i]) s.boolWeighted(1, 3) else s.boolWeighted(4, 1);
            if (!keep) continue;
            sec.recs[sec.n] = rr;
            sec.n += 1;
        }
        var i = sec.n;
        while (i > 1) : (i -= 1) std.mem.swap(dns.ResourceRecord, &sec.recs[i - 1], &sec.recs[s.index(i)]);
        return sec.recs[0..sec.n];
    }
};

fn dump(z: *const Zone, auth: []const dns.ResourceRecord, qname: dns.Name, qtype: dns.RType, extra: anytype) void {
    var b: [dns.max_dotted_len + 1]u8 = undefined;
    std.debug.print("\nzone nsec3={} optout={} iter={} salt={x}\n", .{ z.nsec3, z.optout, z.iterations, z.salt[0..z.salt_len] });
    for (z.entries[0..z.n]) |*e| std.debug.print("  {s} {any}\n", .{ e.name().formatInto(&b), e.types });
    for (z.recs[0..z.n_recs], 0..) |rr, i| {
        std.debug.print("  rec{d} {s} ", .{ i, rr.name.formatInto(&b) });
        switch (rr.rdata) {
            .nsec => |x| std.debug.print("-> {s} bitmap={x}\n", .{ x.next_domain_name.formatInto(&b), x.type_bit_maps }),
            .nsec3 => |x| std.debug.print("-> {x} flags={d} bitmap={x}\n", .{ x.next_hashed_owner, x.flags, x.type_bit_maps }),
            else => {},
        }
    }
    std.debug.print("auth:", .{});
    for (auth) |rr| for (z.recs[0..z.n_recs], 0..) |zr, i| if (zr.name.eql(rr.name)) std.debug.print(" rec{d}", .{i});
    std.debug.print("\nqname={s} qtype={t} {any}\n", .{ qname.formatInto(&b), qtype, extra });
}

// After a fuzz failure, `cp .zig-cache/f/in0 .zig-cache/f/crash` (the mmap
// of the input that died) and plain `zig build test` replays it with the dump.
test "replay" {
    const data = std.Io.Dir.cwd().readFileAlloc(testing.io, ".zig-cache/f/crash", testing.allocator, .limited(1 << 32)) catch return;
    defer testing.allocator.free(data);
    const Header = std.Build.abi.fuzz.MmapInputHeader;
    const len = std.mem.readInt(u32, data[@offsetOf(Header, "len")..][0..4], .little);
    var smith: Smith = .{ .in = data[@sizeOf(Header)..][0..len] };
    try fuzzOne({}, &smith);
}

fn fuzzOne(_: void, s: *Smith) anyerror!void {
    var z: Zone = undefined;
    draw(&z, s);
    const zone = dns.Name{ .labels = &.{apex} };
    const exact = s.boolWeighted(2, 1);
    var mask: [max_chain]bool = undefined;
    var sec: Section = .{};
    var budget: dnssec.ValidationBudget = .{};

    var ql: [max_depth + 1][]const u8 = undefined;
    const qname = genName(s, &ql);
    const qtype = qtypes[s.index(qtypes.len)];
    const t = z.truth(qname, qtype);
    const is_nxdomain = if (exact) t == .nxdomain else s.boolWeighted(1, 1);
    honest(&z, qname, &mask);
    const auth = sec.pick(&z, s, &mask, exact);
    const ce = z.closestEncloser(qname);
    const nc = z.nextCloser(qname);
    var wl: [dns.max_label_count + 1][]const u8 = undefined;
    const wc = dns.makeWildcardName(&wl, ce).?;
    const v1 = dnssec.validateNegativeProof(auth, qname, qtype, is_nxdomain, zone, &budget);
    errdefer dump(&z, auth, qname, qtype, .{ t, is_nxdomain, exact, v1 });
    switch (v1) {
        .secure => if (t == .positive or t == .referral or (is_nxdomain and t != .nxdomain)) return error.UnsoundDenial,
        .insecure => {
            // RFC 5155 §8.6 takes an Opt-Out span over the next closer as the
            // whole DS answer; a wildcard delegation with DS misreads, and
            // that is the RFC's to own.
            const ds_optout = qtype == .ds and !is_nxdomain and z.optoutCovered(nc);
            if (!ds_optout and (t == .positive or !(z.optoutCovered(nc) or z.optoutCovered(wc)))) return error.UnsoundOptOut;
        },
        .bogus, .unchecked => if (exact and (t == .nodata or t == .nxdomain)) return error.HonestDenialRefused,
    }

    // Wildcard expansion: no closer match below the RRSIG's encloser.
    budget = .{};
    const labels: u8 = if (exact) @intCast(ce.labels.len) else s.valueRangeAtMost(u8, 0, @intCast(qname.labels.len));
    const v2 = dnssec.proveNoCloserMatch(auth, qname, labels, zone, &budget);
    errdefer std.debug.print("wildcard labels={d} {t}\n", .{ labels, v2 });
    switch (v2) {
        .secure, .insecure => |v| {
            const closer = dns.Name{ .labels = qname.labels[qname.labels.len - labels - 1 ..] };
            if (v == .secure and z.find(closer) != null) return error.UnsoundWildcard;
            if (v == .insecure and !z.optoutCovered(closer)) return error.UnsoundWildcard;
        },
        .bogus, .unchecked => if (exact and t != .referral and z.find(qname) == null) return error.HonestWildcardRefused,
    }

    budget = .{};
    var cl: [max_depth + 1][]const u8 = undefined;
    var child = genName(s, &cl);
    if (exact) {
        for (z.entries[0..z.n]) |*e| if (e.types.delegation()) {
            child = e.name();
            break;
        };
    }
    honest(&z, child, &mask);
    const ref = sec.pick(&z, s, &mask, exact);
    const e = z.find(child);
    const insecure_delegation = if (e) |x| x.types.delegation() and !x.types.ds else false;
    const v3 = dnssec.classifyDelegation(ref, child, zone, &budget);
    errdefer dump(&z, ref, child, .ds, .{ insecure_delegation, v3 });
    switch (v3) {
        .insecure => {
            if (child.labels.len == 1 or z.cutAbove(child)) return error.UnsoundDelegation;
            if (e != null and !insecure_delegation) return error.UnsoundDelegation;
            if (!z.inChain(child) and !z.optoutCovered(z.nextCloser(child))) return error.UnsoundDelegation;
        },
        .secure => if (exact and insecure_delegation) return error.HonestDelegationRefused,
        .bogus => {},
        .unchecked => return error.DelegationVerdict,
    }
}

test "fuzz: dnssec denial proofs against a model zone" {
    try testing.fuzz({}, fuzzOne, .{});
}
