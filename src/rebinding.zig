/// DNS rebinding protection: strip A/AAAA answers carrying private,
/// loopback, link-local, or otherwise non-routable addresses from public
/// zones, so a browser-side attacker can't point `attacker.com` at the
/// victim's `127.0.0.1:8765` and call the local dev server cross-origin.
///
/// Filter site: a single egress hook in `response.shapeAnswers`. Filtering
/// once at the wire boundary covers fresh resolution, cache hits, and
/// TTL=0 answers (which would skip a cache-insertion filter) in one place,
/// and lets operator config changes (`allow_zones`, `extra_allow`) take
/// effect immediately instead of waiting for TTL expiry.
///
/// What we *don't* do, and why:
///   • Synthesise SOA in authority on an empty-rrset. RFC 2308 makes SOA
///     optional in NODATA; emitting empty-authority means the stub retries
///     on next config change instead of negative-caching a stale block.
///   • SERVFAIL or REFUSED on a scrub. REFUSED tends to push stubs to the
///     next resolver in resolv.conf, leaking the same query to an
///     unprotected upstream and giving the attacker their rebind anyway.
///   • SVCB/HTTPS ipv4hint/ipv6hint scrubbing. `dns.RData` doesn't yet
///     have parsed SVCB variants; folded into the eventual SVCB landing.
///   • NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) translation-prefix
///     embedded-v4 detection. Both encode an IPv4 address in v6 bits,
///     so an attacker AAAA pointing at `64:ff9b::c0a8:0101` translates
///     to `192.168.1.1` on a NAT64-enabled stub. The default block set
///     deliberately does NOT include these prefixes — blocking them by
///     default would break legitimate NAT64/6to4 deployments. Operators
///     running stubs *without* NAT64/6to4 can add either via `extra_block`;
///     operators *with* NAT64/6to4 either disable rebinding scrubbing or
///     accept that mapped-private answers can slip through this vector.
///
/// Owner-name allowlist matching: each RR carries its own owner name on
/// the wire. For a CNAME chain `home.example.com → box.lan.example → A
/// 192.168.1.1`, the terminal A's `name` is `box.lan.example`, so a
/// `lan.example` allowlist entry passes the chain through unmolested
/// — the right behaviour, matching Unbound (not BIND's qname-based variant).
const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const acl = @import("acl.zig");
const dns = @import("dns.zig");
const na = @import("net_address.zig");

const log = std.log.scoped(.rebinding);

/// Inline cap on marks-bitmap size. Realistic answer sections are tiny
/// (1–10 RRs; ~50 worst case before UDP truncation kicks in), so the
/// common path uses a stack-resident array. TCP responses can carry far
/// more RRs — `scrub` heap-allocates marks for those rather than falling
/// back to a less-correct path.
const max_inline_marks = 128;

/// Operator-supplied rebinding policy. Lives in `ServerConfig` and is
/// referenced (not copied) by `ResponseContext`.
pub const Config = struct {
    enabled: bool,
    /// Owner-name allowlist. RRs whose owner name equals or is a subdomain
    /// of any entry bypass the filter entirely. Use for split-horizon
    /// zones like `homelab.lan` whose authoritative legitimately returns
    /// RFC 1918 space. `home.arpa` is intercepted by `special_use.zig`
    /// upstream of recursion, so including it here is a no-op.
    allow_zones: []const dns.Name,
    /// Additive block CIDRs on top of the built-in default set.
    extra_block: []const acl.Cidr,
    /// Subtractive allow CIDRs (DNSBL escape hatch). RRs whose address
    /// matches any entry are kept even if they'd otherwise be blocked —
    /// the canonical use is `["127.0.0.0/8"]` for operators running
    /// RFC 5782 DNSBL lookups that *want* 127/8 answers.
    extra_allow: []const acl.Cidr,

    pub const off: Config = .{
        .enabled = false,
        .allow_zones = &.{},
        .extra_block = &.{},
        .extra_allow = &.{},
    };
};

/// Returns true if this RR should be dropped from the answer section.
/// Inspects only A and AAAA; every other rtype passes through.
fn shouldDrop(rr: dns.ResourceRecord, cfg: Config) bool {
    if (!cfg.enabled) return false;
    // Allowlist walk is per-RR; skip when no zones configured (the
    // default deployment) so the hot path stays one branch + a switch.
    if (cfg.allow_zones.len > 0) {
        for (cfg.allow_zones) |zone| {
            if (rr.name.isSubdomainOf(zone)) return false;
        }
    }
    return switch (rr.rtype) {
        .a => isPrivate(&rr.rdata.a, cfg),
        .aaaa => isPrivate(&rr.rdata.aaaa, cfg),
        else => false,
    };
}

/// Single pass over `answers`: mark + log drops in a marks bitmap, then
/// copy the keep-set if anything would be dropped. Fast path (no drops)
/// returns the input slice unchanged with zero allocation. Single
/// evaluation of `shouldDrop` per RR — no fragility if the predicate
/// ever gains side effects.
///
/// Marks live on the stack for the common case; large answer sections
/// (TCP responses with hundreds of RRs) get a heap-allocated bitmap so
/// the orphan-RRSIG sweep below applies uniformly.
pub fn scrub(
    alloc: mem.Allocator,
    answers: []const dns.ResourceRecord,
    cfg: Config,
) mem.Allocator.Error![]const dns.ResourceRecord {
    if (!cfg.enabled or answers.len == 0) return answers;

    var marks_inline: [max_inline_marks]bool = undefined;
    var marks_heap: ?[]bool = null;
    defer if (marks_heap) |h| alloc.free(h);
    const marks: []bool = if (answers.len <= max_inline_marks)
        marks_inline[0..answers.len]
    else blk: {
        marks_heap = try alloc.alloc(bool, answers.len);
        break :blk marks_heap.?;
    };

    var drop_count: usize = 0;
    for (answers, 0..) |rr, i| {
        marks[i] = shouldDrop(rr, cfg);
        if (marks[i]) {
            drop_count += 1;
            logScrub(rr);
        }
    }
    if (drop_count == 0) return answers;

    // Orphan-RRSIG sweep. Dropping any record from an A/AAAA rrset
    // invalidates the upstream's RRSIG (it signed the full set as it
    // existed at the authoritative). Leaving the signature behind
    // violates RFC 4035 §3.1 and SERVFAILs strict validators on DO=1.
    // Same scope as the scrub: A and AAAA only — RRSIGs over other types
    // pass through. O(N²) but N is bounded by the answer section size.
    for (answers, 0..) |rr, i| {
        if (marks[i] or rr.rtype != .rrsig) continue;
        const covered = rr.rdata.rrsig.type_covered;
        if (covered != .a and covered != .aaaa) continue;
        for (answers, 0..) |other, k| {
            if (!marks[k] or other.rtype != covered) continue;
            if (!other.name.eql(rr.name)) continue;
            marks[i] = true;
            drop_count += 1;
            break;
        }
    }

    const out = try alloc.alloc(dns.ResourceRecord, answers.len - drop_count);
    var j: usize = 0;
    for (answers, 0..) |rr, i| {
        if (marks[i]) continue;
        out[j] = rr;
        j += 1;
    }
    return out;
}

fn logScrub(rr: dns.ResourceRecord) void {
    var name_buf: [dns.max_name_len + 1]u8 = undefined;
    const name = rr.name.formatLower(&name_buf);
    switch (rr.rtype) {
        .a => log.info("scrub a owner={s} addr={d}.{d}.{d}.{d}", .{
            name, rr.rdata.a[0], rr.rdata.a[1], rr.rdata.a[2], rr.rdata.a[3],
        }),
        .aaaa => {
            // `na.format` emits "[addr]:0" — minor cosmetic noise in the log
            // line; not worth a dedicated formatter.
            var addr_buf: [64]u8 = undefined;
            log.info("scrub aaaa owner={s} addr={s}", .{ name, na.format(na.initIp6(rr.rdata.aaaa, 0, 0, 0), &addr_buf) });
        },
        else => unreachable,
    }
}

/// Address is private by this policy when it matches the built-in default
/// set or an `extra_block` entry, AND does not match an `extra_allow`
/// entry. Allow takes precedence so DNSBL operators can carve back 127/8.
///
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is checked against the embedded v4
/// address for both extras — keeps `extra_allow = ["127.0.0.0/8"]` honest
/// when an AAAA-flavoured DNSBL returns a mapped 127.0.0.x. Mirrors the
/// recursion `matchesDefault` already does for the built-in v4 set.
fn isPrivate(bytes: []const u8, cfg: Config) bool {
    const mapped_v4: ?*const [4]u8 = if (na.isIp4Mapped(bytes)) bytes[12..16] else null;

    for (cfg.extra_allow) |c| {
        if (c.matchesBytes(bytes)) return false;
        if (mapped_v4) |v4| if (c.matchesBytes(v4)) return false;
    }
    if (matchesDefault(bytes)) return true;
    for (cfg.extra_block) |c| {
        if (c.matchesBytes(bytes)) return true;
        if (mapped_v4) |v4| if (c.matchesBytes(v4)) return true;
    }
    return false;
}

/// Default block set is the shared special-use table (net_address.zig) —
/// deliberately multicast-free here, unlike NS egress.
fn matchesDefault(bytes: []const u8) bool {
    return switch (bytes.len) {
        4 => na.isSpecialUseIp4(bytes[0..4].*),
        16 => na.isSpecialUseIp6(bytes[0..16].*),
        else => false,
    };
}

// ── Tests ──────────────────────────────────────────────────────────────
//
// The `.rpl` scenarios in `test/scenarios/hark/rebinding/` exercise the
// full stack (scrub fires on egress, allow-zone bypass, DNSBL escape hatch
// via `extra_allow`). Unit tests below cover the bits scenarios can't:
// per-RFC CIDR tables, IPv4-mapped IPv6 symmetry, and the RRSIG-on-partial-
// rrset edge case that's load-bearing for DO=1 protocol correctness.

const public_name = dns.Name{ .labels = &.{ "attacker", "com" } };

fn rrA(name: dns.Name, ip: [4]u8) dns.ResourceRecord {
    return .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = ip } };
}

fn rrAAAA(name: dns.Name, ip: [16]u8) dns.ResourceRecord {
    return .{ .name = name, .rtype = .aaaa, .rclass = .in, .ttl = 60, .rdata = .{ .aaaa = ip } };
}

fn rrsigOver(covered: dns.RType) dns.ResourceRecord {
    return .{ .name = public_name, .rtype = .rrsig, .rclass = .in, .ttl = 60, .rdata = .{ .rrsig = .{
        .type_covered = covered,
        .algorithm = .ecdsap256sha256,
        .labels = 2,
        .original_ttl = 60,
        .sig_expiration = 0,
        .sig_inception = 0,
        .key_tag = 0,
        .signer_name = public_name,
        .signature = &.{},
    } } };
}

test "extra_allow v4 entry carves out IPv4-mapped IPv6 too (symmetric DNSBL behaviour)" {
    // The default v6 set defers to v4 via the mapped-prefix recursion; an
    // operator's v4 `extra_allow` must therefore match the mapped form too,
    // or AAAA-DNSBL silently stops working when v4-DNSBL does not.
    const allow127 = acl.parse("127.0.0.0/8") orelse return error.ParseFailed;
    const cfg = Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{allow127} };
    const mapped_listed = @as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 127, 0, 0, 2 };
    const mapped_rfc1918 = @as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 10, 0, 0, 1 };
    try testing.expect(!shouldDrop(rrAAAA(public_name, mapped_listed), cfg));
    try testing.expect(shouldDrop(rrAAAA(public_name, mapped_rfc1918), cfg));
}

test "scrub drops RRSIG when its rrset is partially scrubbed (sig invalidated by member removal)" {
    // RFC 4034: RRSIG signs the full rrset as it existed upstream. Removing
    // even one member invalidates the signature for the survivors.
    const cfg = Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{} };
    const answers: []const dns.ResourceRecord = &.{
        rrA(public_name, .{ 192, 168, 1, 1 }), // scrubbed
        rrA(public_name, .{ 8, 8, 8, 8 }), // kept
        rrsigOver(.a), // must drop — orphan after partial scrub
    };
    const scrubbed = try scrub(testing.allocator, answers, cfg);
    defer testing.allocator.free(scrubbed);
    try testing.expectEqual(@as(usize, 1), scrubbed.len);
    try testing.expectEqual(dns.RType.a, scrubbed[0].rtype);
}

test "scrub heap path: >128-RR section drops private A and the orphaned RRSIG" {
    // answers.len > max_inline_marks forces the heap marks bitmap + orphan-RRSIG
    // sweep that the small-section tests above never reach.
    const cfg = Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{} };

    const public_count = 100;
    const private_count = 100;
    var answers: [public_count + private_count + 1]dns.ResourceRecord = undefined;
    var idx: usize = 0;
    for (0..public_count) |i| {
        answers[idx] = rrA(public_name, .{ 8, 8, @intCast(i >> 8), @intCast(i & 0xff) });
        idx += 1;
    }
    for (0..private_count) |i| {
        answers[idx] = rrA(public_name, .{ 192, 168, @intCast(i >> 8), @intCast(i & 0xff) });
        idx += 1;
    }
    answers[idx] = rrsigOver(.a); // orphaned once any member of its rrset is scrubbed

    try testing.expect(answers.len > max_inline_marks); // guards the heap branch

    const scrubbed = try scrub(testing.allocator, &answers, cfg);
    defer testing.allocator.free(scrubbed);

    try testing.expectEqual(@as(usize, public_count), scrubbed.len);
    for (scrubbed) |rr| {
        try testing.expectEqual(dns.RType.a, rr.rtype); // RRSIG dropped, no private survived
        try testing.expect(!na.isSpecialUseIp4(rr.rdata.a));
    }
}
