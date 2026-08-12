/// DNS rebinding protection: strip A/AAAA answers carrying private,
/// loopback, link-local, or otherwise non-routable addresses from public
/// zones, so a browser-side attacker can't point `attacker.com` at the
/// victim's `127.0.0.1:8765` and call the local dev server cross-origin.
///
/// Filter site: egress hooks in `response.shapeResponse`, one per
/// section. Filtering at the wire boundary covers fresh resolution,
/// cache hits, and TTL=0 answers (which would skip a cache-insertion
/// filter) in one place, and lets operator config changes
/// (`allow_zones`, `extra_allow`) take effect immediately instead of
/// waiting for TTL expiry.
///
/// What we *don't* do, and why:
///   • Synthesise SOA in authority on an empty-rrset. RFC 2308 makes SOA
///     optional in NODATA; emitting empty-authority means the stub retries
///     on next config change instead of negative-caching a stale block.
///   • SERVFAIL or REFUSED on a scrub. REFUSED tends to push stubs to the
///     next resolver in resolv.conf, leaking the same query to an
///     unprotected upstream and giving the attacker their rebind anyway.
///   • Rewrite SVCB/HTTPS hints in place. RFC 9460 §7.3: modifying the
///     hints breaks DNSSEC validation. The whole RR drops instead,
///     matching Unbound's 1.25.0 rebinding fix.
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

/// Inline cap on marks-bitmap size. Realistic sections are tiny
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

/// Returns true if this RR should be dropped from the section.
/// Inspects A/AAAA addresses and SVCB/HTTPS address hints; every other
/// rtype passes through. The allowlist walk runs only on records that
/// would otherwise drop, so public records never pay a name comparison.
fn shouldDrop(rr: dns.ResourceRecord, cfg: Config) bool {
    if (!cfg.enabled) return false;
    const private = switch (rr.rtype) {
        .a => isPrivate(&rr.rdata.a, cfg),
        .aaaa => isPrivate(&rr.rdata.aaaa, cfg),
        .svcb, .https => svcbHintsPrivate(rr.rdata.unknown, cfg),
        else => false,
    };
    if (!private) return false;
    for (cfg.allow_zones) |zone| {
        if (rr.name.isSubdomainOf(zone)) return false;
    }
    return true;
}

/// SVCB/HTTPS RDATA (RFC 9460 §2.2): SvcPriority u16 · uncompressed
/// TargetName · SvcParams as (key u16, len u16, value) triples. Scan
/// ipv4hint (key 4) and ipv6hint (key 6) for blocked addresses.
///
/// Malformation bias follows Unbound's rebinding fix: past the
/// TargetName, a length overrun is clamped and the bytes inspected
/// anyway — a lenient client must never out-parse the scrubber. The
/// TargetName itself is strict: a compression pointer or invalid label
/// makes the hints unlocatable, so the RR is treated as carrying one.
fn svcbHintsPrivate(rdata: []const u8, cfg: Config) bool {
    if (rdata.len < 3) return false; // too short to hold an address
    var pos: usize = 2; // SvcPriority
    while (true) {
        if (pos >= rdata.len) return true; // truncated TargetName
        const label_len = rdata[pos];
        pos += 1;
        if (label_len == 0) break;
        if (label_len > dns.max_label_len) return true; // pointer or junk
        pos += label_len;
    }
    while (pos + 4 <= rdata.len) {
        const key = mem.readInt(u16, rdata[pos..][0..2], .big);
        const declared_len = mem.readInt(u16, rdata[pos + 2 ..][0..2], .big);
        pos += 4;
        const value = rdata[pos..][0..@min(declared_len, rdata.len - pos)];
        const addr_size: usize = switch (key) {
            4 => 4, // ipv4hint
            6 => 16, // ipv6hint
            else => 0,
        };
        var off: usize = 0;
        while (addr_size != 0 and off + addr_size <= value.len) : (off += addr_size) {
            if (isPrivate(value[off..][0..addr_size], cfg)) return true;
        }
        pos += value.len;
    }
    return false;
}

/// Single pass over one message section: mark + log drops in a marks
/// bitmap, then copy the keep-set if anything would be dropped. Fast
/// path (no drops) returns the input slice unchanged with zero
/// allocation. Single evaluation of `shouldDrop` per RR — no fragility
/// if the predicate ever gains side effects.
///
/// Marks live on the stack for the common case; large sections (TCP
/// responses with hundreds of RRs) get a heap-allocated bitmap so the
/// orphan-RRSIG sweep below applies uniformly.
pub fn scrub(
    alloc: mem.Allocator,
    records: []const dns.ResourceRecord,
    cfg: Config,
) mem.Allocator.Error![]const dns.ResourceRecord {
    if (!cfg.enabled or records.len == 0) return records;

    var marks_inline: [max_inline_marks]bool = undefined;
    var marks_heap: ?[]bool = null;
    defer if (marks_heap) |h| alloc.free(h);
    const marks: []bool = if (records.len <= max_inline_marks)
        marks_inline[0..records.len]
    else blk: {
        marks_heap = try alloc.alloc(bool, records.len);
        break :blk marks_heap.?;
    };

    var drop_count: usize = 0;
    var first_drop: usize = 0;
    for (records, 0..) |rr, i| {
        marks[i] = shouldDrop(rr, cfg);
        if (marks[i]) {
            if (drop_count == 0) first_drop = i;
            drop_count += 1;
        }
    }
    if (drop_count == 0) return records;

    // One line per scrubbed answer, not per RR — a hostile domain can carry
    // hundreds of private-address records.
    var name_buf: [dns.max_name_len + 1]u8 = undefined;
    log.info("scrub dropped={d} owner={s}", .{ drop_count, records[first_drop].name.formatLower(&name_buf) });

    // Orphan-RRSIG sweep. Dropping any record from an rrset invalidates
    // the upstream's RRSIG (it signed the full set as it existed at the
    // authoritative). Leaving the signature behind violates RFC 4035
    // §3.1 and SERVFAILs strict validators on DO=1. The marks bitmap is
    // the scope — an RRSIG drops iff a member of its rrset was dropped,
    // so the sweep can never drift from `shouldDrop`. O(N²) but N is
    // bounded by the section size.
    for (records, 0..) |rr, i| {
        if (marks[i] or rr.rtype != .rrsig) continue;
        const covered = rr.rdata.rrsig.type_covered;
        for (records, 0..) |other, k| {
            if (!marks[k] or other.rtype != covered) continue;
            if (!other.name.eql(rr.name)) continue;
            marks[i] = true;
            drop_count += 1;
            break;
        }
    }

    const out = try alloc.alloc(dns.ResourceRecord, records.len - drop_count);
    var j: usize = 0;
    for (records, 0..) |rr, i| {
        if (marks[i]) continue;
        out[j] = rr;
        j += 1;
    }
    return out;
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

fn rrHttps(name: dns.Name, rdata: []const u8) dns.ResourceRecord {
    return .{ .name = name, .rtype = .https, .rclass = .in, .ttl = 60, .rdata = .{ .unknown = rdata } };
}

/// SvcPriority 1 · TargetName "."
const svc_prefix: []const u8 = &.{ 0, 1, 0 };

fn svcParam(comptime key: u16, comptime value: []const u8) []const u8 {
    const hdr = [_]u8{ key >> 8, key & 0xff, value.len >> 8, value.len & 0xff };
    return &(hdr ++ value[0..value.len].*);
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

test "extra_block scrubs a configured public CIDR, leaving its siblings alone" {
    // extra_block earns its keep only on addresses the default set ignores:
    // a globally-routable CIDR an operator wants treated as internal. The
    // sibling proves it blocks that CIDR, not "any public address".
    const block = acl.parse("93.184.216.0/24") orelse return error.ParseFailed;
    const cfg = Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{block}, .extra_allow = &.{} };
    try testing.expect(shouldDrop(rrA(public_name, .{ 93, 184, 216, 34 }), cfg));
    try testing.expect(!shouldDrop(rrA(public_name, .{ 93, 184, 217, 7 }), cfg));
}

test "svcb hints: private ipv4hint/ipv6hint drop the RR, public hints pass" {
    const cfg = Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{} };
    const private_v4 = comptime svc_prefix ++ svcParam(4, &.{ 192, 168, 1, 1 });
    const public_v4 = comptime svc_prefix ++ svcParam(4, &.{ 8, 8, 8, 8 });
    const private_v6 = comptime svc_prefix ++ svcParam(6, &(@as([15]u8, @splat(0)) ++ [_]u8{1})); // ::1
    const public_after_alpn = comptime svc_prefix ++ svcParam(1, "\x02h2") ++ svcParam(4, &.{ 1, 1, 1, 1 });
    try testing.expect(shouldDrop(rrHttps(public_name, private_v4), cfg));
    try testing.expect(shouldDrop(rrHttps(public_name, private_v6), cfg));
    try testing.expect(!shouldDrop(rrHttps(public_name, public_v4), cfg));
    try testing.expect(!shouldDrop(rrHttps(public_name, public_after_alpn), cfg));
    // second address in the hint list is the private one
    const second_private = comptime svc_prefix ++ svcParam(4, &.{ 8, 8, 8, 8, 10, 0, 0, 1 });
    try testing.expect(shouldDrop(rrHttps(public_name, second_private), cfg));
}

test "svcb hints: malformed rdata is drop-biased past the TargetName, pass-biased before it" {
    const cfg = Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{} };
    // Declared SvcParam length overruns rdata: clamp and inspect anyway.
    const overrun = [_]u8{ 0, 1, 0, 0, 4, 0xff, 0xff, 127, 0, 0, 1 };
    try testing.expect(shouldDrop(rrHttps(public_name, &overrun), cfg));
    // Compression pointer in TargetName: hints unlocatable → drop.
    const pointer = [_]u8{ 0, 1, 0xc0, 0x0c, 0, 4, 0, 4, 8, 8, 8, 8 };
    try testing.expect(shouldDrop(rrHttps(public_name, &pointer), cfg));
    // Truncated TargetName (label runs off the end) → drop.
    const truncated = [_]u8{ 0, 1, 5, 'a', 'b' };
    try testing.expect(shouldDrop(rrHttps(public_name, &truncated), cfg));
    // Too short to hold any address → pass (nothing to hide).
    try testing.expect(!shouldDrop(rrHttps(public_name, &.{ 0, 1 }), cfg));
    // Trailing partial address chunk is not a dialable address → pass.
    const partial = comptime svc_prefix ++ svcParam(4, &.{ 8, 8, 8, 8, 192, 168 });
    try testing.expect(!shouldDrop(rrHttps(public_name, partial), cfg));
    // TargetName with real labels, then a private hint → still found.
    const named = comptime &[_]u8{ 0, 1, 3, 'c', 'd', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 } ++ svcParam(4, &.{ 172, 16, 0, 1 });
    try testing.expect(shouldDrop(rrHttps(public_name, named), cfg));
}

test "svcb hints: extra_allow carve-out applies to hint addresses" {
    const allow127 = acl.parse("127.0.0.0/8") orelse return error.ParseFailed;
    const cfg = Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{allow127} };
    const loopback = comptime svc_prefix ++ svcParam(4, &.{ 127, 0, 0, 2 });
    try testing.expect(!shouldDrop(rrHttps(public_name, loopback), cfg));
}

test "scrub drops RRSIG covering HTTPS when the HTTPS RR is dropped" {
    const cfg = Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{} };
    const answers: []const dns.ResourceRecord = &.{
        rrHttps(public_name, comptime svc_prefix ++ svcParam(4, &.{ 10, 0, 0, 1 })),
        rrsigOver(.https),
    };
    const scrubbed = try scrub(testing.allocator, answers, cfg);
    defer testing.allocator.free(scrubbed);
    try testing.expectEqual(@as(usize, 0), scrubbed.len);
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
