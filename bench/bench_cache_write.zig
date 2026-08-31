//! Cache write-amplification: per-store wall time and backing-allocator
//! call count across rtypes × records-per-RRset (N). The cache read path
//! (`cloneRRset` in src/cache.zig) makes 2 allocator calls regardless of N
//! via a packed alignedAlloc + flat owner name. The write path
//! (`storeOneRRset` + `buildCachedRecord`) dupes per record + per rdata
//! child — this bench measures that asymmetry.
//!
//! Workload: cold-cache fill of M=1000 unique RRsets per combo. The cache's
//! backing allocator is wrapped by a `TallyAllocator` so every call from the
//! cache's `CountingAllocator` lands one tick. The counter is sampled
//! before/after each store; per-store delta is averaged and reported in
//! the bench label alongside ops/sec.
//!
//! Combos:
//!   rtype ∈ {a, aaaa, cname, mx, nsec, dnskey}
//!   N     ∈ {1, 4, 8}              (records per RRset)
//!   dnskey carries N RRSIGs covering the keyset to expose the
//!   sigs-bundled allocation cost predicted at ~30-40 calls.

const std = @import("std");
const hark = @import("hark");
const monotonic = hark.monotonic;
const dns = hark.dns;
const RRsetCache = hark.cache.RRsetCache;
const BenchResult = @import("main.zig").BenchResult;
const Benchmark = @import("main.zig").Benchmark;
const TallyAllocator = @import("tally_alloc.zig").TallyAllocator;
const bench_common = @import("bench_common.zig");

const m_rrsets: u32 = 1000;
const warmup_rrsets: u32 = 32;

// ── Record builders ───────────────────────────────────────────────────

/// Build a 3-label name `hostN.example.com` into the arena.
fn buildHostName(alloc: std.mem.Allocator, idx: u32) !dns.Name {
    const labels = try alloc.alloc([]const u8, 3);
    labels[0] = try std.fmt.allocPrint(alloc, "host{d}", .{idx});
    labels[1] = try alloc.dupe(u8, "example");
    labels[2] = try alloc.dupe(u8, "com");
    return .{ .labels = labels };
}

/// A: 4-byte rdata, no children.
fn buildAGroup(alloc: std.mem.Allocator, idx: u32, n: u32) ![]dns.ResourceRecord {
    const name = try buildHostName(alloc, idx);
    const recs = try alloc.alloc(dns.ResourceRecord, n);
    var k: u32 = 0;
    while (k < n) : (k += 1) {
        recs[k] = .{
            .name = name,
            .rtype = .a,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .a = .{ 10, 0, @intCast((idx >> 8) & 0xff), @intCast((idx & 0xff) ^ k) } },
        };
    }
    return recs;
}

/// AAAA: 16-byte rdata, no children.
fn buildAAAAGroup(alloc: std.mem.Allocator, idx: u32, n: u32) ![]dns.ResourceRecord {
    const name = try buildHostName(alloc, idx);
    const recs = try alloc.alloc(dns.ResourceRecord, n);
    var k: u32 = 0;
    while (k < n) : (k += 1) {
        var v: [16]u8 = .{ 0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        v[15] = @intCast(k);
        v[13] = @intCast(idx & 0xff);
        v[12] = @intCast((idx >> 8) & 0xff);
        recs[k] = .{
            .name = name,
            .rtype = .aaaa,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .aaaa = v },
        };
    }
    return recs;
}

/// CNAME: name child (cloneName allocates labels-array + per-label dupes).
fn buildCnameGroup(alloc: std.mem.Allocator, idx: u32, n: u32) ![]dns.ResourceRecord {
    const name = try buildHostName(alloc, idx);
    const recs = try alloc.alloc(dns.ResourceRecord, n);
    var k: u32 = 0;
    while (k < n) : (k += 1) {
        const target_labels = try alloc.alloc([]const u8, 3);
        target_labels[0] = try std.fmt.allocPrint(alloc, "target{d}-{d}", .{ idx, k });
        target_labels[1] = try alloc.dupe(u8, "example");
        target_labels[2] = try alloc.dupe(u8, "com");
        recs[k] = .{
            .name = name,
            .rtype = .cname,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .cname = .{ .labels = target_labels } },
        };
    }
    return recs;
}

/// MX: preference + name child.
fn buildMxGroup(alloc: std.mem.Allocator, idx: u32, n: u32) ![]dns.ResourceRecord {
    const name = try buildHostName(alloc, idx);
    const recs = try alloc.alloc(dns.ResourceRecord, n);
    var k: u32 = 0;
    while (k < n) : (k += 1) {
        const ex_labels = try alloc.alloc([]const u8, 3);
        ex_labels[0] = try std.fmt.allocPrint(alloc, "mx{d}-{d}", .{ idx, k });
        ex_labels[1] = try alloc.dupe(u8, "example");
        ex_labels[2] = try alloc.dupe(u8, "com");
        recs[k] = .{
            .name = name,
            .rtype = .mx,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .mx = .{ .preference = 10 + @as(u16, @intCast(k)), .exchange = .{ .labels = ex_labels } } },
        };
    }
    return recs;
}

/// NSEC: next-domain name child + 32-byte type bitmap.
fn buildNsecGroup(alloc: std.mem.Allocator, idx: u32, n: u32) ![]dns.ResourceRecord {
    const name = try buildHostName(alloc, idx);
    const recs = try alloc.alloc(dns.ResourceRecord, n);
    var k: u32 = 0;
    while (k < n) : (k += 1) {
        const next_labels = try alloc.alloc([]const u8, 3);
        next_labels[0] = try std.fmt.allocPrint(alloc, "next{d}-{d}", .{ idx, k });
        next_labels[1] = try alloc.dupe(u8, "example");
        next_labels[2] = try alloc.dupe(u8, "com");
        const bitmap = try alloc.alloc(u8, 6);
        // Window 0, length 4, bits for A(1), NS(2), CNAME(5) — bytes form a
        // valid NSEC type-bitmap, sufficient for serialization.
        bitmap[0] = 0; // window
        bitmap[1] = 4; // length
        bitmap[2] = 0b01100010; // A=1 set, NS=2 set, CNAME=5 set, etc
        bitmap[3] = 0;
        bitmap[4] = 0;
        bitmap[5] = 0;
        recs[k] = .{
            .name = name,
            .rtype = .nsec,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .nsec = .{
                .next_domain_name = .{ .labels = next_labels },
                .type_bit_maps = bitmap,
            } },
        };
    }
    return recs;
}

/// DNSKEY + RRSIG: N DNSKEY records covered by N RRSIGs. Authority zone
/// is the owner name (RRSIGs travel as a sibling rrset and bundle through
/// `storeOneRRset.sigs`). Public keys are realistic 256-byte RSA-sized;
/// signatures are 256 bytes too — both are owned []const u8 in RData.
fn buildDnskeyAndSigs(alloc: std.mem.Allocator, idx: u32, n: u32) ![]dns.ResourceRecord {
    const name = try buildHostName(alloc, idx);
    const recs = try alloc.alloc(dns.ResourceRecord, 2 * n);

    // First N: DNSKEY records.
    var k: u32 = 0;
    while (k < n) : (k += 1) {
        const pub_key = try alloc.alloc(u8, 256);
        for (pub_key, 0..) |*b, j| b.* = @truncate(idx +% k +% @as(u32, @intCast(j)));
        recs[k] = .{
            .name = name,
            .rtype = .dnskey,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .dnskey = .{
                .flags = 256,
                .protocol = 3,
                .algorithm = .rsasha256,
                .public_key = pub_key,
            } },
        };
    }

    // Next N: RRSIGs covering DNSKEY.
    var s: u32 = 0;
    while (s < n) : (s += 1) {
        const signer_labels = try alloc.alloc([]const u8, 2);
        signer_labels[0] = try alloc.dupe(u8, "example");
        signer_labels[1] = try alloc.dupe(u8, "com");
        const sig_bytes = try alloc.alloc(u8, 256);
        for (sig_bytes, 0..) |*b, j| b.* = @truncate(idx ^ s ^ @as(u32, @intCast(j)));
        recs[n + s] = .{
            .name = name,
            .rtype = .rrsig,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .rrsig = .{
                .type_covered = .dnskey,
                .algorithm = .rsasha256,
                .labels = 3,
                .original_ttl = 3600,
                .sig_expiration = 4_000_000_000,
                .sig_inception = 1_700_000_000,
                .key_tag = @intCast(s),
                .signer_name = .{ .labels = signer_labels },
                .signature = sig_bytes,
            } },
        };
    }
    return recs;
}

// ── Workload kinds ────────────────────────────────────────────────────

const RtypeKind = enum { a, aaaa, cname, mx, nsec, dnskey };

fn buildGroup(alloc: std.mem.Allocator, kind: RtypeKind, idx: u32, n: u32) ![]dns.ResourceRecord {
    return switch (kind) {
        .a => buildAGroup(alloc, idx, n),
        .aaaa => buildAAAAGroup(alloc, idx, n),
        .cname => buildCnameGroup(alloc, idx, n),
        .mx => buildMxGroup(alloc, idx, n),
        .nsec => buildNsecGroup(alloc, idx, n),
        .dnskey => buildDnskeyAndSigs(alloc, idx, n),
    };
}

fn groupMessage(g: []dns.ResourceRecord) dns.Message {
    return .{
        .header = .{
            .id = 0,
            .flags = bench_common.single_answer_header.flags,
            .qd_count = 0,
            .an_count = @intCast(g.len),
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = g,
    };
}

fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    comptime kind: RtypeKind,
    comptime n: u32,
) !BenchResult {
    const backing = std.heap.page_allocator;

    var counter = TallyAllocator.init(backing);
    const counted_backing = counter.allocator();

    // Per-record allocation budget is roomy for DNSKEY (≥1KB owned bytes).
    var cache = RRsetCache.init(.{
        .backing = counted_backing,
        .max_bytes = 256 * 1024 * 1024,
        .io = io,
    });
    defer cache.deinit();

    // Pre-build all M+warmup messages into a setup arena so per-iter
    // allocation noise doesn't pollute the counter.
    var setup_arena = std.heap.ArenaAllocator.init(backing);
    defer setup_arena.deinit();
    const sa = setup_arena.allocator();

    const total = m_rrsets + warmup_rrsets;
    const groups = try sa.alloc([]dns.ResourceRecord, total);
    for (groups, 0..) |*g, i| {
        g.* = try buildGroup(sa, kind, @intCast(i), n);
    }

    const root_zone = dns.Name{ .labels = &.{} };

    // Warmup: pre-touch backing pages so the first measured store doesn't
    // pay the page-fault tax.
    for (groups[0..warmup_rrsets]) |g| {
        cache.storeResponse(groupMessage(g), root_zone, .unchecked, std.math.maxInt(u32));
    }

    counter.reset();

    const samples = try allocator.alloc(i64, m_rrsets);
    const alloc_deltas = try allocator.alloc(u64, m_rrsets);
    defer allocator.free(alloc_deltas);

    for (groups[warmup_rrsets..], 0..) |g, i| {
        const msg = groupMessage(g);
        const calls_before = counter.calls;
        const t0 = monotonic.nowNs();
        cache.storeResponse(msg, root_zone, .unchecked, std.math.maxInt(u32));
        const t1 = monotonic.nowNs();
        samples[i] = @intCast(t1 - t0);
        alloc_deltas[i] = counter.calls - calls_before;
    }

    var total_calls: u64 = 0;
    for (alloc_deltas) |d| total_calls += d;
    const calls_per_store_x10: u64 = (total_calls * 10) / m_rrsets;

    var total_ns: u64 = 0;
    for (samples) |s| total_ns += @intCast(s);
    const ops_per_sec: u64 = if (total_ns == 0) 0 else (@as(u64, m_rrsets) * std.time.ns_per_s) / total_ns;

    const kind_label = switch (kind) {
        .a => "a",
        .aaaa => "aaaa",
        .cname => "cname",
        .mx => "mx",
        .nsec => "nsec",
        .dnskey => "dnskey+rrsig",
    };

    const label = try std.fmt.allocPrint(
        allocator,
        "rtype={s} N={d} ops/s={d} calls/store={d}.{d} bytes/store={d}",
        .{
            kind_label,
            n,
            ops_per_sec,
            calls_per_store_x10 / 10,
            calls_per_store_x10 % 10,
            counter.bytes / m_rrsets,
        },
    );

    return .{
        .samples_ns = samples,
        .alloc_bytes = counter.bytes / m_rrsets,
        .alloc_count = total_calls / m_rrsets,
        .label = label,
        .label_owner = allocator,
    };
}

fn makeRun(
    comptime kind: RtypeKind,
    comptime n: u32,
) *const fn (std.mem.Allocator, std.Io) anyerror!BenchResult {
    return struct {
        fn r(alloc: std.mem.Allocator, io: std.Io) anyerror!BenchResult {
            return run(alloc, io, kind, n);
        }
    }.r;
}

const kinds = [_]RtypeKind{ .a, .aaaa, .cname, .mx, .nsec, .dnskey };
const sweep_ns = [_]u32{ 1, 4, 8 };

pub const benchmarks = blk: {
    var list: [kinds.len * sweep_ns.len]Benchmark = undefined;
    var i: usize = 0;
    for (kinds) |k| {
        const tag = switch (k) {
            .a => "a",
            .aaaa => "aaaa",
            .cname => "cname",
            .mx => "mx",
            .nsec => "nsec",
            .dnskey => "dnskey",
        };
        for (sweep_ns) |n| {
            list[i] = .{
                .name = std.fmt.comptimePrint("cache_write/{s}/N={d}", .{ tag, n }),
                .run = makeRun(k, n),
            };
            i += 1;
        }
    }
    break :blk list;
};
