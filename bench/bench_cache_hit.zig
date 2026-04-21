//! F-05: cache-hit allocation cost
//!
//! Measures per-lookup wall time and per-lookup bytes allocated into the
//! caller arena. Pre-populated cache of A records with 3-label names.

const std = @import("std");
const hark = @import("hark");
const dns = hark.dns;
const monotonic = hark.monotonic;
const RRsetCache = hark.cache.RRsetCache;
const TallyAllocator = @import("tally_alloc.zig").TallyAllocator;
const BenchResult = @import("main.zig").BenchResult;

const n_entries: u32 = 2000;
const bench_iters: usize = 20_000;
const warmup: usize = 500;

fn makeAResponse(alloc: std.mem.Allocator, idx: u32) !dns.Message {
    const host = try std.fmt.allocPrint(alloc, "host{d}", .{idx});
    const labels = try alloc.alloc([]const u8, 3);
    labels[0] = host;
    labels[1] = try alloc.dupe(u8, "example");
    labels[2] = try alloc.dupe(u8, "com");

    const recs = try alloc.alloc(dns.ResourceRecord, 1);
    recs[0] = .{
        .name = dns.Name{ .labels = labels },
        .rtype = .a,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .a = .{ 10, 0, @intCast((idx >> 8) & 0xff), @intCast(idx & 0xff) } },
    };

    return .{
        .header = .{
            .id = 0,
            .qr = true,
            .opcode = .query,
            .aa = true,
            .tc = false,
            .rd = false,
            .ra = false,
            .z = 0,
            .ad = false,
            .cd = false,
            .rcode = .no_error,
            .qd_count = 0,
            .an_count = 1,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = recs,
    };
}

pub fn run(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    const backing = std.heap.page_allocator;

    var cache = RRsetCache.init(.{
        .backing = backing,
        .max_bytes = 64 * 1024 * 1024,
        .max_entries = n_entries * 2,
        .io = io,
        .thread_safe = true,
    });
    defer cache.deinit();

    var setup_arena = std.heap.ArenaAllocator.init(backing);
    defer setup_arena.deinit();
    const setup_alloc = setup_arena.allocator();

    const lookup_names = try allocator.alloc([]const u8, n_entries);
    defer allocator.free(lookup_names);

    const root_zone = dns.Name{ .labels = &.{} };
    for (0..n_entries) |i| {
        const msg = try makeAResponse(setup_alloc, @intCast(i));
        cache.storeResponse(msg, root_zone);
        lookup_names[i] = try std.fmt.allocPrint(allocator, "host{d}.example.com", .{i});
    }
    defer for (lookup_names) |n| allocator.free(n);

    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    var tally = TallyAllocator.init(arena.allocator());
    const lookup_alloc = tally.allocator();

    // Warmup
    for (0..warmup) |i| {
        _ = arena.reset(.retain_capacity);
        const name = lookup_names[i % n_entries];
        const r = cache.lookup(lookup_alloc, name, .a, .in) orelse return error.SetupMissedLookup;
        std.mem.doNotOptimizeAway(r);
    }
    tally.reset();

    const samples = try allocator.alloc(i64, bench_iters);
    for (0..bench_iters) |i| {
        _ = arena.reset(.retain_capacity);
        const name = lookup_names[i % n_entries];
        const t0 = monotonic.nowNs();
        const r = cache.lookup(lookup_alloc, name, .a, .in) orelse return error.MissedLookup;
        const t1 = monotonic.nowNs();
        samples[i] = @intCast(t1 - t0);
        std.mem.doNotOptimizeAway(r);
    }

    return .{
        .samples_ns = samples,
        .alloc_bytes = tally.bytes / bench_iters,
        .alloc_count = tally.calls / bench_iters,
        .label = "A-record lookup, 3-label name (per-hit avg)",
    };
}
