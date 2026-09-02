//! Cache-hit allocation cost: per-lookup wall time and bytes allocated
//! into the caller arena. Pre-populated cache of A records with 3-label
//! names.

const std = @import("std");
const hark = @import("hark");
const monotonic = hark.monotonic;
const RRsetCache = hark.cache.RRsetCache;
const TallyAllocator = @import("tally_alloc.zig").TallyAllocator;
const BenchResult = @import("main.zig").BenchResult;
const bench_common = @import("bench_common.zig");

const n_entries: u32 = 2000;
const bench_iters: usize = 20_000;
const warmup: usize = 500;

pub fn run(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    const backing = std.heap.page_allocator;

    var cache = RRsetCache.init(.{
        .backing = backing,
        .max_bytes = 64 * 1024 * 1024,
        .io = io,
    });
    defer cache.deinit();

    var setup_arena = std.heap.ArenaAllocator.init(backing);
    defer setup_arena.deinit();

    const lookup_names = try bench_common.populateHostCache(&cache, setup_arena.allocator(), allocator, n_entries);
    defer {
        for (lookup_names) |n| allocator.free(n);
        allocator.free(lookup_names);
    }

    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    var tally = TallyAllocator.init(arena.allocator());
    const lookup_alloc = tally.allocator();

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
