//! Dedup overhead on cache hits. Two variants against a pre-populated cache:
//!  - with_dedup:     acquireOrWait → lookup → releaseLeader
//!  - without_dedup:  lookup only
//!  - f01:            lookupExists → lookup (skip dedup if the probe hit)

const std = @import("std");
const hark = @import("hark");
const monotonic = hark.monotonic;
const RRsetCache = hark.cache.RRsetCache;
const InFlightTable = hark.dedup.InFlightTable;
const BenchResult = @import("main.zig").BenchResult;
const bench_common = @import("bench_common.zig");

const n_entries: u32 = 1000;
const bench_iters: usize = 20_000;
const warmup: usize = 500;

const CacheSetup = struct {
    allocator: std.mem.Allocator,
    cache: RRsetCache,
    dedup: InFlightTable,
    names: [][]const u8,
    setup_arena: *std.heap.ArenaAllocator,

    fn deinit(self: *CacheSetup) void {
        self.cache.deinit();
        self.dedup.deinit();
        for (self.names) |n| self.allocator.free(n);
        self.allocator.free(self.names);
        self.setup_arena.deinit();
        self.allocator.destroy(self.setup_arena);
    }
};

fn populateCache(allocator: std.mem.Allocator, io: std.Io) !CacheSetup {
    const backing = std.heap.page_allocator;
    var cache = RRsetCache.init(.{
        .backing = backing,
        .max_bytes = 64 * 1024 * 1024,
        .max_entries = n_entries * 2,
        .io = io,
        .thread_safe = true,
    });
    errdefer cache.deinit();

    const setup_arena = try allocator.create(std.heap.ArenaAllocator);
    setup_arena.* = std.heap.ArenaAllocator.init(backing);
    errdefer {
        setup_arena.deinit();
        allocator.destroy(setup_arena);
    }

    const names = try bench_common.populateHostCache(&cache, setup_arena.allocator(), allocator, n_entries);
    errdefer {
        for (names) |n| allocator.free(n);
        allocator.free(names);
    }

    const dedup = InFlightTable.init(backing, io);

    return .{ .allocator = allocator, .cache = cache, .dedup = dedup, .names = names, .setup_arena = setup_arena };
}

pub fn runWithDedup(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    var setup = try populateCache(allocator, io);
    defer setup.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    for (0..warmup) |i| {
        _ = arena.reset(.retain_capacity);
        const name = setup.names[i % n_entries];
        const r = setup.dedup.acquireOrWait(name, .a, 0);
        const lookup = setup.cache.lookup(arena.allocator(), name, .a, .in) orelse return error.MissedLookup;
        setup.dedup.releaseLeader(name, .a, 0);
        std.mem.doNotOptimizeAway(r);
        std.mem.doNotOptimizeAway(lookup);
    }

    const samples = try allocator.alloc(i64, bench_iters);
    for (0..bench_iters) |i| {
        _ = arena.reset(.retain_capacity);
        const name = setup.names[i % n_entries];
        const t0 = monotonic.nowNs();
        const r = setup.dedup.acquireOrWait(name, .a, 0);
        const lookup = setup.cache.lookup(arena.allocator(), name, .a, .in) orelse return error.MissedLookup;
        setup.dedup.releaseLeader(name, .a, 0);
        const t1 = monotonic.nowNs();
        samples[i] = @intCast(t1 - t0);
        std.mem.doNotOptimizeAway(r);
        std.mem.doNotOptimizeAway(lookup);
    }

    return .{ .samples_ns = samples, .label = "acquireOrWait + lookup + releaseLeader (current)" };
}

pub fn runWithoutDedup(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    var setup = try populateCache(allocator, io);
    defer setup.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    for (0..warmup) |i| {
        _ = arena.reset(.retain_capacity);
        const name = setup.names[i % n_entries];
        const lookup = setup.cache.lookup(arena.allocator(), name, .a, .in) orelse return error.MissedLookup;
        std.mem.doNotOptimizeAway(lookup);
    }

    const samples = try allocator.alloc(i64, bench_iters);
    for (0..bench_iters) |i| {
        _ = arena.reset(.retain_capacity);
        const name = setup.names[i % n_entries];
        const t0 = monotonic.nowNs();
        const lookup = setup.cache.lookup(arena.allocator(), name, .a, .in) orelse return error.MissedLookup;
        const t1 = monotonic.nowNs();
        samples[i] = @intCast(t1 - t0);
        std.mem.doNotOptimizeAway(lookup);
    }

    return .{ .samples_ns = samples, .label = "lookup only (proposed hot path)" };
}

/// Mirrors server.resolveWithDedupUsing: probe cache existence first; on
/// hit, skip dedup. This workload is 100% cache-hit, so every iteration
/// exercises the fast path — this measures the cost of the extra probe
/// without exercising the concurrent-miss win it's meant to buy.
pub fn runF01(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    var setup = try populateCache(allocator, io);
    defer setup.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    for (0..warmup) |i| {
        _ = arena.reset(.retain_capacity);
        const name = setup.names[i % n_entries];
        if (setup.cache.lookupExists(name, .a, .in)) {
            const lookup = setup.cache.lookup(arena.allocator(), name, .a, .in) orelse return error.MissedLookup;
            std.mem.doNotOptimizeAway(lookup);
        } else {
            const r = setup.dedup.acquireOrWait(name, .a, 0);
            const lookup = setup.cache.lookup(arena.allocator(), name, .a, .in) orelse return error.MissedLookup;
            setup.dedup.releaseLeader(name, .a, 0);
            std.mem.doNotOptimizeAway(r);
            std.mem.doNotOptimizeAway(lookup);
        }
    }

    const samples = try allocator.alloc(i64, bench_iters);
    for (0..bench_iters) |i| {
        _ = arena.reset(.retain_capacity);
        const name = setup.names[i % n_entries];
        const t0 = monotonic.nowNs();
        if (setup.cache.lookupExists(name, .a, .in)) {
            const lookup = setup.cache.lookup(arena.allocator(), name, .a, .in) orelse return error.MissedLookup;
            std.mem.doNotOptimizeAway(lookup);
        } else {
            const r = setup.dedup.acquireOrWait(name, .a, 0);
            const lookup = setup.cache.lookup(arena.allocator(), name, .a, .in) orelse return error.MissedLookup;
            setup.dedup.releaseLeader(name, .a, 0);
            std.mem.doNotOptimizeAway(r);
            std.mem.doNotOptimizeAway(lookup);
        }
        const t1 = monotonic.nowNs();
        samples[i] = @intCast(t1 - t0);
    }

    return .{ .samples_ns = samples, .label = "lookupExists + lookup (dedup-skip fast path on hit)" };
}
