//! F-01: skip dedup on cache hit
//!
//! Two variants against a pre-populated cache:
//!  - with_dedup: acquireOrWait → lookup → releaseLeader  (current hot path)
//!  - without:    lookup                                  (proposed)

const std = @import("std");
const hark = @import("hark");
const dns = hark.dns;
const monotonic = hark.monotonic;
const RRsetCache = hark.cache.RRsetCache;
const InFlightTable = hark.dedup.InFlightTable;
const BenchResult = @import("main.zig").BenchResult;

const n_entries: u32 = 1000;
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

const Ctx = struct {
    cache: *RRsetCache,
    dedup: *InFlightTable,
    names: []const []const u8,
    arena: *std.heap.ArenaAllocator,
};

fn populateCache(allocator: std.mem.Allocator, io: std.Io) !struct {
    cache: RRsetCache,
    dedup: InFlightTable,
    names: [][]const u8,
    setup_arena: *std.heap.ArenaAllocator,
} {
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

    const names = try allocator.alloc([]const u8, n_entries);
    errdefer allocator.free(names);

    const root_zone = dns.Name{ .labels = &.{} };
    for (0..n_entries) |i| {
        const msg = try makeAResponse(setup_arena.allocator(), @intCast(i));
        cache.storeResponse(msg, root_zone);
        names[i] = try std.fmt.allocPrint(allocator, "host{d}.example.com", .{i});
    }

    const dedup = InFlightTable.init(backing, io);

    return .{ .cache = cache, .dedup = dedup, .names = names, .setup_arena = setup_arena };
}

pub fn runWithDedup(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    var setup = try populateCache(allocator, io);
    defer {
        setup.cache.deinit();
        setup.dedup.deinit();
        for (setup.names) |n| allocator.free(n);
        allocator.free(setup.names);
        setup.setup_arena.deinit();
        allocator.destroy(setup.setup_arena);
    }

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
    defer {
        setup.cache.deinit();
        setup.dedup.deinit();
        for (setup.names) |n| allocator.free(n);
        allocator.free(setup.names);
        setup.setup_arena.deinit();
        allocator.destroy(setup.setup_arena);
    }

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

/// Simulates F-01 as implemented in server.resolveWithDedupUsing: probe
/// cache existence first; on hit, skip dedup. On this 100%-hit workload
/// this exercises the fast path exclusively.
pub fn runF01(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    var setup = try populateCache(allocator, io);
    defer {
        setup.cache.deinit();
        setup.dedup.deinit();
        for (setup.names) |n| allocator.free(n);
        allocator.free(setup.names);
        setup.setup_arena.deinit();
        allocator.destroy(setup.setup_arena);
    }

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

    return .{ .samples_ns = samples, .label = "lookupExists + lookup (F-01 fast path on hit)" };
}
