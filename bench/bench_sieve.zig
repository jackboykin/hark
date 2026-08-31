//! Bounded SIEVE eviction scan, worst case: cache full with every entry
//! visited, so sieveEvict hits the scan cap before evicting at hand. We
//! measure the wall time of one storeResponse call in that state.
//!
//! Setup between samples: lookup every currently-in-cache key to re-mark
//! visited (sieveEvict clears flags during its scan).

const std = @import("std");
const hark = @import("hark");
const dns = hark.dns;
const monotonic = hark.monotonic;
const RRsetCache = hark.cache.RRsetCache;
const BenchResult = @import("main.zig").BenchResult;
const bench_common = @import("bench_common.zig");

/// ~500 entries; fill to first eviction so every measured store evicts.
const max_bytes: usize = 256 * 1024;
const fill_max: u32 = 1024;
const bench_iters: usize = 2000;
const warmup: usize = 100;
const labels_spec = [_][]const u8{ "k{d}", "test" };

fn markAllVisited(cache: *RRsetCache, mark_arena: *std.heap.ArenaAllocator) void {
    _ = mark_arena.reset(.retain_capacity);
    for (cache.shards[0..cache.shard_count]) |*shard| {
        for (shard.map.keys()) |k| {
            _ = cache.lookup(mark_arena.allocator(), k.name, k.rtype, k.rclass);
        }
    }
}

pub fn runWorstCase(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    const backing = std.heap.page_allocator;

    var cache = RRsetCache.init(.{
        .backing = backing,
        .max_bytes = max_bytes,
        .io = io,
    });
    defer cache.deinit();

    const total_msgs = fill_max + bench_iters + warmup;
    var msg_arena = std.heap.ArenaAllocator.init(backing);
    defer msg_arena.deinit();
    const msg_alloc = msg_arena.allocator();

    const messages = try allocator.alloc(dns.Message, total_msgs);
    defer allocator.free(messages);
    for (0..total_msgs) |i| {
        const idx: u32 = @intCast(i);
        messages[i] = try bench_common.makeAResponse(msg_alloc, idx, &labels_spec, .{ 1, 2, 3, @intCast(idx & 0xff) });
    }

    const root_zone = dns.Name{ .labels = &.{} };

    var next: usize = 0;
    while (next < fill_max and cache.getStats().evictions == 0) : (next += 1) {
        cache.storeResponse(messages[next], root_zone, .unchecked, std.math.maxInt(u32));
    }

    var mark_arena = std.heap.ArenaAllocator.init(backing);
    defer mark_arena.deinit();

    // Warmup
    for (0..warmup) |_| {
        markAllVisited(&cache, &mark_arena);
        cache.storeResponse(messages[next], root_zone, .unchecked, std.math.maxInt(u32));
        next += 1;
    }

    const samples = try allocator.alloc(i64, bench_iters);
    for (0..bench_iters) |i| {
        markAllVisited(&cache, &mark_arena);
        const t0 = monotonic.nowNs();
        cache.storeResponse(messages[next], root_zone, .unchecked, std.math.maxInt(u32));
        next += 1;
        const t1 = monotonic.nowNs();
        samples[i] = @intCast(t1 - t0);
    }

    return .{ .samples_ns = samples, .label = "storeResponse, fully-visited full cache (worst-case SIEVE scan)" };
}
