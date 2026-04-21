//! F-04: bounded SIEVE eviction scan
//!
//! Worst case: cache full with all entries visited. sieveEvict scans all N
//! entries clearing flags before evicting at hand. We measure the wall time
//! of one storeResponse call in that state.
//!
//! Setup between samples: lookup every currently-in-cache key to re-mark
//! visited (sieveEvict clears flags during its scan).

const std = @import("std");
const hark = @import("hark");
const dns = hark.dns;
const monotonic = hark.monotonic;
const RRsetCache = hark.cache.RRsetCache;
const BenchResult = @import("main.zig").BenchResult;

const cache_size: u32 = 512;
const bench_iters: usize = 2000;
const warmup: usize = 100;

fn makeAResponse(alloc: std.mem.Allocator, idx: u32) !dns.Message {
    const label_num = try std.fmt.allocPrint(alloc, "k{d}", .{idx});
    const labels = try alloc.alloc([]const u8, 2);
    labels[0] = label_num;
    labels[1] = try alloc.dupe(u8, "test");

    const recs = try alloc.alloc(dns.ResourceRecord, 1);
    recs[0] = .{
        .name = dns.Name{ .labels = labels },
        .rtype = .a,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .a = .{ 1, 2, 3, @intCast(idx & 0xff) } },
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

fn markAllVisited(cache: *RRsetCache, mark_arena: *std.heap.ArenaAllocator) void {
    _ = mark_arena.reset(.retain_capacity);
    const keys = cache.map.keys();
    for (keys) |k| {
        _ = cache.lookup(mark_arena.allocator(), k.name, k.rtype, k.rclass);
    }
}

pub fn runWorstCase(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    const backing = std.heap.page_allocator;

    var cache = RRsetCache.init(.{
        .backing = backing,
        .max_bytes = 64 * 1024 * 1024,
        .max_entries = cache_size,
        .io = io,
        .thread_safe = true,
    });
    defer cache.deinit();

    const total_msgs = cache_size + bench_iters + warmup;
    var msg_arena = std.heap.ArenaAllocator.init(backing);
    defer msg_arena.deinit();
    const msg_alloc = msg_arena.allocator();

    const messages = try allocator.alloc(dns.Message, total_msgs);
    defer allocator.free(messages);
    for (0..total_msgs) |i| messages[i] = try makeAResponse(msg_alloc, @intCast(i));

    const root_zone = dns.Name{ .labels = &.{} };

    // Fill cache
    for (0..cache_size) |i| cache.storeResponse(messages[i], root_zone);

    var mark_arena = std.heap.ArenaAllocator.init(backing);
    defer mark_arena.deinit();

    // Warmup
    for (0..warmup) |i| {
        markAllVisited(&cache, &mark_arena);
        cache.storeResponse(messages[cache_size + i], root_zone);
    }

    const samples = try allocator.alloc(i64, bench_iters);
    for (0..bench_iters) |i| {
        markAllVisited(&cache, &mark_arena);
        const t0 = monotonic.nowNs();
        cache.storeResponse(messages[cache_size + warmup + i], root_zone);
        const t1 = monotonic.nowNs();
        samples[i] = @intCast(t1 - t0);
    }

    return .{ .samples_ns = samples, .label = "storeResponse, fully-visited full cache (worst-case SIEVE scan)" };
}
