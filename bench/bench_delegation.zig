//! Closest-cached-delegation walk: per-call wall time and bytes allocated
//! into the caller arena. A 4-label name ("www.sub.zoneN.com") against a
//! cache pre-populated with NS + glue for "com" and "zoneN.com" — so the
//! walk hits at two levels, misses at "sub.zoneN.com", and short-circuits
//! before probing the full name.

const std = @import("std");
const hark = @import("hark");
const dns = hark.dns;
const monotonic = hark.monotonic;
const RRsetCache = hark.cache.RRsetCache;
const RecursiveResolver = hark.recursive.RecursiveResolver;
const BlockingUdpTransport = hark.blocking_transport.BlockingUdpTransport;
const TallyAllocator = @import("tally_alloc.zig").TallyAllocator;
const BenchResult = @import("main.zig").BenchResult;
const bench_common = @import("bench_common.zig");

const n_zones: u32 = 500;
const bench_iters: usize = 10_000;
const warmup: usize = 500;

fn storeRecord(cache: *RRsetCache, alloc: std.mem.Allocator, rr: dns.ResourceRecord, authority_zone: dns.Name) !void {
    const msg = try bench_common.singleAnswerMessage(alloc, rr);
    cache.storeResponse(msg, authority_zone);
}

pub fn run(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    const backing = std.heap.page_allocator;

    var cache = RRsetCache.init(.{
        .backing = backing,
        .max_bytes = 64 * 1024 * 1024,
        .max_entries = n_zones * 8,
        .io = io,
    });
    defer cache.deinit();

    var setup_arena = std.heap.ArenaAllocator.init(backing);
    defer setup_arena.deinit();
    const setup = setup_arena.allocator();

    const root_zone = dns.Name{ .labels = &.{} };

    // Shared TLD-level fixtures: NS "com" → "a.root-servers.net" and its A record.
    {
        const com = dns.Name{ .labels = try bench_common.dupeLabels(setup, &.{"com"}) };
        const rs = dns.Name{ .labels = try bench_common.dupeLabels(setup, &.{ "a", "root-servers", "net" }) };
        try storeRecord(&cache, setup, .{ .name = com, .rtype = .ns, .rclass = .in, .ttl = 3600, .rdata = .{ .ns = rs } }, root_zone);
        try storeRecord(&cache, setup, .{ .name = rs, .rtype = .a, .rclass = .in, .ttl = 3600, .rdata = .{ .a = .{ 198, 41, 0, 4 } } }, root_zone);
    }

    // Per-zone fixtures: NS "zoneN.com" → "nsN.com" and its A record.
    const query_names = try allocator.alloc([]const u8, n_zones);
    errdefer allocator.free(query_names);
    var filled: usize = 0;
    errdefer for (query_names[0..filled]) |n| allocator.free(n);
    for (0..n_zones) |i| {
        const idx: u32 = @intCast(i);
        const zone_first = try std.fmt.allocPrint(setup, "zone{d}", .{idx});
        const ns_first = try std.fmt.allocPrint(setup, "ns{d}", .{idx});
        const zone = dns.Name{ .labels = try bench_common.dupeLabels(setup, &.{ zone_first, "com" }) };
        const ns = dns.Name{ .labels = try bench_common.dupeLabels(setup, &.{ ns_first, "com" }) };
        const ip: [4]u8 = .{ 10, 0, @intCast((idx >> 8) & 0xff), @intCast(idx & 0xff) };

        try storeRecord(&cache, setup, .{ .name = zone, .rtype = .ns, .rclass = .in, .ttl = 3600, .rdata = .{ .ns = ns } }, root_zone);
        try storeRecord(&cache, setup, .{ .name = ns, .rtype = .a, .rclass = .in, .ttl = 3600, .rdata = .{ .a = ip } }, root_zone);

        query_names[i] = try std.fmt.allocPrint(allocator, "www.sub.zone{d}.com", .{i});
        filled = i + 1;
    }
    defer {
        for (query_names) |n| allocator.free(n);
        allocator.free(query_names);
    }

    var transport = BlockingUdpTransport.init(.{}, io);
    var resolver = RecursiveResolver{
        .transports = .{ .do53 = .{ .blocking = .{ .udp = &transport, .tcp = null } } },
        .io = io,
        .cache = &cache,
    };

    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    var tally = TallyAllocator.init(arena.allocator());
    const lookup_alloc = tally.allocator();

    for (0..warmup) |i| {
        _ = arena.reset(.retain_capacity);
        const name = query_names[i % n_zones];
        const r = try resolver.findClosestCachedDelegation(lookup_alloc, name);
        if (r == null) return error.SetupMissedDelegation;
        std.mem.doNotOptimizeAway(r);
    }
    tally.reset();

    const samples = try allocator.alloc(i64, bench_iters);
    for (0..bench_iters) |i| {
        _ = arena.reset(.retain_capacity);
        const name = query_names[i % n_zones];
        const t0 = monotonic.nowNs();
        const r = try resolver.findClosestCachedDelegation(lookup_alloc, name);
        const t1 = monotonic.nowNs();
        samples[i] = @intCast(t1 - t0);
        if (r == null) return error.UnexpectedMissedDelegation;
        std.mem.doNotOptimizeAway(r);
    }

    return .{
        .samples_ns = samples,
        .alloc_bytes = tally.bytes / bench_iters,
        .alloc_count = tally.calls / bench_iters,
        .label = "findClosestCachedDelegation, 4-label name, 2 cached NS levels (per-call avg, caller arena only)",
    };
}
