//! bench tp <rounds> <workload> side...
//!
//! Throughput. A side is label=<hark binary>, label=<directory of layouts>
//! (layouts.sh) or a peer (unbound pdns kresd bind) at N threads. Every run
//! is a fresh resolver on freshly drawn cores under LEN (10) s of load,
//! closed loop with N times the queries in flight:
//!   hit 64 flows, few 4 flows, miss, mix half hits, lat 70% of the ceiling open loop
//! Busy is /proc/stat's and true only saturated: below it ticks alias with a
//! paced sender, so read cost from PERF=1's counters.
//!
//! The report gives each side, then each against the first. One layout a
//! side: the per-round ratio, its median with a bootstrap 95% CI, and a
//! sign test, for qps and for each counter per query. Several: the
//! difference of per-layout means, bootstrapped over layouts, real only if
//! the CI excludes 0 and |Δ| > 1%, the reach of a relink.
const std = @import("std");
const Allocator = std.mem.Allocator;
const os = @import("os.zig");
const load = @import("load.zig");
const stats = @import("stats.zig");
const Rig = @import("rig.zig");
const Ledger = @import("ledger.zig");

const gpa = std.heap.smp_allocator;

const Workload = enum { hit, few, miss, mix, lat };

const Subject = struct { label: []const u8, path: []const u8, identity: []const u8 };

fn identity(arena: Allocator, path: []const u8) ![]const u8 {
    const version: []const []const u8 = switch (std.meta.stringToEnum(Rig.Peer, path) orelse {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(try os.slurp(gpa, path), &digest, .{});
        const said = std.mem.trim(u8, try os.capture(arena, &.{ path, "version" }), " \n");
        return arena.print("{s} sha256 {x}", .{ said, digest[0..8] });
    }) {
        .unbound => &.{ "unbound", "-V" },
        .pdns => &.{ "pdns_recursor", "--version" },
        .kresd => &.{ "kresd", "--version" },
        .bind => &.{ "named", "-v" },
    };
    const said = try os.capture(arena, version);
    return std.mem.trim(u8, said[0 .. std.mem.findScalar(u8, said, '\n') orelse said.len], " ");
}

fn subjects(arena: Allocator, sides: []const []const u8) ![]Subject {
    var all: std.ArrayList(Subject) = .empty;
    for (sides) |side| {
        const eq = std.mem.findScalar(u8, side, '=');
        const label = side[0 .. eq orelse side.len];
        const path = side[if (eq) |e| e + 1 else 0..];
        if (eq == null and std.meta.stringToEnum(Rig.Peer, side) == null) return error.Usage;
        const found = if (eq == null) "" else try os.capture(arena, &.{ "find", path, "-maxdepth", "1", "-type", "f", "-executable" });
        var files: std.ArrayList([]const u8) = .empty;
        var lines = std.mem.tokenizeScalar(u8, found, '\n');
        while (lines.next()) |f| try files.append(arena, f);
        std.mem.sort([]const u8, files.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);
        if (files.items.len == 0) try files.append(arena, path);
        for (files.items) |f| try all.append(arena, .{ .label = label, .path = f, .identity = try identity(arena, f) });
    }
    return all.items;
}

fn counts(arena: Allocator, text: []const u8) !Ledger.Counts {
    var c: Ledger.Counts = .{};
    var pairs = std.mem.tokenizeScalar(u8, text, ' ');
    while (pairs.next()) |pair| {
        const eq = std.mem.findScalar(u8, pair, '=') orelse continue;
        try c.map.put(arena, try arena.dupe(u8, pair[0..eq]), std.fmt.parseFloat(f64, pair[eq + 1 ..]) catch continue);
    }
    return c;
}

fn one(rig: *Rig, s: Subject, wl: Workload) !Ledger.Run {
    try rig.place(rig.threads);
    try rig.start(s.path);
    defer rig.stop();
    const secs = os.knob(u32, "LEN", 10);
    var o: load.Opts = .{
        .port = Rig.port,
        .source = .hit,
        .secs = secs,
        .sockets = 64,
        .threads = @intCast(rig.cpu_load.len),
        .inflight = 400 * rig.threads,
        .cpus = rig.cpu_load,
    };
    switch (wl) {
        .hit, .lat => rig.warm(),
        .few => {
            rig.warm();
            o.sockets = 4;
            o.threads = @min(o.threads, 4);
        },
        .miss => o.source = .{ .miss = 42 },
        .mix => {
            rig.warm();
            o.source = .{ .mix = 42 };
        },
    }
    if (wl == .miss or wl == .mix) o.inflight = 1000 * rig.threads;
    if (wl == .lat) {
        o.secs = 5;
        o.qps = @intFromFloat((try load.run(gpa, o)).qps * 0.7);
        o.secs = secs;
    }
    try rig.perfOn();
    const before = try rig.snap();
    const r = try load.run(gpa, o);
    const after = try rig.snap();
    const counted = try rig.perfOff();
    return .{
        .experiment = "tp",
        .workload = @tagName(wl),
        .side = s.label,
        .binary = std.Io.Dir.path.basename(s.path),
        .identity = s.identity,
        .threads = rig.threads,
        .secs = secs,
        .cores = try Rig.cpuList(rig.arena, rig.cpu_res),
        .sent = r.sent,
        .completed = r.completed,
        .lost = r.lost,
        .qps = r.qps,
        .busy = Rig.busy(before, after),
        .latency = if (wl == .lat) .{ r.p50_ns, r.p99_ns, r.p999_ns } else null,
        .counters = try counts(rig.arena, counted),
    };
}

fn us(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1e3;
}

fn show(run: Ledger.Run) void {
    std.debug.print("{d} {s} {s} {d:.1} {d} {d} {d:.1} {d:.1} {d:.1} {d:.1} cpu={s}", .{ run.round, run.side, run.binary, run.qps, run.completed, run.lost, run.busy[0], run.busy[1], run.busy[2], run.busy[3], run.cores });
    if (run.latency) |l| std.debug.print(" p50={d:.1} p99={d:.1} p999={d:.1}", .{ us(l[0]), us(l[1]), us(l[2]) });
    for (run.counters.map.keys(), run.counters.map.values()) |k, v| std.debug.print(" {s}={d:.0}", .{ k, v });
    std.debug.print("\n", .{});
}

pub fn main(arena: Allocator, config: []const u8, ledger: *const Ledger, args: []const []const u8) !void {
    if (args.len < 3) return error.Usage;
    const rounds = std.fmt.parseInt(u32, args[0], 10) catch return error.Usage;
    const wl = std.meta.stringToEnum(Workload, args[1]) orelse return error.Usage;
    const all = try subjects(arena, args[2..]);
    var rig: Rig = try .enter(arena, config);
    try rig.up();
    defer rig.down();
    const order = try arena.dupe(Subject, all);
    for (1..rounds + 1) |round| {
        if (order.len > 2) rig.random.random().shuffle(Subject, order);
        if (order.len == 2 and round > 1) std.mem.swap(Subject, &order[0], &order[1]);
        for (order) |s| {
            var run = try one(&rig, s, wl);
            run.round = @intCast(round);
            show(run);
            try ledger.append(run);
        }
    }
    try report(arena, try ledger.read("tp", ledger.session), &.{});
}

const Report = struct {
    arena: Allocator,
    runs: []const Ledger.Run,
    boot: stats.Boot = .{ .gpa = gpa },
    width: usize = 0,

    const Measure = union(enum) { qps, counter: []const u8 };

    fn of(run: Ledger.Run, m: Measure) ?f64 {
        return switch (m) {
            .qps => run.qps,
            .counter => |k| if (run.completed == 0) null else (run.counters.map.get(k) orelse return null) / @as(f64, @floatFromInt(run.completed)),
        };
    }

    fn name(m: Measure) []const u8 {
        return switch (m) {
            .qps => "qps",
            .counter => |k| k,
        };
    }

    fn values(r: *Report, s: []const u8, m: Measure) ![]f64 {
        var v: std.ArrayList(f64) = .empty;
        for (r.runs) |run| if (std.mem.eql(u8, run.side, s)) try v.append(r.arena, of(run, m) orelse continue);
        return v.items;
    }

    fn measures(r: *Report, s: []const u8) ![]Measure {
        var all: std.ArrayList(Measure) = .empty;
        try all.append(r.arena, .qps);
        for (r.runs) |run| if (std.mem.eql(u8, run.side, s)) {
            for (run.counters.map.keys()) |k| if (run.counters.map.get(k).? != 0) try all.append(r.arena, .{ .counter = k });
            break;
        };
        return all.items;
    }

    fn label(r: *Report, s: []const u8) ![]const u8 {
        const out = try r.arena.alloc(u8, @max(r.width, s.len));
        @memset(out, ' ');
        @memcpy(out[out.len - s.len ..], s);
        return out;
    }

    fn side(r: *Report, s: []const u8) !void {
        const q = try r.values(s, .qps);
        if (q.len == 0) return;
        const mid = try stats.median(gpa, q);
        var lost: u64 = 0;
        var busy_min: f64 = 100;
        var unsaturated: usize = 0;
        var lat: [3]std.ArrayList(f64) = @splat(.empty);
        for (r.runs) |run| if (std.mem.eql(u8, run.side, s)) {
            lost += run.lost;
            busy_min = @min(busy_min, run.busy[0]);
            if (run.busy[0] < 97) unsaturated += 1;
            if (run.latency) |l| for (&lat, l) |*list, ns| try list.append(r.arena, us(ns));
        };
        std.debug.print("  {s} median {d: >9.0} qps  cv {d:.2}%  range {d:.0}-{d:.0}  {d:.3} µs/query  busy min {d:.1}%  lost {d}", .{
            try r.label(s),      mid,                 stats.cv(q),
            std.mem.min(f64, q), std.mem.max(f64, q), 1e6 / mid,
            busy_min,            lost,
        });
        if (lat[0].items.len == q.len) {
            std.debug.print("  p50 {d:.1} p99 {d:.1} p99.9 {d:.1} µs", .{ try stats.median(gpa, lat[0].items), try stats.median(gpa, lat[1].items), try stats.median(gpa, lat[2].items) });
        } else if (unsaturated > 0) std.debug.print("  UNSATURATED {d}/{d} runs <97% busy", .{ unsaturated, q.len });
        std.debug.print("\n", .{});
        const ms = try r.measures(s);
        if (ms.len == 1) return;
        std.debug.print("  {s} per query:", .{try r.label("")});
        for (ms[1..]) |m| {
            const v = try r.values(s, m);
            std.debug.print("  {s} {d:.0} cv {d:.2}%", .{ name(m), try stats.median(gpa, v), stats.cv(v) });
        }
        std.debug.print("\n", .{});
    }

    fn layouts(r: *Report, s: []const u8) ![]f64 {
        var by: std.array_hash_map.String(std.ArrayList(f64)) = .empty;
        for (r.runs) |run| if (std.mem.eql(u8, run.side, s)) {
            const at = try by.getOrPutValue(r.arena, run.binary, .empty);
            try at.value_ptr.append(r.arena, run.qps);
        };
        const means = try r.arena.alloc(f64, by.count());
        for (means, by.values()) |*m, v| m.* = stats.mean(v.items);
        std.mem.sort(f64, means, {}, std.sort.asc(f64));
        return means;
    }

    fn overLayouts(r: *Report, a: []const u8, b: []const u8, la: []const f64, lb: []const f64) !void {
        for ([_][]const u8{ a, b }, [_][]const f64{ la, lb }) |s, means| {
            std.debug.print("  {s} {d} layouts, means", .{ try r.label(s), means.len });
            for (means) |m| std.debug.print(" {d:.0}", .{m});
            std.debug.print("  cv {d:.2}%\n", .{stats.cv(means)});
        }
        const d = stats.mean(lb) / stats.mean(la);
        const ci = try r.boot.ofMeanRatio(lb, la);
        const real = (ci[0] > 1 or ci[1] < 1) and @abs(d - 1) > 0.01;
        std.debug.print("  layouts {s}/{s} {d:.2}%  95% CI [{d:.2}%, {d:.2}%]  {s}\n", .{ b, a, pct(d), pct(ci[0]), pct(ci[1]), if (real) "REAL" else "within layout noise" });
    }

    fn in(r: *const Report, round: u32, s: []const u8) ?Ledger.Run {
        var found: ?Ledger.Run = null;
        for (r.runs) |run| if (run.round == round and std.mem.eql(u8, run.side, s)) {
            found = run;
        };
        return found;
    }

    fn paired(r: *Report, a: []const u8, b: []const u8) !void {
        var last: u32 = 0;
        for (r.runs) |run| last = @max(last, run.round);
        for (try r.measures(a)) |m| {
            var ratio: std.ArrayList(f64) = .empty;
            for (1..last + 1) |round| {
                const x = of(r.in(@intCast(round), a) orelse continue, m) orelse continue;
                const y = of(r.in(@intCast(round), b) orelse continue, m) orelse continue;
                try ratio.append(r.arena, y / x);
            }
            if (ratio.items.len == 0) continue;
            var wins: usize = 0;
            for (ratio.items) |x| wins += @intFromBool(x > 1);
            const ci = try r.boot.ofMedian(ratio.items);
            std.debug.print("  paired {s}/{s} {s} median {d:.2}%  95% CI [{d:.2}%, {d:.2}%]  {s} higher {d}/{d}, sign p={d:.3}\n", .{
                b,               a,                                     name(m), pct(try stats.median(gpa, ratio.items)),
                pct(ci[0]),      pct(ci[1]),                            b,       wins,
                ratio.items.len, stats.signTest(ratio.items.len, wins),
            });
        }
    }

    fn pct(x: f64) f64 {
        return 100 * (x - 1);
    }
};

pub fn report(arena: Allocator, runs: []const Ledger.Run, sides: []const []const u8) !void {
    if (runs.len == 0) return error.NoRuns;
    var names: std.ArrayList([]const u8) = .empty;
    try names.appendSlice(arena, sides);
    if (sides.len == 0) for (runs) |run| {
        for (names.items) |n| {
            if (std.mem.eql(u8, n, run.side)) break;
        } else try names.append(arena, run.side);
    };
    var r: Report = .{ .arena = arena, .runs = runs };
    for (names.items) |n| r.width = @max(r.width, n.len);
    std.debug.print("tp {s} {s}, {s}\n", .{ runs[0].workload, runs[0].session, runs[0].host });
    for (names.items) |n| try r.side(n);
    const a = names.items[0];
    for (names.items[1..]) |b| {
        const la = try r.layouts(a);
        const lb = try r.layouts(b);
        if (@max(la.len, lb.len) > 1) try r.overLayouts(a, b, la, lb) else try r.paired(a, b);
    }
}
