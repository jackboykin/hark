//! bench overload <hark binary>
//!
//! Open-loop miss load at LEVELS (1 2 4 8) times the miss ceiling over 16
//! flows, and an open-loop cached-name probe (PROBE_QPS, 2000) beside it, on
//! a fresh hark per run for LEN (8) s, RUNS (3) times a level. The ceiling
//! is measured closed loop (4 flows, 1000 in flight) unless CEILING is given.
//!
//! The report is one row per run, pass or fail per criterion:
//!   loss  probe loses nothing up to 4x the ceiling
//!   p99   probe p99 <= P99_MS (7: 5 ms plus 2 ms slack) at every level
//!   good  miss goodput >= 0.95x the ceiling at every level
//!   acct  hark's unanswered (dropped + shed + late + reaped) plus kernel drops
//!         on the listener and the generators equals offered - answered within 0.1%
//!   unsat the core was under 97% busy: at 1x and above the load did not reach
//!         hark, so the run proves nothing
//! A ceiling measured on an unsaturated core invalidates the whole series.
const std = @import("std");
const Allocator = std.mem.Allocator;
const os = @import("os.zig");
const load = @import("load.zig");
const Rig = @import("rig.zig");
const Ledger = @import("ledger.zig");

const gpa = std.heap.smp_allocator;

fn unanswered(dump: []const u8) !u64 {
    var sum: u64 = 0;
    var lines = std.mem.tokenizeScalar(u8, dump, '\n');
    while (lines.next()) |line| {
        const at = std.mem.find(u8, line, "stats clients.unanswered.") orelse continue;
        var f = std.mem.tokenizeScalar(u8, line[at..], ' ');
        _ = f.next();
        _ = f.next();
        sum += try std.fmt.parseInt(u64, f.next() orelse continue, 10);
    }
    return sum;
}

fn ceiling(rig: *Rig, bin: []const u8) !Ledger.Run {
    try rig.start(bin);
    defer rig.stop();
    const before = try rig.snap();
    const r = try load.run(gpa, .{ .port = Rig.port, .source = .{ .miss = 42 }, .sockets = 4, .threads = 4, .inflight = 1000, .cpus = rig.cpu_load });
    return .{ .experiment = "overload", .workload = "ceiling", .side = "hark", .secs = 10, .sent = r.sent, .completed = r.completed, .lost = r.lost, .qps = r.qps, .busy = Rig.busy(before, try rig.snap()) };
}

fn offer(o: load.Opts, into: *?load.Result) void {
    into.* = load.run(gpa, o) catch null;
}

fn one(rig: *Rig, bin: []const u8, level: f64, top: f64) !Ledger.Run {
    const secs = os.knob(u32, "LEN", 8);
    try rig.start(bin);
    defer rig.stop();
    rig.warm();
    const before = try unanswered(try rig.dump());
    var sampler: Rig.Sampler = .{ .cpus = rig.cpu_aux };
    try sampler.start();
    var flood: ?load.Result = null;
    var probe: ?load.Result = null;
    const base: load.Opts = .{ .port = Rig.port, .source = .hit, .timeout_s = 1, .cpus = rig.cpu_load };
    var flooding = base;
    flooding.source = .{ .miss = 42 };
    flooding.sockets = 16;
    flooding.threads = 4;
    flooding.qps = @intFromFloat(top * level);
    flooding.secs = secs;
    const flooder = try std.Thread.spawn(.{}, offer, .{ flooding, &flood });
    os.sleep(500 * std.time.ns_per_ms);
    var probing = base;
    probing.qps = os.knob(u64, "PROBE_QPS", 2000);
    probing.secs = secs - 1;
    const prober = try std.Thread.spawn(.{}, offer, .{ probing, &probe });
    const s0 = try rig.snap();
    os.sleep(@as(u64, secs - 1) * std.time.ns_per_s);
    const busy = Rig.busy(s0, try rig.snap());
    flooder.join();
    prober.join();
    const seen = sampler.stop();
    const f = flood orelse return error.Load;
    const p = probe orelse return error.Load;
    return .{
        .experiment = "overload",
        .workload = "miss",
        .side = "hark",
        .secs = secs,
        .cores = try Rig.cpuList(rig.arena, rig.cpu_res),
        .sent = f.sent,
        .completed = f.completed,
        .lost = f.lost,
        .qps = f.qps,
        .busy = busy,
        .latency = .{ p.p50_ns, p.p99_ns, p.p999_ns },
        .overload = .{
            .level = level,
            .ceiling = top,
            .probe_sent = p.sent,
            .probe_completed = p.completed,
            .rxq_max = seen.rxq_max,
            .kernel_drops = seen.listener_drops + seen.generator_drops,
            .unanswered = try unanswered(try rig.dump()) - before,
        },
    };
}

pub fn main(arena: Allocator, config: []const u8, ledger: *const Ledger, args: []const []const u8) !void {
    if (args.len != 1) return error.Usage;
    var rig: Rig = try .enter(arena, config);
    try rig.up();
    defer rig.down();
    const top = os.knob(?f64, "CEILING", null) orelse blk: {
        const run = try ceiling(&rig, args[0]);
        try ledger.append(run);
        break :blk run.qps;
    };
    var levels = std.mem.tokenizeScalar(u8, os.knob([]const u8, "LEVELS", "1 2 4 8"), ' ');
    while (levels.next()) |text| {
        const level = std.fmt.parseFloat(f64, text) catch return error.Usage;
        for (1..os.knob(u32, "RUNS", 3) + 1) |i| {
            var run = try one(&rig, args[0], level, top);
            run.round = @intCast(i);
            try ledger.append(run);
            std.debug.print("{d}x run {d}\n", .{ level, i });
        }
    }
    try report(arena, try ledger.read("overload", ledger.session));
}

fn row(arena: Allocator, run: Ledger.Run, p99_ms: f64) !bool {
    const o = run.overload.?;
    const secs: f64 = @floatFromInt(run.secs);
    const sent: f64 = @floatFromInt(run.sent);
    const psent: f64 = @floatFromInt(o.probe_sent);
    const offered = sent + psent;
    const answered: f64 = @floatFromInt(run.completed + o.probe_completed);
    const acct = @abs(@as(f64, @floatFromInt(o.unanswered + o.kernel_drops)) - (offered - answered)) / offered;
    const p50 = @as(f64, @floatFromInt(run.latency.?[0])) / 1e6;
    const p99 = @as(f64, @floatFromInt(run.latency.?[1])) / 1e6;
    var bad: std.ArrayList(u8) = .empty;
    for ([_]bool{ o.level > 4 or o.probe_completed == o.probe_sent, p99 <= p99_ms, run.qps >= 0.95 * o.ceiling, acct <= 0.001, run.busy[0] >= 97 }, [_][]const u8{ "loss", "p99", "good", "acct", "unsat" }) |fine, what| {
        if (!fine) try bad.print(arena, "{s}{s}", .{ if (bad.items.len == 0) "" else ",", what });
    }
    std.debug.print("{d: >2}x {d: >3} {d: >7.0}k {d: >7.1}k {d: >6.3}  {d: >5.1}% {d: >6.2} {d: >6.2}  {d: >6} {d: >8} {d: >7} {d: >5.2}% {d: >5.1}  {s}{s}{s}\n", .{
        o.level,                                                           run.round,                                   run.sent / run.secs / 1000,
        run.qps / 1e3,                                                     run.qps / o.ceiling,                         100 * (psent - @as(f64, @floatFromInt(o.probe_completed))) / psent,
        p50,                                                               p99,                                         o.rxq_max / 1024,
        o.kernel_drops,                                                    o.unanswered,                                100 * acct,
        run.busy[0],                                                       if (bad.items.len == 0) "pass" else "FAIL ", bad.items,
        if (sent < 0.97 * o.ceiling * o.level * secs) "  (short)" else "",
    });
    return bad.items.len == 0;
}

pub fn report(arena: Allocator, runs: []const Ledger.Run) !void {
    if (runs.len == 0) return error.NoRuns;
    const p99_ms = os.knob(f64, "P99_MS", 7);
    var passed: usize = 0;
    var rows: usize = 0;
    for (runs) |run| {
        const o = run.overload orelse {
            if (run.busy[0] < 97) {
                std.debug.print("INVALID: the miss ceiling ({d:.0} qps) was measured at {d:.1}% core busy\n", .{ run.qps, run.busy[0] });
                return;
            }
            std.debug.print("miss ceiling {d:.0} qps (closed loop, {d:.1}% busy)\n", .{ run.qps, run.busy[0] });
            continue;
        };
        if (rows == 0) std.debug.print("{d} s per run at multiples of {d:.0} qps\nlvl run  offered  goodput g/ceil   probe  p50ms  p99ms  rxq KB  k.drops  unsent   acct  busy  verdict\n", .{ run.secs, o.ceiling });
        rows += 1;
        passed += @intFromBool(try row(arena, run, p99_ms));
    }
    std.debug.print("{s}: {d}/{d} runs pass\n", .{ if (passed == rows) "PASS" else "FAIL", passed, rows });
}
