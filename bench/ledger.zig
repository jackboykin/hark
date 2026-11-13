//! The ledger: every run the bench makes, a JSON line each in
//! bench/out/ledger.jsonl, saying what ran, where, and what was measured.
//! Reports read nothing else.
const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const os = @import("os.zig");

arena: Allocator,
file: []const u8,
session: []const u8,
bench: []const u8,
host: []const u8,

const Ledger = @This();

pub const Counts = std.json.ArrayHashMap(f64);

pub const Run = struct {
    session: []const u8 = "",
    bench: []const u8 = "",
    host: []const u8 = "",
    experiment: []const u8,
    workload: []const u8,
    round: u32 = 0,
    side: []const u8,
    binary: []const u8 = "",
    identity: []const u8 = "",
    threads: u32 = 1,
    secs: u32 = 0,
    cores: []const u8 = "",
    sent: u64 = 0,
    completed: u64 = 0,
    lost: u64 = 0,
    qps: f64 = 0,
    /// Busy, user, system and softirq, percent of the resolver's cores.
    busy: [4]f64 = @splat(0),
    /// p50, p99 and p99.9 in ns, from open-loop runs.
    latency: ?[3]u64 = null,
    counters: Counts = .{},
    profile: ?Profile = null,
    syscalls: ?Counts = null,
    failed: ?Counts = null,
    overload: ?Overload = null,
};

const Overload = struct {
    level: f64,
    ceiling: f64,
    probe_sent: u64,
    probe_completed: u64,
    rxq_max: u64,
    kernel_drops: u64,
    unanswered: u64,
};

pub const Profile = struct {
    seconds: f64,
    parts: Counts = .{},
    top: std.json.ArrayHashMap(Counts) = .{},
    cycles: Counts = .{},
    instructions: Counts = .{},
};

fn clock(buf: []u8) []const u8 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    const secs: std.time.epoch.EpochSeconds = .{ .secs = @intCast(ts.sec) };
    const day = secs.getEpochDay().calculateYearDay();
    const month = day.calculateMonthDay();
    const time = secs.getDaySeconds();
    return std.mem.print(buf, "{d}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        day.year,               month.month.numeric(),     @as(u32, month.day_index) + 1,
        time.getHoursIntoDay(), time.getMinutesIntoHour(), time.getSecondsIntoMinute(),
    }) catch unreachable;
}

fn firstLine(text: []const u8) []const u8 {
    return std.mem.trim(u8, text[0 .. std.mem.findScalar(u8, text, '\n') orelse text.len], " \t");
}

pub fn open(arena: Allocator, dir: []const u8) !Ledger {
    var buf: [32]u8 = undefined;
    try os.run(arena, &.{ "mkdir", "-p", try arena.print("{s}/out", .{dir}) });
    var uts: linux.utsname = undefined;
    _ = linux.uname(&uts);
    const cpuinfo = try os.slurp(arena, "/proc/cpuinfo");
    const model = if (std.mem.find(u8, cpuinfo, "model name")) |at| firstLine(cpuinfo[std.mem.findScalarPos(u8, cpuinfo, at, ':').? + 1 ..]) else "?";
    var power: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "scaling_driver", "scaling_governor", "energy_performance_preference" }) |f| {
        const v = os.slurp(arena, try arena.print("/sys/devices/system/cpu/cpu0/cpufreq/{s}", .{f})) catch continue;
        try power.print(arena, "{s}{s}", .{ if (power.items.len == 0) "" else "/", firstLine(v) });
    }
    return .{
        .arena = arena,
        .file = try arena.print("{s}/out/ledger.jsonl", .{dir}),
        .session = try arena.dupe(u8, clock(&buf)),
        .bench = try arena.dupe(u8, firstLine(try os.capture(arena, &.{ "git", "-C", dir, "describe", "--always", "--dirty" }))),
        .host = try arena.print("{s}, {s}, kernel {s}", .{ model, power.items, std.mem.sliceTo(&uts.release, 0) }),
    };
}

pub fn append(l: *const Ledger, run: Run) !void {
    var stamped = run;
    stamped.session = l.session;
    stamped.bench = l.bench;
    stamped.host = l.host;
    const line = try std.json.Stringify.valueAlloc(l.arena, stamped, .{ .emit_null_optional_fields = false });
    const fd = try os.writer(l.file, true);
    defer _ = linux.close(fd);
    os.put(fd, try l.arena.print("{s}\n", .{line}));
}

pub fn read(l: *const Ledger, experiment: []const u8, session: ?[]const u8) ![]Run {
    var runs: std.ArrayList(Run) = .empty;
    var lines = std.mem.tokenizeScalar(u8, os.slurp(l.arena, l.file) catch "", '\n');
    while (lines.next()) |line| {
        const run = try std.json.parseFromSliceLeaky(Run, l.arena, line, .{ .ignore_unknown_fields = true });
        if (!std.mem.eql(u8, run.experiment, experiment)) continue;
        if (session) |s| {
            if (!std.mem.eql(u8, run.session, s)) continue;
        } else if (runs.items.len > 0 and !std.mem.eql(u8, runs.items[0].session, run.session)) runs.clearRetainingCapacity();
        try runs.append(l.arena, run);
    }
    return runs.items;
}
