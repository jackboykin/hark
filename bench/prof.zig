//! bench prof <rounds> hit|miss label=<hark binary>...
//!
//! Where a query's time goes on the resolver core, kernel included, and how
//! two builds differ there. Each run is a fresh hark under open-loop load at
//! Q qps (miss 40000, hit 150000; stay under the ceiling or the split
//! smears) with perf sampling cycles and user instructions, kernel stacks
//! included, on the resolver core for W (10) s. Sides alternate by round on
//! one core. Then strace -c counts each side's syscalls at 1000 qps.
//! Unstripped binaries (-Dstrip=false) name hark's functions, and each must
//! be named `hark`: samples are told apart by process name.
//!
//! The report divides by the queries asked in the window and takes each
//! side's median over its rounds: its parts with their top kernel symbols,
//! hark's functions, and syscalls per query. Each later side is then set
//! against the first, part by part and function by function, with half the
//! range of the first side's rounds beside each figure as its noise.
const std = @import("std");
const Allocator = std.mem.Allocator;
const os = @import("os.zig");
const load = @import("load.zig");
const stats = @import("stats.zig");
const Rig = @import("rig.zig");
const Ledger = @import("ledger.zig");

const gpa = std.heap.smp_allocator;

const Workload = enum { hit, miss };

const Side = struct { label: []const u8, path: []const u8 };

const kernel_space = 0xffff800000000000;

fn part(arena: Allocator, task: []const u8, ips: []const u64, syms: []const []const u8) ![]const u8 {
    if (!std.mem.eql(u8, task, "hark")) return arena.print("other task: {s}", .{task});
    if (ips[0] < kernel_space) return "hark";
    for (syms) |s| {
        for ([_][]const u8{ "__x64_sys_", "__se_sys_", "__do_sys_" }) |p|
            if (std.mem.startsWith(u8, s, p)) return arena.print("sys {s}", .{s[p.len..]});
        for ([_][]const u8{ "handle_softirqs", "__do_softirq", "net_rx_action" }) |p|
            if (std.mem.startsWith(u8, s, p)) return "softirq";
    }
    return "kernel, no syscall";
}

/// `sym` without what tells one instance of a generic function from another:
/// `__func_N`, `__anon_N` and a trailing `'N`.
fn plain(arena: Allocator, sym: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < sym.len) {
        const numbered = for ([_][]const u8{ "__func_", "__anon_", "'" }) |p| {
            if (!std.mem.startsWith(u8, sym[i..], p)) continue;
            var end = i + p.len;
            while (end < sym.len and std.ascii.isDigit(sym[end])) end += 1;
            if (end > i + p.len and (p.len > 1 or end == sym.len)) break end;
        } else null;
        if (numbered) |end| {
            i = end;
        } else {
            try out.append(arena, sym[i]);
            i += 1;
        }
    }
    return out.items;
}

fn add(arena: Allocator, c: *Ledger.Counts, key: []const u8, n: f64) !void {
    const at = try c.map.getOrPutValue(arena, key, 0);
    at.value_ptr.* += n;
}

/// One sample of `perf script -F comm,event,period,ip,sym`: a head line
/// "task period event:", then a frame a line, "ip sym", leaf first.
fn sample(arena: Allocator, p: *Ledger.Profile, all: *std.json.ArrayHashMap(Ledger.Counts), block: []const u8) !void {
    var lines = std.mem.tokenizeScalar(u8, block, '\n');
    var head = std.mem.tokenizeAny(u8, lines.next() orelse return, " \t");
    var words: std.ArrayList([]const u8) = .empty;
    while (head.next()) |w| try words.append(arena, w);
    if (words.items.len < 3) return;
    const task = try std.mem.join(arena, " ", words.items[0 .. words.items.len - 2]);
    const period: f64 = @floatFromInt(try std.fmt.parseInt(u64, words.items[words.items.len - 2], 10));
    const named = words.items[words.items.len - 1];
    const event = named[0 .. std.mem.findScalar(u8, named, ':') orelse named.len];
    var ips: std.ArrayList(u64) = .empty;
    var syms: std.ArrayList([]const u8) = .empty;
    while (lines.next()) |line| {
        const frame = std.mem.trim(u8, line, " \t");
        const space = std.mem.findScalar(u8, frame, ' ') orelse frame.len;
        try ips.append(arena, std.fmt.parseInt(u64, frame[0..space], 16) catch 0);
        try syms.append(arena, if (space < frame.len) std.mem.trim(u8, frame[space..], " ") else "?");
    }
    if (ips.items.len == 0) {
        try ips.append(arena, 0);
        try syms.append(arena, "?");
    }
    const where = try part(arena, task, ips.items, syms.items);
    const leaf = try plain(arena, syms.items[0]);
    const cycles = std.mem.eql(u8, event, "cycles");
    if (std.mem.eql(u8, where, "hark")) try add(arena, if (cycles) &p.cycles else &p.instructions, leaf, period);
    if (!cycles) return;
    try add(arena, &p.parts, where, period);
    const of = try all.map.getOrPutValue(arena, where, .{});
    try add(arena, of.value_ptr, leaf, period);
}

const Entry = struct { key: []const u8, value: f64 };

fn ranked(arena: Allocator, c: Ledger.Counts) ![]Entry {
    const all = try arena.alloc(Entry, c.map.count());
    for (all, c.map.keys(), c.map.values()) |*e, k, v| e.* = .{ .key = k, .value = v };
    std.mem.sort(Entry, all, {}, struct {
        fn lessThan(_: void, a: Entry, b: Entry) bool {
            return @abs(a.value) > @abs(b.value);
        }
    }.lessThan);
    return all;
}

fn fold(arena: Allocator, text: []const u8, seconds: f64) !Ledger.Profile {
    var p: Ledger.Profile = .{ .seconds = seconds };
    var all: std.json.ArrayHashMap(Ledger.Counts) = .{};
    var blocks = std.mem.tokenizeSequence(u8, text, "\n\n");
    while (blocks.next()) |block| try sample(arena, &p, &all, block);
    for (all.map.keys(), all.map.values()) |where, syms| {
        var top: Ledger.Counts = .{};
        const first = try ranked(arena, syms);
        for (first[0..@min(3, first.len)]) |e| try top.map.put(arena, e.key, e.value);
        try p.top.map.put(arena, where, top);
    }
    return p;
}

fn start(rig: *Rig, side: Side, wl: Workload) !void {
    try rig.start(side.path);
    if (wl == .hit) rig.warm();
}

fn offer(rig: *const Rig, wl: Workload, secs: u32, qps: u64, into: *?load.Result) void {
    into.* = load.run(gpa, .{
        .port = Rig.port,
        .source = if (wl == .hit) .hit else .{ .miss = 42 },
        .secs = secs,
        .sockets = 4,
        .threads = 4,
        .qps = qps,
        .cpus = rig.cpu_load,
    }) catch null;
}

fn sampled(rig: *Rig, side: Side, wl: Workload, tag: []const u8) !Ledger.Run {
    const window = os.knob(u32, "W", 10);
    const qps = os.knob(u64, "Q", if (wl == .hit) 150000 else 40000);
    try start(rig, side, wl);
    var result: ?load.Result = null;
    const loader = try std.Thread.spawn(.{}, offer, .{ rig, wl, window + 3, qps, &result });
    os.sleep(std.time.ns_per_s);
    const data = try rig.arena.print("{s}/{s}.data", .{ rig.scratch, tag });
    const cores = try Rig.cpuList(rig.arena, rig.cpu_res);
    const secs = try rig.arena.print("{d}", .{window});
    try rig.observer.outside(rig.arena, "", &.{ "perf", "record", "-q", "-o", data, "-F", "10000", "-e", "cycles", "-e", "instructions:u", "-g", "-C", cores, "--", "sleep", secs });
    loader.join();
    rig.stop();
    const r = result orelse return error.Load;
    const script = try rig.arena.print("{s}.txt", .{data});
    try rig.observer.outside(rig.arena, script, &.{ "perf", "script", "-i", data, "-F", "comm,event,period,ip,sym", "--no-inline" });
    const text = try os.slurp(gpa, script);
    defer gpa.free(text);
    return .{
        .experiment = "prof",
        .workload = @tagName(wl),
        .side = side.label,
        .secs = window,
        .cores = cores,
        .sent = r.sent,
        .completed = r.completed,
        .lost = r.lost,
        .qps = r.qps,
        .profile = try fold(rig.arena, text, @floatFromInt(window)),
    };
}

/// strace -c's table: "% time, seconds, usecs/call, calls, [errors,] syscall".
fn traced(rig: *Rig, side: Side, wl: Workload) !Ledger.Run {
    try start(rig, side, wl);
    const table = try rig.arena.print("{s}/strace", .{rig.scratch});
    const pid = try rig.arena.print("{d}", .{rig.pid()});
    const strace = try os.spawn(rig.arena, .{ .argv = &.{ "strace", "-q", "-c", "-f", "-o", table, "-p", pid } });
    os.sleep(500 * std.time.ns_per_ms);
    var result: ?load.Result = null;
    offer(rig, wl, 5, 1000, &result);
    strace.signal(.INT);
    _ = strace.wait();
    rig.stop();
    const r = result orelse return error.Load;
    var calls: Ledger.Counts = .{};
    var failed: Ledger.Counts = .{};
    var lines = std.mem.tokenizeScalar(u8, try os.slurp(rig.arena, table), '\n');
    while (lines.next()) |line| {
        var f: std.ArrayList([]const u8) = .empty;
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        while (words.next()) |w| try f.append(rig.arena, w);
        if (f.items.len < 5 or std.mem.eql(u8, f.items[f.items.len - 1], "total")) continue;
        const name = f.items[f.items.len - 1];
        try calls.map.put(rig.arena, name, std.fmt.parseFloat(f64, f.items[3]) catch continue);
        if (f.items.len == 6) try failed.map.put(rig.arena, name, try std.fmt.parseFloat(f64, f.items[4]));
    }
    return .{ .experiment = "prof", .workload = @tagName(wl), .side = side.label, .secs = 5, .sent = r.sent, .completed = r.completed, .lost = r.lost, .qps = r.qps, .syscalls = calls, .failed = failed };
}

pub fn main(arena: Allocator, config: []const u8, ledger: *const Ledger, args: []const []const u8) !void {
    if (args.len < 3) return error.Usage;
    const rounds = std.fmt.parseInt(u32, args[0], 10) catch return error.Usage;
    const wl = std.meta.stringToEnum(Workload, args[1]) orelse return error.Usage;
    const sides = try arena.alloc(Side, args.len - 2);
    for (sides, args[2..]) |*s, a| {
        const eq = std.mem.findScalar(u8, a, '=') orelse return error.Usage;
        s.* = .{ .label = a[0..eq], .path = a[eq + 1 ..] };
    }
    var rig: Rig = try .enter(arena, config);
    try rig.up();
    defer rig.down();
    for (1..rounds + 1) |round| {
        for (0..sides.len) |i| {
            const side = sides[(i + round - 1) % sides.len];
            var run = try sampled(&rig, side, wl, try arena.print("{d}-{s}", .{ round, side.label }));
            run.round = @intCast(round);
            std.debug.print("{d} {s} {d:.0} qps, {d} lost\n", .{ round, side.label, run.qps, run.lost });
            try ledger.append(run);
        }
    }
    for (sides) |side| try ledger.append(try traced(&rig, side, wl));
    try report(arena, try ledger.read("prof", ledger.session));
}

const Report = struct {
    arena: Allocator,
    runs: []const Ledger.Run,

    const Field = enum { parts, cycles, instructions };

    fn counts(run: Ledger.Run, f: Field) Ledger.Counts {
        const p = run.profile.?;
        return switch (f) {
            .parts => p.parts,
            .cycles => p.cycles,
            .instructions => p.instructions,
        };
    }

    fn each(r: *const Report, side: []const u8, f: Field, key: ?[]const u8) ![]f64 {
        var v: std.ArrayList(f64) = .empty;
        for (r.runs) |run| {
            if (run.profile == null or !std.mem.eql(u8, run.side, side)) continue;
            const c = counts(run, f);
            var n: f64 = 0;
            if (key) |k| n = c.map.get(k) orelse 0 else for (c.map.values()) |x| n += x;
            try v.append(r.arena, n / (run.qps * run.profile.?.seconds));
        }
        return v.items;
    }

    fn med(r: *const Report, side: []const u8, f: Field, key: ?[]const u8) !f64 {
        return stats.median(gpa, try r.each(side, f, key));
    }

    fn spread(r: *const Report, side: []const u8, f: Field, key: ?[]const u8) !f64 {
        const v = try r.each(side, f, key);
        return (std.mem.max(f64, v) - std.mem.min(f64, v)) / 2;
    }

    fn first(r: *const Report, side: []const u8) Ledger.Run {
        for (r.runs) |run| if (run.profile != null and std.mem.eql(u8, run.side, side)) return run;
        unreachable;
    }

    fn one(r: *const Report, side: []const u8) !void {
        var lost: u64 = 0;
        var qps: std.ArrayList(f64) = .empty;
        for (r.runs) |run| if (run.profile != null and std.mem.eql(u8, run.side, side)) {
            lost += run.lost;
            try qps.append(r.arena, run.qps);
        };
        const total = try r.med(side, .parts, null);
        std.debug.print("{s}: {d} runs at {d:.0} qps, {d} lost\n  {d: >8.0} cycles per query\n", .{ side, qps.items.len, try stats.median(gpa, qps.items), lost, total });
        const head = r.first(side);
        for (try ranked(r.arena, head.profile.?.parts)) |e| {
            const c = try r.med(side, .parts, e.key);
            if (c / total < 0.002) continue;
            std.debug.print("  {d: >8.0} {d: >5.1}%  {s: <22}", .{ c, 100 * c / total, e.key });
            const top = head.profile.?.top.map.get(e.key) orelse Ledger.Counts{};
            var sum: f64 = 0;
            for (top.map.values()) |x| sum += x;
            if (!std.mem.eql(u8, e.key, "hark")) for (try ranked(r.arena, top), 0..) |s, i|
                std.debug.print("{s} {s} {d:.0}%", .{ if (i == 0) "" else ",", s.key, 100 * s.value / sum });
            std.debug.print("\n", .{});
        }
        std.debug.print("  hark's own code: {d:.0} instructions per query; top functions, cycles and instructions per query:\n", .{try r.med(side, .instructions, null)});
        const fns = try ranked(r.arena, head.profile.?.cycles);
        for (fns[0..@min(12, fns.len)]) |e|
            std.debug.print("  {d: >8.0} {d: >8.0}  {s}\n", .{ try r.med(side, .cycles, e.key), try r.med(side, .instructions, e.key), e.key[0..@min(100, e.key.len)] });
        try r.syscalls(side);
        std.debug.print("\n", .{});
    }

    fn syscalls(r: *const Report, side: []const u8) !void {
        const run = for (r.runs) |run| {
            if (run.syscalls != null and std.mem.eql(u8, run.side, side)) break run;
        } else return;
        const done: f64 = @floatFromInt(run.completed);
        std.debug.print("  syscalls per query (strace -c over {d} queries):", .{run.completed});
        var all: f64 = 0;
        for (try ranked(r.arena, run.syscalls.?), 0..) |e, i| {
            all += e.value / done;
            if (e.value / done < 0.01) continue;
            std.debug.print("{s} {s} {d:.2}", .{ if (i == 0) "" else ",", e.key, e.value / done });
            if (run.failed.?.map.get(e.key)) |f| std.debug.print(" ({d:.2} failed)", .{f / done});
        }
        std.debug.print("; {d:.2} in all\n", .{all});
    }

    fn signed(r: *const Report, x: f64, comptime decimals: []const u8) ![]const u8 {
        return r.arena.print("{s}{d:." ++ decimals ++ "}", .{ if (x < 0) "" else "+", x });
    }

    fn against(r: *const Report, a: []const u8, b: []const u8) !void {
        std.debug.print("{s} - {s}, per query, ± half the range of {s}'s runs:\n", .{ b, a, a });
        for ([_]Field{ .parts, .instructions }, [_][]const u8{ "cycles", "hark's instructions" }) |f, what| {
            const base = try r.med(a, f, null);
            const d = try r.med(b, f, null) - base;
            std.debug.print("  {s: >8} ± {d:.0}  {s} ({s}%)\n", .{ try r.signed(d, "0"), try r.spread(a, f, null), what, try r.signed(100 * d / base, "2") });
        }
        for ([_]Field{ .parts, .instructions }, [_][]const u8{ "part, cycles", "function, instructions" }) |f, what| {
            var delta: Ledger.Counts = .{};
            for (r.runs) |run| {
                if (run.profile == null or !(std.mem.eql(u8, run.side, a) or std.mem.eql(u8, run.side, b))) continue;
                for (counts(run, f).map.keys()) |k| {
                    if (!delta.map.contains(k)) try delta.map.put(r.arena, k, try r.med(b, f, k) - try r.med(a, f, k));
                }
            }
            std.debug.print("  by {s}:\n", .{what});
            const top = try ranked(r.arena, delta);
            for (top[0..@min(10, top.len)]) |e|
                std.debug.print("  {s: >8} ± {d:.0}  {s}\n", .{ try r.signed(e.value, "0"), try r.spread(a, f, e.key), e.key[0..@min(100, e.key.len)] });
        }
        std.debug.print("\n", .{});
    }
};

pub fn report(arena: Allocator, runs: []const Ledger.Run) !void {
    if (runs.len == 0) return error.NoRuns;
    var sides: std.ArrayList([]const u8) = .empty;
    for (runs) |run| {
        for (sides.items) |s| {
            if (std.mem.eql(u8, s, run.side)) break;
        } else try sides.append(arena, run.side);
    }
    const r: Report = .{ .arena = arena, .runs = runs };
    std.debug.print("prof {s} {s}, {s}\n", .{ runs[0].workload, runs[0].session, runs[0].host });
    for (sides.items) |s| try r.one(s);
    for (sides.items[1..]) |s| try r.against(sides.items[0], s);
}
