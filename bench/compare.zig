//! bench compare <live/run.sh's OUT> <A> <B>
//!
//! The live bench's two sides, pass by pass, then cold answer by cold
//! answer; the names they disagree on go to OUT/disagree.tsv.
const std = @import("std");
const Allocator = std.mem.Allocator;
const os = @import("os.zig");
const stats = @import("stats.zig");

const gpa = std.heap.smp_allocator;

/// As test/ask.go writes it: [rcode, ad, ede, answers, ms].
const Answer = struct {
    rcode: []const u8,
    ad: bool,
    ede: []const i64,
    rrs: []const []const u8,
    ms: f64,

    fn from(arena: Allocator, v: std.json.Value) !Answer {
        const a = v.array.items;
        const ede = try arena.alloc(i64, a[2].array.items.len);
        for (ede, a[2].array.items) |*e, x| e.* = x.integer;
        const rrs = try arena.alloc([]const u8, a[3].array.items.len);
        for (rrs, a[3].array.items) |*r, x| r.* = x.string;
        const ms: f64 = switch (a[4]) {
            .integer => |i| @floatFromInt(i),
            .float => |f| f,
            else => return error.Malformed,
        };
        return .{ .rcode = a[0].string, .ad = a[1].bool, .ede = ede, .rrs = rrs, .ms = ms };
    }

    fn failed(a: Answer) bool {
        return std.mem.startsWith(u8, a.rcode, "TIMEOUT") or std.mem.startsWith(u8, a.rcode, "ERROR");
    }

    fn shape(a: Answer, arena: Allocator) ![]const []const u8 {
        var set: std.array_hash_map.String(void) = .empty;
        for (a.rrs) |rr| try set.put(arena, rr[0 .. std.mem.findScalarLast(u8, rr, '|') orelse rr.len], {});
        sortNames(set.keys());
        return set.keys();
    }
};

const Row = struct { name: []const u8, round: usize, answers: [2]Answer };

fn sortNames(names: [][]const u8) void {
    std.mem.sort([]const u8, names, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
}

fn sameNames(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

fn files(arena: Allocator, dir: []const u8, pattern: []const u8) ![][]const u8 {
    var all: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.tokenizeScalar(u8, try os.capture(arena, &.{ "find", dir, "-maxdepth", "1", "-name", pattern }), '\n');
    while (lines.next()) |f| try all.append(arena, f);
    sortNames(all.items);
    return all.items;
}

fn percentile(v: []f64, p: usize) f64 {
    if (v.len == 0) return 0;
    std.mem.sort(f64, v, {}, std.sort.asc(f64));
    const n: f64 = @floatFromInt(v.len);
    return v[@min(v.len - 1, @as(usize, @intFromFloat(@as(f64, @floatFromInt(p)) / 100 * n)))];
}

fn bucket(arena: Allocator, a: Answer, b: Answer) ![]const u8 {
    if (std.mem.eql(u8, a.rcode, b.rcode) and a.failed()) return arena.print("both {s}", .{a.rcode});
    if (!std.mem.eql(u8, a.rcode, b.rcode)) return arena.print("rcode {s}/{s}", .{ a.rcode, b.rcode });
    if (a.ad != b.ad) return arena.print("ad {d}/{d}", .{ @intFromBool(a.ad), @intFromBool(b.ad) });
    if (!sameNames(try a.shape(arena), try b.shape(arena))) return "shape";
    return if (sameNames(a.rrs, b.rrs)) "same" else "addresses";
}

const Compare = struct {
    arena: Allocator,
    dir: []const u8,
    sides: [2][]const u8,
    passes: std.array_hash_map.String(std.ArrayList(Row)) = .empty,

    fn load(c: *Compare) !void {
        for (try files(c.arena, c.dir, "*.jsonl"), 0..) |file, round| {
            var parts = std.mem.splitBackwardsScalar(u8, file, '.');
            _ = parts.next();
            const pass = try c.passes.getOrPutValue(c.arena, parts.next().?, .empty);
            var lines = std.mem.tokenizeScalar(u8, try os.slurp(c.arena, file), '\n');
            while (lines.next()) |line| {
                const row = try std.json.parseFromSliceLeaky(struct { n: []const u8, r: [2]std.json.Value }, c.arena, line, .{});
                try pass.value_ptr.append(c.arena, .{ .name = row.n, .round = round, .answers = .{ try .from(c.arena, row.r[0]), try .from(c.arena, row.r[1]) } });
            }
        }
    }

    fn times(c: *Compare) !void {
        std.debug.print("{s: <22} {s: >10} {s: >10}\n", .{ "", c.sides[0], c.sides[1] });
        for (c.passes.keys(), c.passes.values()) |name, rows| {
            var ms: [2]std.ArrayList(f64) = @splat(.empty);
            // Cold times cluster by hop count; a percentile on the gap between
            // clusters swings as a few names cross it. Pairing each name's two
            // answers in a round does not.
            var paired: std.ArrayList(f64) = .empty;
            for (rows.items) |row| {
                for (&ms, row.answers) |*list, a| if (!a.failed()) try list.append(c.arena, a.ms);
                if (!row.answers[0].failed() and !row.answers[1].failed()) try paired.append(c.arena, row.answers[1].ms - row.answers[0].ms);
            }
            for ([_]usize{ 50, 90, 99 }) |p| {
                const o = percentile(ms[0].items, p);
                const n = percentile(ms[1].items, p);
                std.debug.print("{s} ms p{d: <14} {d: >10.2} {d: >10.2}  {s}%\n", .{ name, p, o, n, try signed(c.arena, if (o != 0) 100 * (n - o) / o else 0, 1) });
            }
            std.debug.print("{s} ms {s}-{s} paired   median {s}  mean {s}\n", .{ name, c.sides[1], c.sides[0], try signed(c.arena, try stats.median(gpa, paired.items), 2), try signed(c.arena, stats.mean(paired.items), 2) });
        }
    }

    const Table = [2]std.array_hash_map.String(std.ArrayList(f64));

    fn note(c: *Compare, t: *Table, side: usize, key: []const u8, value: f64) !void {
        const at = try t[side].getOrPutValue(c.arena, key, .empty);
        try at.value_ptr.append(c.arena, value);
    }

    fn counter(log: []const u8, comptime name: []const u8) ?f64 {
        const at = std.mem.findLast(u8, log, "stats " ++ name ++ " ") orelse return null;
        var f = std.mem.tokenizeAny(u8, log[at + 7 + name.len ..], " \n");
        const value = f.next() orelse return null;
        var digits: usize = 0;
        while (digits < value.len and std.ascii.isDigit(value[digits])) digits += 1;
        return std.fmt.parseFloat(f64, value[0..digits]) catch null;
    }

    fn footprint(c: *Compare, t: *Table, side: usize) !void {
        for (try files(c.arena, c.dir, try c.arena.print("{s}.*.mem", .{c.sides[side]}))) |mem| {
            const status = try os.slurp(c.arena, mem);
            if (std.mem.find(u8, status, "VmHWM:")) |at| {
                var f = std.mem.tokenizeAny(u8, status[at + 6 ..], " \t");
                try c.note(t, side, "VmHWM KiB", try std.fmt.parseFloat(f64, f.next().?));
            }
            const log = try os.slurp(c.arena, try c.arena.print("{s}.log", .{mem[0 .. mem.len - 4]}));
            if (counter(log, "resolver.exchanges.udp")) |udp| if (counter(log, "resolver.exchanges.tcp")) |tcp| {
                try c.note(t, side, "exchanges", udp + tcp);
                try c.note(t, side, "upstream tcp", tcp);
            };
            if (counter(log, "resolver.faults.timeout")) |n| try c.note(t, side, "upstream timeouts", n);
            if (counter(log, "trust.bogus")) |n| try c.note(t, side, "bogus", n);
            if (counter(log, "store.held")) |n| try c.note(t, side, "store KiB", n);
            if (counter(log, "store.facts")) |n| try c.note(t, side, "store facts", n);
        }
    }

    fn table(c: *Compare, cold: []const Row) !void {
        var t: Table = @splat(.empty);
        var round: usize = 0;
        var n: [2][3]f64 = @splat(@splat(0));
        for (cold, 0..) |row, i| {
            for (&n, row.answers) |*x, a| {
                x[0] += @floatFromInt(@intFromBool(a.ad));
                x[1] += @floatFromInt(@intFromBool(std.mem.eql(u8, a.rcode, "SERVFAIL")));
                x[2] += @floatFromInt(@intFromBool(a.failed()));
            }
            if (i + 1 < cold.len and cold[i + 1].round == round) continue;
            if (i + 1 < cold.len) round = cold[i + 1].round;
            for (n, 0..) |x, side| for (x, [_][]const u8{ "cold ad", "cold servfail", "cold failed" }) |v, key| try c.note(&t, side, key, v);
            n = @splat(@splat(0));
        }
        for (0..2) |side| try c.footprint(&t, side);
        for ([_][]const u8{ "cold ad", "cold servfail", "cold failed", "exchanges", "upstream tcp", "upstream timeouts", "bogus", "store KiB", "store facts", "VmHWM KiB" }) |key| {
            std.debug.print("{s: <22}", .{key});
            for (t) |side| {
                if (side.get(key)) |v| std.debug.print(" {d: >10.1}", .{try stats.median(gpa, v.items)}) else std.debug.print(" {s: >10}", .{"-"});
            }
            std.debug.print("\n", .{});
        }
    }

    const Moved = struct { by: f64, name: []const u8 };

    fn moved(c: *Compare, cold: []const Row) !void {
        var per: std.array_hash_map.String([2]std.ArrayList(f64)) = .empty;
        for (cold) |row| {
            const at = try per.getOrPutValue(c.arena, row.name, @splat(.empty));
            for (at.value_ptr, row.answers) |*list, a| try list.append(c.arena, a.ms);
        }
        const all = try c.arena.alloc(Moved, per.count());
        var faster: usize = 0;
        for (all, per.keys(), per.values()) |*m, name, ms| {
            m.* = .{ .by = try stats.median(gpa, ms[1].items) - try stats.median(gpa, ms[0].items), .name = name };
            faster += @intFromBool(m.by < 0);
        }
        std.mem.sort(Moved, all, {}, struct {
            fn lessThan(_: void, a: Moved, b: Moved) bool {
                return a.by < b.by or (a.by == b.by and std.mem.lessThan(u8, a.name, b.name));
            }
        }.lessThan);
        const few = @min(6, all.len);
        for ([_][]const u8{ "faster", "slower" }, [_][]const Moved{ all[0..few], all[all.len - few ..] }) |what, most| {
            std.debug.print("{s} {s} most: [", .{ c.sides[1], what });
            for (most, 0..) |m, i| std.debug.print("{s}('{s}', {d:.0})", .{ if (i == 0) "" else ", ", m.name, @round(m.by) });
            std.debug.print("]\n", .{});
        }
        std.debug.print("names {s} is faster on (median cold): {d}/{d}\n", .{ c.sides[1], faster, all.len });
    }

    fn agreement(c: *Compare, cold: []const Row, rounds: usize) !void {
        var buckets: std.array_hash_map.String(std.array_hash_map.String(usize)) = .empty;
        for (cold) |row| {
            const names = try buckets.getOrPutValue(c.arena, try bucket(c.arena, row.answers[0], row.answers[1]), .empty);
            const count = try names.value_ptr.getOrPutValue(c.arena, row.name, 0);
            count.value_ptr.* += 1;
        }
        const Sized = struct { kind: []const u8, names: [][]const u8, rows: usize };
        var sized: std.ArrayList(Sized) = .empty;
        for (buckets.keys(), buckets.values()) |kind, names| {
            var rows: usize = 0;
            for (names.values()) |n| rows += n;
            sortNames(names.keys());
            try sized.append(c.arena, .{ .kind = kind, .names = names.keys(), .rows = rows });
        }
        std.mem.sort(Sized, sized.items, {}, struct {
            fn lessThan(_: void, a: Sized, b: Sized) bool {
                return a.rows > b.rows;
            }
        }.lessThan);
        var tsv: std.ArrayList(u8) = .empty;
        std.debug.print("cold answers, {d} over {d} rounds:\n", .{ cold.len, rounds });
        for (sized.items) |s| {
            std.debug.print("  {d: >8}  {s}", .{ s.rows, s.kind });
            const agree = std.mem.eql(u8, s.kind, "same") or std.mem.eql(u8, s.kind, "addresses");
            if (!agree) {
                std.debug.print("  e.g.", .{});
                for (s.names[0..@min(4, s.names.len)]) |n| std.debug.print(" {s}", .{n});
                for (s.names) |n| try tsv.print(c.arena, "{s}\t{s}\n", .{ s.kind, n });
            }
            std.debug.print("\n", .{});
        }
        try os.spit(try c.arena.print("{s}/disagree.tsv", .{c.dir}), tsv.items);
    }

    fn errors(c: *Compare, cold: []const Row) !void {
        var tally: std.array_hash_map.String(f64) = .empty;
        for (cold) |row| for (row.answers, c.sides) |a, side| for (a.ede) |e| {
            const at = try tally.getOrPutValue(c.arena, try c.arena.print("('{s}', {d})", .{ side, e }), 0);
            at.value_ptr.* += 1;
        };
        const Ctx = struct {
            counts: []const f64,
            pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
                return ctx.counts[a] > ctx.counts[b];
            }
        };
        tally.sort(Ctx{ .counts = tally.values() });
        std.debug.print("ede: {{", .{});
        for (tally.keys()[0..@min(12, tally.count())], tally.values()[0..@min(12, tally.count())], 0..) |k, n, i|
            std.debug.print("{s}{s}: {d:.0}", .{ if (i == 0) "" else ", ", k, n });
        std.debug.print("}}\n", .{});
    }
};

fn signed(arena: Allocator, x: f64, comptime decimals: u8) ![]const u8 {
    return arena.print("{s}{d:." ++ std.fmt.comptimePrint("{d}", .{decimals}) ++ "}", .{ if (x < 0) "" else "+", x });
}

pub fn main(arena: Allocator, args: []const []const u8) !void {
    if (args.len != 3) return error.Usage;
    var c: Compare = .{ .arena = arena, .dir = args[0], .sides = .{ args[1], args[2] } };
    try c.load();
    const cold = (c.passes.get("cold") orelse return error.NoColdPass).items;
    var rounds: usize = 0;
    for (cold, 0..) |row, i| rounds += @intFromBool(i == 0 or cold[i - 1].round != row.round);
    try c.times();
    try c.table(cold);
    try c.moved(cold);
    try c.agreement(cold, rounds);
    try c.errors(cold);
}
