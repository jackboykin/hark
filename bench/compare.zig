//! bench compare <live/run.sh's OUT> <side>...
//!
//! The live bench's sides, pass by pass, then cold answer by cold answer,
//! each side against the first; the names a side disagrees with the first
//! on go to OUT/disagree.tsv.
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

const Row = struct { name: []const u8, round: usize, answers: []Answer };

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
    sides: []const []const u8,
    passes: std.array_hash_map.String(std.ArrayList(Row)) = .empty,

    fn load(c: *Compare) !void {
        for (try files(c.arena, c.dir, "*.jsonl"), 0..) |file, round| {
            var parts = std.mem.splitBackwardsScalar(u8, file, '.');
            _ = parts.next();
            const pass = try c.passes.getOrPutValue(c.arena, parts.next().?, .empty);
            var lines = std.mem.tokenizeScalar(u8, try os.slurp(c.arena, file), '\n');
            while (lines.next()) |line| {
                const row = try std.json.parseFromSliceLeaky(struct { n: []const u8, r: []std.json.Value }, c.arena, line, .{});
                if (row.r.len != c.sides.len) return error.SidesMismatch;
                const answers = try c.arena.alloc(Answer, row.r.len);
                for (answers, row.r) |*a, v| a.* = try .from(c.arena, v);
                try pass.value_ptr.append(c.arena, .{ .name = row.n, .round = round, .answers = answers });
            }
        }
    }

    fn header(c: *Compare) void {
        std.debug.print("{s: <22}", .{""});
        for (c.sides) |s| std.debug.print(" {s: >10}", .{s});
        std.debug.print("\n", .{});
    }

    fn times(c: *Compare) !void {
        c.header();
        for (c.passes.keys(), c.passes.values()) |name, rows| {
            const ms = try c.arena.alloc(std.ArrayList(f64), c.sides.len);
            @memset(ms, .empty);
            // Cold times cluster by hop count; a percentile on the gap between
            // clusters swings as a few names cross it. Pairing each name's
            // answers in a round does not.
            const paired = try c.arena.alloc(std.ArrayList(f64), c.sides.len);
            @memset(paired, .empty);
            for (rows.items) |row| {
                for (ms, row.answers) |*list, a| if (!a.failed()) try list.append(c.arena, a.ms);
                const ref = row.answers[0];
                for (paired[1..], row.answers[1..]) |*list, a| if (!ref.failed() and !a.failed()) try list.append(c.arena, a.ms - ref.ms);
            }
            for ([_]usize{ 50, 90, 99 }) |p| {
                std.debug.print("{s} ms p{d: <14}", .{ name, p });
                for (ms) |list| std.debug.print(" {d: >10.2}", .{percentile(list.items, p)});
                std.debug.print("\n", .{});
            }
            for (c.sides[1..], paired[1..]) |side, list| std.debug.print("{s} ms {s}-{s} paired   median {s}  mean {s}\n", .{ name, side, c.sides[0], try signed(c.arena, try stats.median(gpa, list.items), 2), try signed(c.arena, stats.mean(list.items), 2) });
        }
    }

    const Table = []std.array_hash_map.String(std.ArrayList(f64));

    fn note(c: *Compare, t: Table, side: usize, key: []const u8, value: f64) !void {
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

    fn footprint(c: *Compare, t: Table, side: usize) !void {
        for (try files(c.arena, c.dir, try c.arena.print("{s}.*.mem", .{c.sides[side]}))) |mem| {
            const status = try os.slurp(c.arena, mem);
            if (std.mem.find(u8, status, "VmHWM:")) |at| {
                var f = std.mem.tokenizeAny(u8, status[at + 6 ..], " \t");
                try c.note(t, side, "VmHWM KiB", try std.fmt.parseFloat(f64, f.next().?));
            }
            const log = try os.slurp(c.arena, try c.arena.print("{s}.log", .{mem[0 .. mem.len - 4]}));
            if (counter(log, "resolver.exchanges.datagram")) |datagram| if (counter(log, "resolver.exchanges.stream")) |stream| {
                try c.note(t, side, "exchanges", datagram + stream);
                try c.note(t, side, "upstream stream", stream);
            };
            if (counter(log, "resolver.faults.timeout")) |n| try c.note(t, side, "upstream timeouts", n);
            if (counter(log, "trust.bogus")) |n| try c.note(t, side, "bogus", n);
            if (counter(log, "store.held")) |n| try c.note(t, side, "store KiB", n);
            if (counter(log, "store.facts")) |n| try c.note(t, side, "store facts", n);
        }
    }

    fn table(c: *Compare, cold: []const Row) !void {
        const t: Table = try c.arena.alloc(std.array_hash_map.String(std.ArrayList(f64)), c.sides.len);
        @memset(t, .empty);
        var round: usize = 0;
        const n = try c.arena.alloc([3]f64, c.sides.len);
        @memset(n, @splat(0));
        for (cold, 0..) |row, i| {
            for (n, row.answers) |*x, a| {
                x[0] += @floatFromInt(@intFromBool(a.ad));
                x[1] += @floatFromInt(@intFromBool(std.mem.eql(u8, a.rcode, "SERVFAIL")));
                x[2] += @floatFromInt(@intFromBool(a.failed()));
            }
            if (i + 1 < cold.len and cold[i + 1].round == round) continue;
            if (i + 1 < cold.len) round = cold[i + 1].round;
            for (n, 0..) |x, side| for (x, [_][]const u8{ "cold ad", "cold servfail", "cold failed" }) |v, key| try c.note(t, side, key, v);
            @memset(n, @splat(0));
        }
        for (0..c.sides.len) |side| try c.footprint(t, side);
        c.header();
        for ([_][]const u8{ "cold ad", "cold servfail", "cold failed", "exchanges", "upstream stream", "upstream timeouts", "bogus", "store KiB", "store facts", "VmHWM KiB" }) |key| {
            std.debug.print("{s: <22}", .{key});
            for (t) |side| {
                if (side.get(key)) |v| std.debug.print(" {d: >10.1}", .{try stats.median(gpa, v.items)}) else std.debug.print(" {s: >10}", .{"-"});
            }
            std.debug.print("\n", .{});
        }
    }

    const Moved = struct { by: f64, name: []const u8 };

    fn moved(c: *Compare, cold: []const Row, side: usize) !void {
        var per: std.array_hash_map.String([2]std.ArrayList(f64)) = .empty;
        for (cold) |row| {
            const at = try per.getOrPutValue(c.arena, row.name, @splat(.empty));
            for (at.value_ptr, [_]Answer{ row.answers[0], row.answers[side] }) |*list, a| try list.append(c.arena, a.ms);
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
            std.debug.print("{s} {s} most: [", .{ c.sides[side], what });
            for (most, 0..) |m, i| std.debug.print("{s}('{s}', {d:.0})", .{ if (i == 0) "" else ", ", m.name, @round(m.by) });
            std.debug.print("]\n", .{});
        }
        std.debug.print("names {s} is faster on (median cold): {d}/{d}\n", .{ c.sides[side], faster, all.len });
    }

    fn agreement(c: *Compare, cold: []const Row, rounds: usize, side: usize, tsv: *std.ArrayList(u8)) !void {
        var buckets: std.array_hash_map.String(std.array_hash_map.String(usize)) = .empty;
        for (cold) |row| {
            const names = try buckets.getOrPutValue(c.arena, try bucket(c.arena, row.answers[0], row.answers[side]), .empty);
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
        std.debug.print("{s} against {s}, cold answers, {d} over {d} rounds:\n", .{ c.sides[side], c.sides[0], cold.len, rounds });
        for (sized.items) |s| {
            std.debug.print("  {d: >8}  {s}", .{ s.rows, s.kind });
            const agree = std.mem.eql(u8, s.kind, "same") or std.mem.eql(u8, s.kind, "addresses");
            if (!agree) {
                std.debug.print("  e.g.", .{});
                for (s.names[0..@min(4, s.names.len)]) |n| std.debug.print(" {s}", .{n});
                for (s.names) |n| try tsv.print(c.arena, "{s}\t{s}\t{s}\n", .{ c.sides[side], s.kind, n });
            }
            std.debug.print("\n", .{});
        }
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
    if (args.len < 3) return error.Usage;
    var c: Compare = .{ .arena = arena, .dir = args[0], .sides = args[1..] };
    try c.load();
    const cold = (c.passes.get("cold") orelse return error.NoColdPass).items;
    var rounds: usize = 0;
    for (cold, 0..) |row, i| rounds += @intFromBool(i == 0 or cold[i - 1].round != row.round);
    try c.times();
    try c.table(cold);
    for (1..c.sides.len) |side| try c.moved(cold, side);
    var tsv: std.ArrayList(u8) = .empty;
    for (1..c.sides.len) |side| try c.agreement(cold, rounds, side, &tsv);
    try os.spit(try c.arena.print("{s}/disagree.tsv", .{c.dir}), tsv.items);
    try c.errors(cold);
}
