//! The statistics the bench's reports read: the middle and spread of a few
//! runs, and bootstrap intervals over them.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub fn mean(v: []const f64) f64 {
    var sum: f64 = 0;
    for (v) |x| sum += x;
    return sum / @as(f64, @floatFromInt(v.len));
}

pub fn median(gpa: Allocator, v: []const f64) !f64 {
    const s = try gpa.dupe(f64, v);
    defer gpa.free(s);
    std.mem.sort(f64, s, {}, std.sort.asc(f64));
    const m = s.len / 2;
    return if (s.len % 2 == 1) s[m] else (s[m - 1] + s[m]) / 2;
}

pub fn cv(v: []const f64) f64 {
    if (v.len < 2) return 0;
    const m = mean(v);
    var sum: f64 = 0;
    for (v) |x| sum += (x - m) * (x - m);
    return 100 * @sqrt(sum / @as(f64, @floatFromInt(v.len - 1))) / m;
}

pub const Boot = struct {
    gpa: Allocator,
    random: std.Random.Pcg = .init(1),

    const draws = 20000;

    fn resample(b: *Boot, v: []const f64, into: []f64) void {
        for (into) |*x| x.* = v[b.random.random().uintLessThan(usize, v.len)];
    }

    fn interval(boot: []f64) [2]f64 {
        std.mem.sort(f64, boot, {}, std.sort.asc(f64));
        return .{ boot[draws / 40], boot[draws - draws / 40] };
    }

    pub fn ofMedian(b: *Boot, v: []const f64) ![2]f64 {
        const boot = try b.gpa.alloc(f64, draws);
        defer b.gpa.free(boot);
        const drawn = try b.gpa.alloc(f64, v.len);
        defer b.gpa.free(drawn);
        for (boot) |*x| {
            b.resample(v, drawn);
            x.* = try median(b.gpa, drawn);
        }
        return interval(boot);
    }

    pub fn ofMeanRatio(b: *Boot, y: []const f64, x: []const f64) ![2]f64 {
        const boot = try b.gpa.alloc(f64, draws);
        defer b.gpa.free(boot);
        const dy = try b.gpa.alloc(f64, y.len);
        defer b.gpa.free(dy);
        const dx = try b.gpa.alloc(f64, x.len);
        defer b.gpa.free(dx);
        for (boot) |*r| {
            b.resample(y, dy);
            b.resample(x, dx);
            r.* = mean(dy) / mean(dx);
        }
        return interval(boot);
    }
};

pub fn signTest(n: usize, wins: usize) f64 {
    var tail: f64 = 0;
    for (0..@min(wins, n - wins) + 1) |k| {
        var c: f64 = 1;
        for (1..k + 1) |i| c = c * @as(f64, @floatFromInt(n - k + i)) / @as(f64, @floatFromInt(i));
        tail += c;
    }
    return @min(1.0, 2 * tail / std.math.pow(f64, 2, @floatFromInt(n)));
}
