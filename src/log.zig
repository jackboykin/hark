//! The log: std.log's lines gather in memory and reach stderr once a turn
//! of the server's loop, which never waits for it. Holds the sink, the
//! flush a turn ends with and the drain an exit ends with. One thread's.
const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const monotonic = @import("monotonic.zig");
const sys = @import("sys.zig");

var held: [64 * 1024]u8 = undefined;
var len: usize = 0;
var lost: u64 = 0;
var stalled = false;
var plain = false;
var out: posix.fd_t = posix.STDERR_FILENO;
var stamp: Stamp = .{};

const Stamp = struct {
    sec: i64 = std.math.minInt(i64),
    text: ["65535-12-31T23:59:59Z ".len]u8 = undefined,
    len: u8 = 0,

    fn now(s: *Stamp) []const u8 {
        const sec = monotonic.wallclockSec();
        if (sec == s.sec) return s.text[0..s.len];
        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(sec) };
        const day = es.getDaySeconds();
        const year = es.getEpochDay().calculateYearDay();
        const month = year.calculateMonthDay();
        const text = std.mem.print(&s.text, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z ", .{
            year.year,             month.month.numeric(),    @as(u9, month.day_index) + 1,
            day.getHoursIntoDay(), day.getMinutesIntoHour(), day.getSecondsIntoMinute(),
        }) catch unreachable;
        s.len = @intCast(text.len);
        s.sec = sec;
        return text;
    }
};

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const head = comptime level.asText() ++ if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    while (true) {
        var w: std.Io.Writer = .fixed(held[len..]);
        if (line(&w, head ++ format ++ "\n", args)) {
            len += w.end;
            lost = 0;
            return;
        } else |_| {}
        if (stalled or len == 0) break;
        flush();
    }
    lost += 1;
}

fn line(w: *std.Io.Writer, comptime format: []const u8, args: anytype) !void {
    try owed(w);
    try w.print("{s}" ++ format, .{stamp.now()} ++ args);
}

fn owed(w: *std.Io.Writer) !void {
    if (lost != 0) try w.print("{s}warning(log): {d} lines lost\n", .{ stamp.now(), lost });
}

pub fn flush() void {
    if (len == 0) return;
    const n = (if (plain) sys.write(out, held[0..len]) else sys.writeNoWait(out, held[0..len])) catch |err| switch (err) {
        error.WouldBlock => 0,
        error.Unsupported => {
            plain = true;
            return flush();
        },
        // A sink that fails loses what was held.
        else => len,
    };
    mem.copyForwards(u8, held[0 .. len - n], held[n..len]);
    len -= n;
    stalled = len != 0;
}

pub fn drain() void {
    // The second pass writes the count of lines lost.
    for (0..2) |_| {
        var rest: []const u8 = held[0..len];
        while (rest.len != 0) rest = rest[sys.write(out, rest) catch break ..];
        var w: std.Io.Writer = .fixed(&held);
        owed(&w) catch unreachable;
        len = w.end;
        lost = 0;
    }
}

const testing = std.testing;
const linux = std.os.linux;

const Pipe = struct {
    fds: [2]posix.fd_t,

    fn open() Pipe {
        var fds: [2]posix.fd_t = undefined;
        std.debug.assert(linux.pipe2(&fds, .{ .NONBLOCK = true }) == 0);
        std.debug.assert(linux.fcntl(fds[1], linux.F.SETFL, 0) == 0);
        out = fds[1];
        return .{ .fds = fds };
    }

    fn close(p: Pipe) void {
        for (p.fds) |fd| sys.close(fd);
        out = posix.STDERR_FILENO;
        len = 0;
        lost = 0;
        stalled = false;
        plain = false;
    }

    fn read(p: Pipe, buf: []u8) []u8 {
        var n: usize = 0;
        while (true) {
            const rc = linux.read(p.fds[0], buf[n..].ptr, buf.len - n);
            if (linux.errno(rc) != .SUCCESS or rc == 0) return buf[0..n];
            n += rc;
        }
    }
};

test "a full sink is never waited for, and what it cost is counted" {
    const p: Pipe = .open();
    defer p.close();
    const wide: [1000]u8 = @splat('x');
    for (0..200) |_| {
        logFn(.info, .default, "{s}", .{&wide});
        flush();
    }
    try testing.expect(stalled);
    try testing.expect(lost > 60);
    const was = lost;
    const big = try testing.allocator.alloc(u8, 256 * 1024);
    defer testing.allocator.free(big);
    _ = p.read(big);
    flush();
    _ = p.read(big);
    try testing.expect(!stalled);
    logFn(.info, .default, "back", .{});
    flush();
    const at = stamp.now();
    var want: [128]u8 = undefined;
    try testing.expectEqualStrings(try std.mem.print(&want, "{s}warning(log): {d} lines lost\n{s}info: back\n", .{ at, was, at }), p.read(big));
}
