//! The observer: a process left outside the rig's namespaces, where perf
//! may count and sample whole cores (inside, perf_event_open is refused),
//! and the rig's line to it.
//!
//! A request is one message, fields tab-separated; so is its reply.
//!   stat <cpus> <events> <file>   opens a counting window on those cores, perf's output to <file>
//!   stop                          closes it: "event=value ..."
//!   run <stdout> <argv>...        runs a command to its end: its exit status
const std = @import("std");
const linux = std.os.linux;
const os = @import("os.zig");
const Allocator = std.mem.Allocator;

fd: i32,

const Observer = @This();

const max_message = 1 << 16;

const Window = struct {
    perf: os.Child,
    counts: []const u8,
    ctl: i32,
    ack: i32,
    hold: i32,

    fn tell(w: Window, what: []const u8) void {
        var buf: [16]u8 = undefined;
        os.put(w.ctl, what);
        _ = linux.read(w.ack, &buf, buf.len);
    }
};

/// Call before any namespace is left and before any thread starts.
pub fn start() !Observer {
    var pair: [2]i32 = undefined;
    if (!os.ok(linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &pair))) return error.SocketPair;
    const rc = linux.fork();
    if (!os.ok(rc)) return error.Fork;
    if (rc == 0) {
        _ = linux.close(pair[0]);
        serve(pair[1]);
    }
    _ = linux.close(pair[1]);
    return .{ .fd = pair[0] };
}

fn serve(fd: i32) noreturn {
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_state.allocator();
    var window: ?Window = null;
    var buf: [max_message]u8 = undefined;
    while (true) {
        _ = arena_state.reset(.retain_capacity);
        const n = linux.read(fd, &buf, buf.len);
        if (!os.ok(n) or n == 0) linux.exit(0);
        var fields = std.mem.splitScalar(u8, buf[0..n], '\t');
        const verb = fields.next().?;
        const reply = if (std.mem.eql(u8, verb, "stat"))
            open(&window, fields.next().?, fields.next().?, fields.next().?)
        else if (std.mem.eql(u8, verb, "stop"))
            close(arena, &window)
        else
            run(arena, &fields);
        os.put(fd, reply catch |e| arena.print("error {t}", .{e}) catch "error");
    }
}

/// The window outlives this request, so what it keeps is not the arena's.
fn open(window: *?Window, cpus: []const u8, events: []const u8, file: []const u8) ![]const u8 {
    const gpa = std.heap.page_allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const counts = try gpa.dupe(u8, file);
    var ctl: [2]i32 = undefined;
    var ack: [2]i32 = undefined;
    var hold: [2]i32 = undefined;
    for ([_]*[2]i32{ &ctl, &ack, &hold }) |p| if (!os.ok(linux.pipe2(p, .{ .CLOEXEC = true }))) return error.Pipe;
    const null_fd = try os.writer("/dev/null", true);
    defer for ([_]i32{ ctl[0], ack[1], hold[0], null_fd }) |f| {
        _ = linux.close(f);
    };
    const control = try arena.print("fd:{d},{d}", .{ os.first_extra, os.first_extra + 1 });
    const perf = try os.spawn(arena, .{
        .argv = &.{ "perf", "stat", "-C", cpus, "-e", events, "-x,", "-o", counts, "-D", "-1", "--control", control, "--", "cat" },
        .stdin = hold[0],
        .stdout = null_fd,
        .stderr = null_fd,
        .extra = &.{ ctl[0], ack[1] },
    });
    window.* = .{ .perf = perf, .counts = counts, .ctl = ctl[1], .ack = ack[0], .hold = hold[1] };
    window.*.?.tell("enable\n");
    return "ok";
}

/// perf's -x, lines are "value,unit,event,...".
fn close(arena: Allocator, window: *?Window) ![]const u8 {
    const w = window.* orelse return error.NoWindow;
    window.* = null;
    w.tell("disable\n");
    for ([_]i32{ w.hold, w.ctl, w.ack }) |f| _ = linux.close(f);
    if (w.perf.wait() != 0) return error.PerfStat;
    var out: std.ArrayList(u8) = .empty;
    defer std.heap.page_allocator.free(w.counts);
    var lines = std.mem.tokenizeScalar(u8, try os.slurp(arena, w.counts), '\n');
    while (lines.next()) |line| {
        if (line[0] == '#') continue;
        var f = std.mem.splitScalar(u8, line, ',');
        const value = f.next().?;
        _ = f.next() orelse continue;
        const event = f.next() orelse continue;
        try out.print(arena, "{s}={s} ", .{ event, value });
    }
    return out.items;
}

fn run(arena: Allocator, fields: *std.mem.SplitIterator(u8, .scalar)) ![]const u8 {
    const to = fields.next() orelse return error.Malformed;
    var argv: std.ArrayList([]const u8) = .empty;
    while (fields.next()) |a| try argv.append(arena, a);
    const out = if (to.len > 0) try os.writer(to, false) else null;
    defer if (out) |f| {
        _ = linux.close(f);
    };
    const child = try os.spawn(arena, .{ .argv = argv.items, .stdout = out });
    return arena.print("{d}", .{child.wait()});
}

fn call(o: Observer, arena: Allocator, request: []const u8) ![]const u8 {
    os.put(o.fd, request);
    const buf = try arena.alloc(u8, max_message);
    const n = linux.read(o.fd, buf.ptr, buf.len);
    if (!os.ok(n) or n == 0) return error.ObserverGone;
    if (std.mem.startsWith(u8, buf[0..n], "error")) {
        std.debug.print("bench: observer: {s} ({s})\n", .{ buf[0..n], request });
        return error.Observer;
    }
    return buf[0..n];
}

pub fn statOn(o: Observer, arena: Allocator, cpus: []const u8, events: []const u8, file: []const u8) !void {
    _ = try o.call(arena, try arena.print("stat\t{s}\t{s}\t{s}", .{ cpus, events, file }));
}

pub fn statOff(o: Observer, arena: Allocator) ![]const u8 {
    return o.call(arena, "stop");
}

pub fn outside(o: Observer, arena: Allocator, to: []const u8, argv: []const []const u8) !void {
    const request = try std.mem.join(arena, "\t", argv);
    const status = try o.call(arena, try arena.print("run\t{s}\t{s}", .{ to, request }));
    if (!std.mem.eql(u8, status, "0")) {
        std.debug.print("bench: {s} exited {s}\n", .{ argv[0], status });
        return error.Failed;
    }
}
