//! Linux as the bench uses it: the clock, whole files, and child processes
//! on chosen cores.
const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

pub var environ: [*:null]const ?[*:0]const u8 = undefined;
pub var vars: *const std.process.Environ.Map = undefined;

pub fn knob(comptime T: type, name: []const u8, default: T) T {
    const v = vars.get(name) orelse return default;
    if (v.len == 0) return default;
    const Value = switch (@typeInfo(T)) {
        .optional => |o| o.child,
        else => T,
    };
    return switch (@typeInfo(Value)) {
        .int => std.fmt.parseInt(Value, v, 10) catch bad(name, v),
        .float => std.fmt.parseFloat(Value, v) catch bad(name, v),
        .bool => v[0] != '0',
        else => v,
    };
}

fn bad(name: []const u8, v: []const u8) noreturn {
    std.debug.print("bench: {s}={s} is not a number\n", .{ name, v });
    std.process.exit(2);
}

pub fn now() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * std.time.ns_per_s + ts.nsec;
}

pub fn sleep(ns: u64) void {
    const ts: linux.timespec = .{ .sec = @intCast(ns / std.time.ns_per_s), .nsec = @intCast(ns % std.time.ns_per_s) };
    _ = linux.nanosleep(&ts, null);
}

pub fn ok(rc: usize) bool {
    return linux.errno(rc) == .SUCCESS;
}

fn open(file: []const u8, flags: linux.O) !i32 {
    var buf: [4096]u8 = undefined;
    const z = try std.mem.printSentinel(&buf, "{s}", .{file}, 0);
    var f = flags;
    f.CLOEXEC = true;
    const rc = linux.open(z, f, 0o644);
    if (!ok(rc)) return error.Open;
    return @intCast(rc);
}

/// Reads to the end: procfs reports no size.
pub fn slurp(gpa: Allocator, file: []const u8) ![]u8 {
    const fd = try open(file, .{});
    defer _ = linux.close(fd);
    var all: std.ArrayList(u8) = .empty;
    while (true) {
        try all.ensureUnusedCapacity(gpa, 1 << 16);
        const n = linux.read(fd, all.unusedCapacitySlice().ptr, all.unusedCapacitySlice().len);
        if (!ok(n)) return error.Read;
        if (n == 0) return all.items;
        all.items.len += n;
    }
}

pub fn writer(file: []const u8, append: bool) !i32 {
    return open(file, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = append, .TRUNC = !append });
}

pub fn put(fd: i32, bytes: []const u8) void {
    var at: usize = 0;
    while (at < bytes.len) {
        const n = linux.write(fd, bytes[at..].ptr, bytes.len - at);
        if (!ok(n)) return;
        at += n;
    }
}

pub fn spit(file: []const u8, bytes: []const u8) !void {
    const fd = try writer(file, false);
    defer _ = linux.close(fd);
    put(fd, bytes);
}

fn cpuSet(cpus: []const u16) linux.cpu_set_t {
    var set: linux.cpu_set_t = @splat(0);
    for (cpus) |c| set[c / @bitSizeOf(usize)] |= @as(usize, 1) << @intCast(c % @bitSizeOf(usize));
    return set;
}

pub fn pin(cpus: []const u16) void {
    linux.sched_setaffinity(0, &cpuSet(cpus)) catch {};
}

pub const Child = struct {
    pid: linux.pid_t,

    pub fn signal(c: Child, sig: linux.SIG) void {
        _ = linux.kill(c.pid, sig);
    }

    pub fn wait(c: Child) u8 {
        var status: i32 = 0;
        _ = linux.waitpid(c.pid, &status, 0);
        const s: u32 = @bitCast(status);
        return if (linux.W.IFEXITED(s)) linux.W.EXITSTATUS(s) else 128;
    }

    pub fn stop(c: Child) void {
        c.signal(.TERM);
        _ = c.wait();
    }
};

const Spawn = struct {
    argv: []const []const u8,
    cpus: ?[]const u16 = null,
    stdin: ?i32 = null,
    stdout: ?i32 = null,
    stderr: ?i32 = null,
    extra: []const i32 = &.{},
    /// Only PATH in its environment: a subject's stack then sits the same
    /// from one session to the next, whatever the bench was started under.
    bare: bool = false,
};

pub const first_extra = 100;

fn resolve(arena: Allocator, name: []const u8) ![:0]const u8 {
    if (std.mem.findScalar(u8, name, '/') != null) return arena.dupeSentinel(u8, name, 0);
    var dirs = std.mem.splitScalar(u8, vars.get("PATH") orelse "", ':');
    while (dirs.next()) |dir| {
        const full = try arena.printSentinel("{s}/{s}", .{ dir, name }, 0);
        if (ok(linux.access(full, linux.X_OK))) return full;
    }
    std.debug.print("bench: {s} is not on PATH\n", .{name});
    return error.NotFound;
}

pub fn spawn(arena: Allocator, s: Spawn) !Child {
    const exe = try resolve(arena, s.argv[0]);
    const argv = try arena.allocSentinel(?[*:0]const u8, s.argv.len, null);
    for (argv, s.argv) |*a, v| a.* = try arena.dupeSentinel(u8, v, 0);
    const set = cpuSet(s.cpus orelse &.{});
    const only_path = [_:null]?[*:0]const u8{try arena.printSentinel("PATH={s}", .{vars.get("PATH") orelse ""}, 0)};
    const rc = linux.fork();
    if (!ok(rc)) return error.Fork;
    if (rc != 0) return .{ .pid = @intCast(rc) };
    _ = linux.prctl(@backingInt(linux.PR.SET_PDEATHSIG), @backingInt(linux.SIG.TERM), 0, 0, 0);
    if (s.cpus != null) linux.sched_setaffinity(0, &set) catch {};
    for ([_]?i32{ s.stdin, s.stdout, s.stderr }, 0..) |fd, to| if (fd) |f| {
        _ = linux.dup2(f, @intCast(to));
    };
    for (s.extra, first_extra..) |fd, to| _ = linux.dup2(fd, @intCast(to));
    _ = linux.execve(exe, argv.ptr, if (s.bare) &only_path else environ);
    linux.exit(127);
}

pub fn capture(arena: Allocator, argv: []const []const u8) ![]u8 {
    var fds: [2]i32 = undefined;
    if (!ok(linux.pipe2(&fds, .{ .CLOEXEC = true }))) return error.Pipe;
    const child = try spawn(arena, .{ .argv = argv, .stdout = fds[1], .stderr = fds[1] });
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    var all: std.ArrayList(u8) = .empty;
    while (true) {
        try all.ensureUnusedCapacity(arena, 1 << 12);
        const n = linux.read(fds[0], all.unusedCapacitySlice().ptr, all.unusedCapacitySlice().len);
        if (!ok(n) or n == 0) break;
        all.items.len += n;
    }
    _ = child.wait();
    return all.items;
}

pub fn run(arena: Allocator, argv: []const []const u8) !void {
    const child = try spawn(arena, .{ .argv = argv });
    if (child.wait() != 0) {
        std.debug.print("bench: {s} failed\n", .{argv[0]});
        return error.Failed;
    }
}
