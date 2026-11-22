//! The hark executable: its arguments and the config it loads, then the
//! server.

const std = @import("std");
const build_options = @import("build_options");
const hark = @import("hark");
const Io = std.Io;

pub const std_options: std.Options = .{
    .logFn = hark.log.logFn,
    .log_level = .debug,
};

pub const panic = std.debug.FullPanic(panicked);

fn panicked(msg: []const u8, first_trace_addr: ?usize) noreturn {
    hark.log.drain();
    std.debug.defaultPanic(msg, first_trace_addr);
}

const log = std.log;
const leaks = std.log.scoped(.slab);

var reserve: hark.slab.Reserve = .{};
var kept: hark.Share = .{};
var owed: hark.Share = .{};
var facts: hark.slab.Tenant = .in(&reserve, &kept);
var lasting: hark.slab.Tenant = .in(&reserve, &owed);
var work: hark.slab.Tenant = .in(&reserve, &owed);

pub fn main(init: std.process.Init) u8 {
    defer hark.log.drain();
    const status: u8 = if (command(init)) 0 else |_| 1;
    reserve.drain();
    if (kept.held + owed.held > 0) leaks.err("{d} bytes cached and {d} owed still held at exit", .{ kept.held, owed.held });
    return status;
}

fn command(init: std.process.Init) !void {
    const allocator = lasting.allocator();
    const work_allocator = work.allocator();
    const io = init.io;

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.skip();
    const name = args.next() orelse {
        printUsage();
        return error.Usage;
    };

    if (std.mem.eql(u8, name, "--help") or std.mem.eql(u8, name, "-h") or std.mem.eql(u8, name, "help")) {
        printUsage();
    } else if (std.mem.eql(u8, name, "version") or std.mem.eql(u8, name, "--version") or std.mem.eql(u8, name, "-V")) {
        var stdout_buf: [64]u8 = undefined;
        var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
        try stdout_writer.interface.print("hark {s}\n", .{build_options.version});
        try stdout_writer.interface.flush();
    } else if (std.mem.eql(u8, name, "serve") or std.mem.eql(u8, name, "check")) {
        return runServe(allocator, work_allocator, &args, io, std.mem.eql(u8, name, "check"));
    } else {
        log.err("unknown command: {s}", .{name});
        printUsage();
        return error.Usage;
    }
}

fn printUsage() void {
    std.debug.print(
        \\Usage: hark <command> [options]
        \\
        \\Commands:
        \\  serve [options]     Start DNS server
        \\  check [options]     Load the config as serve would, then exit
        \\  version             Print version
        \\
        \\Serve and check options:
        \\  --config <path>     Path to config file (default: /etc/hark/hark.toml)
        \\  --verbose, -v       Trace each resolution's steps
        \\
    , .{});
}

fn runServe(allocator: std.mem.Allocator, work_allocator: std.mem.Allocator, args: *std.process.Args.Iterator, io: Io, check: bool) !void {
    hark.sys.random.bytes(&hark.keyed.hash_key);
    var config_path: ?[]const u8 = null;
    var trace = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config")) {
            config_path = args.next() orelse {
                log.err("--config requires a path", .{});
                return error.Usage;
            };
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            trace = true;
        } else {
            log.err("unknown serve option: {s}", .{arg});
            return error.Usage;
        }
    }

    var cfg = if (config_path) |path|
        readConfig(allocator, io, path) catch |err| {
            log.err("loading config '{s}': {s}", .{ path, @errorName(err) });
            return err;
        }
    else
        try loadDefaultConfig(allocator, io);
    defer cfg.deinit();
    if (check) return;

    // A socket per exchange in flight can pass the usual 1024 soft limit.
    if (std.posix.getrlimit(.NOFILE)) |lim| {
        if (lim.cur < lim.max) std.posix.setrlimit(.NOFILE, .{ .cur = lim.max, .max = lim.max }) catch |err|
            log.warn("raising fd limit {d} -> {d}: {s}", .{ lim.cur, lim.max, @errorName(err) });
    } else |_| {}

    if (cgroupMemoryMax()) |max| if (cfg.memoryLimit() > max) {
        log.err("[server] memory is {d} bytes, over the memory.max of {d} on hark's cgroup or one above it", .{ cfg.memoryLimit(), max });
        return error.MemoryOverCgroup;
    };
    reserve.limit = cfg.memoryLimit();
    kept.limit = cfg.cache_size;
    owed.limit = hark.config.ServerConfig.sharesOf(reserve.limit) - cfg.cache_size;
    hark.serve.run(allocator, work_allocator, &owed, .{ .allocator = facts.allocator(), .share = &kept }, &reserve, &cfg, trace) catch |err| {
        log.err("server error: {s}", .{@errorName(err)});
        return err;
    };
}

fn cgroupMemoryMax() ?u64 {
    var buf: [4096]u8 = undefined;
    const own = readSmall("/proc/self/cgroup", &buf) orelse return null;
    const at = std.mem.find(u8, own, "0::") orelse return null;
    const rest = own[at + 3 ..];
    var dir = rest[0 .. std.mem.findScalar(u8, rest, '\n') orelse rest.len];
    var least: ?u64 = null;
    while (dir.len > 1) : (dir = dir[0 .. std.mem.findScalarLast(u8, dir, '/') orelse 0]) {
        var path: [4096 + 32]u8 = undefined;
        const file = std.mem.printSentinel(&path, "/sys/fs/cgroup{s}/memory.max", .{dir}, 0) catch return least;
        var limit: [32]u8 = undefined;
        const text = std.mem.trimEnd(u8, readSmall(file, &limit) orelse continue, "\n");
        const max = std.fmt.parseInt(u64, text, 10) catch continue;
        least = @min(least orelse max, max);
    }
    return least;
}

fn readSmall(path: [*:0]const u8, buf: []u8) ?[]const u8 {
    const linux = std.os.linux;
    const rc = linux.open(path, .{ .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const n = linux.read(fd, buf.ptr, buf.len);
    if (linux.errno(n) != .SUCCESS) return null;
    return buf[0..n];
}

fn readConfig(allocator: std.mem.Allocator, io: Io, path: []const u8) !hark.config.ServerConfig {
    const contents = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024)) catch |err| switch (err) {
        error.StreamTooLong => return error.ConfigFileTooLarge,
        else => |e| return e,
    };
    defer allocator.free(contents);
    return hark.config.parseConfig(allocator, contents);
}

fn loadDefaultConfig(allocator: std.mem.Allocator, io: Io) !hark.config.ServerConfig {
    // Absolute: a service manager's working directory is not where the config is.
    const default_path = "/etc/hark/hark.toml";
    if (readConfig(allocator, io, default_path)) |cfg| {
        return cfg;
    } else |err| switch (err) {
        error.FileNotFound => {
            log.warn("no config at {s}; using built-in defaults (pass --config <path> for a custom location)", .{default_path});
        },
        else => {
            log.err("loading config '{s}': {s}", .{ default_path, @errorName(err) });
            return err;
        },
    }
    return hark.config.parseConfig(allocator, "") catch |err| {
        log.err("creating default config: {s}", .{@errorName(err)});
        return err;
    };
}
