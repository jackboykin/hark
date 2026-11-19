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
var kept: hark.slab.Share = .{};
var owed: hark.slab.Share = .{};
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
    } else if (std.mem.eql(u8, name, "serve")) {
        return runServe(allocator, work_allocator, &args, io);
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
        \\  version             Print version
        \\
        \\Serve options:
        \\  --config <path>     Path to config file (default: /etc/hark/hark.toml)
        \\  --verbose, -v       Trace each resolution's steps
        \\
    , .{});
}

fn runServe(allocator: std.mem.Allocator, work_allocator: std.mem.Allocator, args: *std.process.Args.Iterator, io: Io) !void {
    hark.rand.randomizeHashKey();
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
        hark.config.parseConfigFile(allocator, io, path) catch |err| {
            log.err("loading config '{s}': {s}", .{ path, @errorName(err) });
            return err;
        }
    else
        try loadDefaultConfig(allocator, io);
    defer cfg.deinit();

    // A socket per exchange in flight can pass the usual 1024 soft limit.
    if (std.posix.getrlimit(.NOFILE)) |lim| {
        if (lim.cur < lim.max) std.posix.setrlimit(.NOFILE, .{ .cur = lim.max, .max = lim.max }) catch |err|
            log.warn("raising fd limit {d} -> {d}: {s}", .{ lim.cur, lim.max, @errorName(err) });
    } else |_| {}

    kept.limit = cfg.cache_size;
    hark.serve.run(allocator, work_allocator, .{ .allocator = facts.allocator(), .share = &kept }, &reserve, &cfg, trace) catch |err| {
        log.err("server error: {s}", .{@errorName(err)});
        return err;
    };
}

fn loadDefaultConfig(allocator: std.mem.Allocator, io: Io) !hark.config.ServerConfig {
    // Absolute: a service manager's working directory is not where the config is.
    const default_path = "/etc/hark/hark.toml";
    if (hark.config.parseConfigFile(allocator, io, default_path)) |cfg| {
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
