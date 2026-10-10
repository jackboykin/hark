const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const hark = @import("hark");
const Io = std.Io;

var log_verbose = false;

pub const std_options: std.Options = .{
    .logFn = logFn,
    .log_level = .debug,
};

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (level == .debug and !log_verbose) return;

    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";

    const secs: u64 = @intCast(hark.monotonic.wallclockSec());
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const ds = es.getDaySeconds();
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();

    var buf: [4096]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z " ++ level.asText() ++ scope_prefix ++ format ++ "\n", .{
        yd.year,              md.month.numeric(),      @as(u9, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    } ++ args) catch return;
    std.debug.print("{s}", .{line});
}

const log = std.log;

/// Debug keeps std's allocator, which names every leak.
var reserve: hark.slab.Reserve = .{};
var lasting: hark.slab.Tenant = .init(&reserve);
var work: hark.slab.Tenant = .init(&reserve);

pub fn main(init: std.process.Init) !void {
    const allocator = if (builtin.mode == .debug) init.gpa else lasting.allocator();
    const work_allocator = if (builtin.mode == .debug) init.gpa else work.allocator();
    const io = init.io;

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.skip();
    const command = args.next() orelse {
        printUsage();
        std.process.exit(1);
    };

    if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h") or std.mem.eql(u8, command, "help")) {
        printUsage();
    } else if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-V")) {
        var stdout_buf: [64]u8 = undefined;
        var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
        stdout_writer.interface.print("hark {s}\n", .{build_options.version}) catch std.process.exit(1);
        stdout_writer.interface.flush() catch std.process.exit(1);
    } else if (std.mem.eql(u8, command, "serve")) {
        return runServe(allocator, work_allocator, &args, io);
    } else {
        log.err("unknown command: {s}", .{command});
        printUsage();
        std.process.exit(1);
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
        \\  --verbose, -v       Enable debug logging (per-query log lines)
        \\
    , .{});
}

fn runServe(allocator: std.mem.Allocator, work_allocator: std.mem.Allocator, args: *std.process.Args.Iterator, io: Io) !void {
    var config_path: ?[]const u8 = null;
    var cli_verbose = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config")) {
            config_path = args.next() orelse {
                log.err("--config requires a path", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            cli_verbose = true;
        } else {
            log.err("unknown serve option: {s}", .{arg});
            std.process.exit(1);
        }
    }

    // Only a missing default config falls back to the built-in defaults.
    var cfg = if (config_path) |path|
        hark.config.parseConfigFile(allocator, io, path) catch |err| {
            log.err("loading config '{s}': {s}", .{ path, @errorName(err) });
            std.process.exit(1);
        }
    else
        loadDefaultConfig(allocator, io) catch std.process.exit(1);
    defer cfg.deinit();
    log_verbose = cli_verbose or cfg.log_queries;

    // A socket per exchange in flight can exceed systemd's default 1024 soft cap.
    if (std.posix.getrlimit(.NOFILE)) |lim| {
        if (lim.cur < lim.max) std.posix.setrlimit(.NOFILE, .{ .cur = lim.max, .max = lim.max }) catch |err|
            log.warn("raising fd limit {d} -> {d}: {s}", .{ lim.cur, lim.max, @errorName(err) });
    } else |_| {}

    hark.serve.run(allocator, work_allocator, if (builtin.mode == .debug) null else &reserve, &cfg, cli_verbose) catch |err| {
        log.err("server error: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn loadDefaultConfig(allocator: std.mem.Allocator, io: Io) !hark.config.ServerConfig {
    // Never relative to the working directory, which under a service
    // manager is unrelated to where the operator put the config.
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
