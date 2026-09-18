const std = @import("std");
const build_options = @import("build_options");
const hark = @import("hark");
const Io = std.Io;
const Server = hark.server.Server;

var log_verbose: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

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
    if (level == .debug and !log_verbose.load(.acquire)) return;

    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const level_prefix = comptime level.asText() ++ scope_prefix;

    var buf: [4096]u8 = undefined;
    var pos: usize = 0;

    const secs: u64 = @intCast(hark.monotonic.wallclockSec());
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const ds = es.getDaySeconds();
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();

    const ts = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z ", .{
        yd.year,              md.month.numeric(),      @as(u9, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch return;
    pos = ts.len;

    if (pos + level_prefix.len >= buf.len) return;
    @memcpy(buf[pos..][0..level_prefix.len], level_prefix);
    pos += level_prefix.len;

    const msg = std.fmt.bufPrint(buf[pos..], format ++ "\n", args) catch return;
    pos += msg.len;

    std.debug.print("{s}", .{buf[0..pos]});
}

const log = std.log;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    var args_list = std.ArrayList([:0]const u8).empty;
    defer args_list.deinit(allocator);
    while (args_iter.next()) |arg| {
        try args_list.append(allocator, arg);
    }
    const args = args_list.items;

    if (args.len < 2) {
        printUsage();
        std.process.exit(1);
    }

    const command = args[1];
    if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h") or std.mem.eql(u8, command, "help")) {
        printUsage();
        return;
    } else if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-V")) {
        var stdout_buf: [64]u8 = undefined;
        var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
        stdout_writer.interface.print("hark {s}\n", .{build_options.version}) catch std.process.exit(1);
        stdout_writer.interface.flush() catch std.process.exit(1);
        return;
    } else if (std.mem.eql(u8, command, "serve")) {
        return runServe(allocator, args[2..], io, .pool);
    } else if (std.mem.eql(u8, command, "graph")) {
        // Proof of concept; serve's options.
        return runServe(allocator, args[2..], io, .graph);
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

fn runServe(allocator: std.mem.Allocator, args: []const []const u8, io: Io, engine: enum { pool, graph }) !void {
    var config_path: ?[]const u8 = null;
    var cli_verbose = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--config")) {
            i += 1;
            if (i >= args.len) {
                log.err("--config requires a path", .{});
                std.process.exit(1);
            }
            config_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--verbose") or std.mem.eql(u8, args[i], "-v")) {
            cli_verbose = true;
        } else {
            log.err("unknown serve option: {s}", .{args[i]});
            std.process.exit(1);
        }
    }

    // Load config: explicit --config path → /etc/hark/hark.toml → defaults.
    // Only fall through on FileNotFound; surface any other error (parse, I/O).
    const cfg = if (config_path) |path|
        hark.config.parseConfigFile(allocator, io, path) catch |err| {
            log.err("loading config '{s}': {s}", .{ path, @errorName(err) });
            std.process.exit(1);
        }
    else
        loadDefaultConfig(allocator, io) catch std.process.exit(1);

    if (cli_verbose or cfg.log_queries) {
        log_verbose.store(true, .release);
    }

    // The source-port pools alone can exceed systemd's default 1024 soft cap.
    if (std.posix.getrlimit(.NOFILE)) |lim| {
        if (lim.cur < lim.max) std.posix.setrlimit(.NOFILE, .{ .cur = lim.max, .max = lim.max }) catch |err|
            log.warn("raising fd limit {d} -> {d}: {s}", .{ lim.cur, lim.max, @errorName(err) });
    } else |_| {}

    if (engine == .graph) return hark.graph.serve.run(allocator, &cfg, cli_verbose) catch |err| {
        log.err("graph server error: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    var server = Server.init(allocator, cfg, io) catch |err| {
        log.err("initializing server: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    server.run() catch |err| {
        log.err("server error: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn loadDefaultConfig(allocator: std.mem.Allocator, io: Io) !hark.config.ServerConfig {
    // No CWD-relative search: under systemd or any non-interactive runner the
    // working directory is unrelated to where the operator put the config.
    // Pass --config <path> for non-default locations.
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
