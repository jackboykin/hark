const std = @import("std");
const build_options = @import("build_options");
const hark = @import("hark");
const dns = hark.dns;
const dns_print = hark.dns_print;
const BlockingUdpTransport = hark.blocking_transport.BlockingUdpTransport;
const TlsTransport = hark.tls_transport.TlsTransport;
const RecursiveResolver = hark.recursive.RecursiveResolver;
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

    // Timestamp
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

    // Level + scope prefix
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
    } else if (std.mem.eql(u8, command, "dump")) {
        return runDump(allocator, io);
    } else if (std.mem.eql(u8, command, "query")) {
        return runQuery(allocator, args[2..], io);
    } else if (std.mem.eql(u8, command, "serve")) {
        return runServe(allocator, args[2..], io);
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
        \\  dump                Read a raw DNS packet from stdin and print it
        \\  query <name> [type] [options]
        \\                      Resolve a DNS query recursively
        \\  serve [options]     Start DNS server
        \\  version             Print version
        \\
        \\Query options:
        \\  --opportunistic     Opportunistic encryption to authoritatives (RFC 9539)
        \\  --no-qmin           Disable QNAME minimization (RFC 9156)
        \\  --dnssec            Enable DNSSEC validation
        \\  --no-dnssec         Disable DNSSEC validation (default)
        \\  --verbose, -v       Enable debug logging
        \\
        \\Serve options:
        \\  --config <path>     Path to config file (default: /etc/hark/hark.toml)
        \\  --verbose, -v       Enable debug logging (per-query log lines)
        \\
        \\Defaults: type=A, QNAME minimization enabled, DNSSEC off
        \\
    , .{});
}

fn runDump(gpa: std.mem.Allocator, io: Io) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    var stdin_buf: [4096]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buf);
    const input = stdin_reader.interface.allocRemaining(allocator, @enumFromInt(dns.max_udp_payload * 4)) catch |err| {
        log.err("failed to read stdin: {}", .{err});
        std.process.exit(1);
    };

    if (input.len == 0) {
        log.err("no input; pipe a raw DNS packet via stdin", .{});
        std.process.exit(1);
    }

    const msg = dns.parseMessage(allocator, input) catch |err| {
        log.err("failed to parse DNS message: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    dns_print.printMessage(msg, stdout) catch |err| {
        log.err("failed to print message: {}", .{err});
        std.process.exit(1);
    };

    stdout.flush() catch {};
}

fn runQuery(allocator: std.mem.Allocator, args: []const []const u8, io: Io) !void {
    if (args.len == 0) {
        log.err("query requires a domain name", .{});
        printUsage();
        std.process.exit(1);
    }

    const name = args[0];
    var qtype: dns.RType = .a;
    var no_qmin = false;
    var dnssec_enabled = false;
    var opportunistic = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--verbose") or std.mem.eql(u8, args[i], "-v")) {
            log_verbose.store(true, .release);
        } else if (std.mem.eql(u8, args[i], "--opportunistic")) {
            opportunistic = true;
        } else if (std.mem.eql(u8, args[i], "--no-qmin")) {
            no_qmin = true;
        } else if (std.mem.eql(u8, args[i], "--dnssec")) {
            dnssec_enabled = true;
        } else if (std.mem.eql(u8, args[i], "--no-dnssec")) {
            dnssec_enabled = false;
        } else {
            qtype = parseRType(args[i]) orelse {
                log.err("unknown record type: {s}", .{args[i]});
                std.process.exit(1);
            };
        }
    }

    // Reuse Server.init/fromContext so one-shot `query` is wired exactly like
    // `serve` (caches, NS selector, DNSSEC, opportunistic, fanout) from the
    // same config path, instead of a hand-rolled subset that silently drifts.
    // init never binds sockets; only run() does.
    var cfg = hark.config.parseConfig(allocator, "") catch |err| {
        log.err("building default config: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    cfg.qname_minimization = !no_qmin;
    cfg.dnssec = dnssec_enabled;
    cfg.opportunistic = opportunistic;
    defer cfg.deinit();

    var server = Server.init(allocator, cfg, io) catch |err| {
        log.err("initializing resolver: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    defer server.deinit();

    // Fresh transports for this single resolve (mirrors the bg-prefetch path).
    var t = BlockingUdpTransport.init(.{}, io);
    defer t.deinit();
    var tls_t: ?TlsTransport = if (opportunistic) blk: {
        var tt = TlsTransport.init(allocator, .{}, server.ca_bundle, io);
        if (server.enc_pool) |*pool| tt.pool = pool;
        break :blk tt;
    } else null;
    const tls_ptr: ?*TlsTransport = if (tls_t) |*tt| tt else null;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var resolver = RecursiveResolver.fromContext(
        server.resolverContext(),
        .{ .udp = &t, .tcp_enabled = true, .tls = tls_ptr },
        .{},
    );
    const result = resolver.resolve(arena.allocator(), name, qtype) catch |err| {
        log.err("query failed: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    var response = result.message;

    var lower_buf: [dns.max_name_len + 1]u8 = undefined;
    var questions: [1]dns.Question = undefined;
    if (dns.parseDottedName(arena.allocator(), dns.lowerNameIntoBuf(&lower_buf, name))) |qname| {
        questions[0] = .{ .name = qname, .qtype = qtype, .qclass = .in };
        response.questions = &questions;
    } else |_| {}

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    dns_print.printMessage(response, stdout) catch |err| {
        log.err("failed to print response: {}", .{err});
        std.process.exit(1);
    };

    stdout.flush() catch {};
}

fn parseRType(s: []const u8) ?dns.RType {
    var buf: [16]u8 = undefined;
    if (s.len > buf.len) return null;
    for (s, 0..) |c, idx| buf[idx] = std.ascii.toLower(c);
    const result = std.meta.stringToEnum(dns.RType, buf[0..s.len]) orelse return null;
    if (result == .opt) return null; // pseudo-type, not a real query type
    return result;
}

fn runServe(allocator: std.mem.Allocator, args: []const []const u8, io: Io) !void {
    // Parse serve flags
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
    var cfg = if (config_path) |path|
        hark.config.parseConfigFile(allocator, path) catch |err| {
            log.err("loading config '{s}': {s}", .{ path, @errorName(err) });
            std.process.exit(1);
        }
    else
        loadDefaultConfig(allocator) catch std.process.exit(1);
    defer cfg.deinit();

    // Enable verbose logging from CLI flag or config
    if (cli_verbose or cfg.log_queries) {
        log_verbose.store(true, .release);
    }

    // Start server
    var server = Server.init(allocator, cfg, io) catch |err| {
        log.err("initializing server: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    defer server.deinit();

    server.run() catch |err| {
        log.err("server error: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn loadDefaultConfig(allocator: std.mem.Allocator) !hark.config.ServerConfig {
    // No CWD-relative search: under systemd or any non-interactive runner the
    // working directory is unrelated to where the operator put the config.
    // Pass --config <path> for non-default locations.
    const default_path = "/etc/hark/hark.toml";
    if (hark.config.parseConfigFile(allocator, default_path)) |cfg| {
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
