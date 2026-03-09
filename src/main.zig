const std = @import("std");
const builtin = @import("builtin");
const hark = @import("hark");
const dns = hark.dns;
const EventLoop = hark.event_loop.EventLoop;
const UdpTransport = hark.transport.UdpTransport;
const TcpTransport = hark.tcp_transport.TcpTransport;
const TlsTransport = hark.tls_transport.TlsTransport;
const ConnectionPool = hark.connection_pool.ConnectionPool;
const EncryptedNsCache = hark.encrypted_ns.EncryptedNsCache;
const ForwardingResolver = hark.resolver.ForwardingResolver;
const RecursiveResolver = hark.recursive.RecursiveResolver;
const RttCache = hark.ns_rtt.RttCache;
const RRsetCache = hark.cache.RRsetCache;
const Certificate = std.crypto.Certificate;
const Server = hark.server.Server;
const ServerConfig = hark.config.ServerConfig;

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
    const secs: u64 = @intCast(std.time.timestamp());
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const ds = es.getDaySeconds();
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();

    const ts = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z ", .{
        yd.year, md.month.numeric(), @as(u9, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch return;
    pos = ts.len;

    // Level + scope prefix
    if (pos + level_prefix.len >= buf.len) return;
    @memcpy(buf[pos..][0..level_prefix.len], level_prefix);
    pos += level_prefix.len;

    // Message
    const msg = std.fmt.bufPrint(buf[pos..], format ++ "\n", args) catch return;
    pos += msg.len;

    // Write atomically to stderr
    const stderr = std.debug.lockStderrWriter(buf[pos..]);
    defer std.debug.unlockStderrWriter();
    nosuspend stderr.writeAll(buf[0..pos]) catch {};
}

const log = std.log;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        std.process.exit(1);
    }

    const command = args[1];
    if (std.mem.eql(u8, command, "dump")) {
        return runDump(allocator);
    } else if (std.mem.eql(u8, command, "query")) {
        return runQuery(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "serve")) {
        return runServe(allocator, args[2..]);
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
        \\                      Resolve a DNS query (recursive by default)
        \\  serve [options]     Start DNS server
        \\
        \\Query options:
        \\  --forward           Use forwarding mode instead of recursive resolution
        \\  --upstream <addr>   Upstream server (IPv4, IPv6, or [IPv6]:port; default: 8.8.8.8)
        \\  --dot               Use DNS-over-TLS (forwarding mode, port 853)
        \\  --dot-host <name>   TLS server hostname for SNI/cert verification
        \\  --dot-strict        Require hostname verification (RFC 7858 strict mode)
        \\  --opportunistic     Opportunistic encryption to authoritatives (RFC 9539)
        \\  --no-qmin           Disable QNAME minimization (RFC 9156)
        \\  --dnssec            Enable DNSSEC validation
        \\  --no-dnssec         Disable DNSSEC validation (default)
        \\
        \\Serve options:
        \\  --config <path>     Path to config file (default: ./hark.toml)
        \\  --verbose, -v       Enable debug logging (per-query log lines)
        \\
        \\Defaults: type=A, mode=recursive, QNAME minimization enabled, DNSSEC off
        \\
    , .{});
}

fn runDump(gpa_alloc: std.mem.Allocator) !void {
    var arena = std.heap.ArenaAllocator.init(gpa_alloc);
    defer arena.deinit();
    const allocator = arena.allocator();

    var stdin_buf: [4096]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buf);
    const input = stdin_reader.interface.allocRemaining(allocator, @enumFromInt(dns.max_udp_payload * 4)) catch |err| {
        log.err("failed to read stdin: {}", .{err});
        std.process.exit(1);
    };

    if (input.len == 0) {
        log.err("no input — pipe a raw DNS packet via stdin", .{});
        std.process.exit(1);
    }

    const msg = dns.parseMessage(allocator, input) catch |err| {
        log.err("failed to parse DNS message: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    dns.printMessage(msg, stdout) catch |err| {
        log.err("failed to print message: {}", .{err});
        std.process.exit(1);
    };

    stdout.flush() catch {};
}

fn runQuery(gpa_alloc: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        log.err("query requires a domain name", .{});
        printUsage();
        std.process.exit(1);
    }

    const name = args[0];
    var qtype: dns.RType = .a;
    var upstream_addr = std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 53);
    var forward_mode = false;
    var dot_mode = false;
    var dot_host: ?[]const u8 = null;
    var dot_strict = false;
    var no_qmin = false;
    var dnssec_enabled = false;
    var opportunistic = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--forward")) {
            forward_mode = true;
        } else if (std.mem.eql(u8, args[i], "--dot")) {
            dot_mode = true;
            forward_mode = true; // DoT implies forwarding
        } else if (std.mem.eql(u8, args[i], "--dot-host")) {
            i += 1;
            if (i >= args.len) {
                log.err("--dot-host requires a hostname", .{});
                std.process.exit(1);
            }
            dot_host = args[i];
        } else if (std.mem.eql(u8, args[i], "--dot-strict")) {
            dot_strict = true;
            dot_mode = true;
            forward_mode = true;
        } else if (std.mem.eql(u8, args[i], "--opportunistic")) {
            opportunistic = true;
        } else if (std.mem.eql(u8, args[i], "--no-qmin")) {
            no_qmin = true;
        } else if (std.mem.eql(u8, args[i], "--dnssec")) {
            dnssec_enabled = true;
        } else if (std.mem.eql(u8, args[i], "--no-dnssec")) {
            dnssec_enabled = false;
        } else if (std.mem.eql(u8, args[i], "--upstream")) {
            i += 1;
            if (i >= args.len) {
                log.err("--upstream requires an address", .{});
                std.process.exit(1);
            }
            upstream_addr = hark.config.parseAddress(args[i], 53) orelse {
                log.err("invalid address: {s}", .{args[i]});
                std.process.exit(1);
            };
        } else {
            qtype = parseRType(args[i]) orelse {
                log.err("unknown record type: {s}", .{args[i]});
                std.process.exit(1);
            };
        }
    }

    // EventLoop and transport use GPA (long-lived)
    const loop = EventLoop.create(gpa_alloc) catch |err| {
        log.err("failed to initialize io_uring: {}", .{err});
        std.process.exit(1);
    };
    defer loop.destroy();

    var t = UdpTransport.init(loop, .{}) catch |err| {
        log.err("failed to create UDP socket: {}", .{err});
        std.process.exit(1);
    };
    defer t.deinit();

    var tcp_t = TcpTransport.init(loop, .{});

    if (dot_strict and dot_host == null) {
        log.err("--dot-strict requires --dot-host for hostname verification", .{});
        std.process.exit(1);
    }

    // Load CA bundle if DoT is enabled
    var ca_bundle: Certificate.Bundle = .{};
    var ca_bundle_loaded = false;
    if (dot_mode) {
        ca_bundle.rescan(gpa_alloc) catch {
            log.err("failed to load system CA certificates", .{});
            std.process.exit(1);
        };
        ca_bundle_loaded = true;
    }
    defer if (ca_bundle_loaded) ca_bundle.deinit(gpa_alloc);

    // TLS transport (only when --dot is set)
    var tls_t = TlsTransport.init(loop, gpa_alloc, .{
        .server_name = dot_host,
        .strict = dot_strict,
    }, ca_bundle);

    // Cache: 16MB cap, 10k max entries
    const cache_alloc = if (builtin.single_threaded)
        gpa_alloc
    else
        std.heap.smp_allocator;
    var cache = RRsetCache.init(cache_alloc, 16 * 1024 * 1024, 10_000);
    defer cache.deinit();

    // DNS message data uses arena
    var arena = std.heap.ArenaAllocator.init(gpa_alloc);
    defer arena.deinit();

    const response = if (forward_mode) blk: {
        var resolver = ForwardingResolver.initWithTcp(&t, &tcp_t);
        if (dot_mode) {
            resolver.tls_transport = &tls_t;
        }
        break :blk resolver.resolve(arena.allocator(), name, qtype, upstream_addr) catch |err| {
            log.err("query failed: {s}", .{@errorName(err)});
            std.process.exit(1);
        };
    } else blk: {
        var enc_ns = EncryptedNsCache.init(gpa_alloc);
        var enc_pool = ConnectionPool.init(gpa_alloc);
        defer {
            enc_ns.awaitProbes();
            enc_pool.deinit();
            enc_ns.deinit();
        }

        if (opportunistic) tls_t.pool = &enc_pool;

        var rtt_cache = RttCache.init(gpa_alloc);
        defer rtt_cache.deinit();

        var resolver = RecursiveResolver{
            .transport = &t,
            .tcp_transport = &tcp_t,
            .cache = &cache,
            .qname_minimisation = !no_qmin,
            .dnssec_enabled = dnssec_enabled,
            .dnssec_aware = dnssec_enabled,
            .rtt_cache = &rtt_cache,
            .tls_transport = if (opportunistic) &tls_t else null,
            .encrypted_ns_cache = if (opportunistic) &enc_ns else null,
        };
        const result = resolver.resolve(arena.allocator(), name, qtype) catch |err| {
            log.err("query failed: {s}", .{@errorName(err)});
            std.process.exit(1);
        };
        break :blk result.message;
    };

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    dns.printMessage(response, stdout) catch |err| {
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

fn runServe(gpa_alloc: std.mem.Allocator, args: []const []const u8) !void {
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

    // Load config: explicit path → ./hark.toml → /etc/hark/hark.toml → defaults
    var cfg = if (config_path) |path|
        hark.config.parseConfigFile(gpa_alloc, path) catch |err| {
            log.err("loading config '{s}': {s}", .{ path, @errorName(err) });
            std.process.exit(1);
        }
    else
        hark.config.parseConfigFile(gpa_alloc, "hark.toml") catch
            hark.config.parseConfigFile(gpa_alloc, "/etc/hark/hark.toml") catch
            hark.config.parseConfig(gpa_alloc, "") catch |err| {
            log.err("creating default config: {s}", .{@errorName(err)});
            std.process.exit(1);
        };
    defer cfg.deinit();

    // Enable verbose logging from CLI flag or config
    if (cli_verbose or cfg.log_queries) {
        log_verbose.store(true, .release);
    }

    // Start server
    var server = Server.init(gpa_alloc, cfg) catch |err| {
        log.err("initializing server: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    defer server.deinit();

    server.run() catch |err| {
        log.err("server error: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
}
