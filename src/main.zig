const std = @import("std");
const hark = @import("hark");
const dns = hark.dns;
const EventLoop = hark.event_loop.EventLoop;
const UdpTransport = hark.transport.UdpTransport;
const TcpTransport = hark.tcp_transport.TcpTransport;
const TlsTransport = hark.tls_transport.TlsTransport;
const ConnectionPool = hark.connection_pool.ConnectionPool;
const EncryptionStateCache = hark.encryption_state.EncryptionStateCache;
const ForwardingResolver = hark.resolver.ForwardingResolver;
const RecursiveResolver = hark.recursive.RecursiveResolver;
const RRsetCache = hark.cache.RRsetCache;
const Certificate = std.crypto.Certificate;

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
    } else {
        std.debug.print("Unknown command: {s}\n\n", .{command});
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
        \\
        \\Query options:
        \\  --forward           Use forwarding mode instead of recursive resolution
        \\  --upstream <ip>     Upstream server for forwarding mode (default: 8.8.8.8)
        \\  --dot               Use DNS-over-TLS (forwarding mode, port 853)
        \\  --dot-host <name>   TLS server hostname for SNI/cert verification
        \\  --opportunistic     Opportunistic encryption to authoritatives (RFC 9539)
        \\  --no-qmin           Disable QNAME minimization (RFC 9156)
        \\  --dnssec            Enable DNSSEC validation
        \\  --no-dnssec         Disable DNSSEC validation (default)
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
        std.debug.print("Failed to read stdin: {}\n", .{err});
        std.process.exit(1);
    };

    if (input.len == 0) {
        std.debug.print("No input. Pipe a raw DNS packet via stdin.\n", .{});
        std.process.exit(1);
    }

    const msg = dns.parseMessage(allocator, input) catch |err| {
        std.debug.print("Failed to parse DNS message: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    dns.printMessage(msg, stdout) catch |err| {
        std.debug.print("Failed to print message: {}\n", .{err});
        std.process.exit(1);
    };

    stdout.flush() catch {};
}

fn runQuery(gpa_alloc: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        std.debug.print("Error: query requires a domain name\n\n", .{});
        printUsage();
        std.process.exit(1);
    }

    const name = args[0];
    var qtype: dns.RType = .a;
    var upstream_ip: [4]u8 = .{ 8, 8, 8, 8 };
    var forward_mode = false;
    var dot_mode = false;
    var dot_host: ?[]const u8 = null;
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
                std.debug.print("Error: --dot-host requires a hostname\n", .{});
                std.process.exit(1);
            }
            dot_host = args[i];
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
                std.debug.print("Error: --upstream requires an IP address\n", .{});
                std.process.exit(1);
            }
            upstream_ip = parseIpv4(args[i]) orelse {
                std.debug.print("Error: invalid IPv4 address: {s}\n", .{args[i]});
                std.process.exit(1);
            };
        } else {
            qtype = parseRType(args[i]) orelse {
                std.debug.print("Error: unknown record type: {s}\n", .{args[i]});
                std.process.exit(1);
            };
        }
    }

    // EventLoop and transport use GPA (long-lived)
    const loop = EventLoop.create(gpa_alloc) catch |err| {
        std.debug.print("Failed to initialize io_uring: {}\n", .{err});
        std.process.exit(1);
    };
    defer loop.destroy();

    var t = UdpTransport.init(loop, .{}) catch |err| {
        std.debug.print("Failed to create UDP socket: {}\n", .{err});
        std.process.exit(1);
    };
    defer t.deinit();

    var tcp_t = TcpTransport.init(loop, .{});

    // Load CA bundle if DoT is enabled
    var ca_bundle: Certificate.Bundle = .{};
    var ca_bundle_loaded = false;
    if (dot_mode) {
        ca_bundle.rescan(gpa_alloc) catch {
            std.debug.print("Error: failed to load system CA certificates\n", .{});
            std.process.exit(1);
        };
        ca_bundle_loaded = true;
    }
    defer if (ca_bundle_loaded) ca_bundle.deinit(gpa_alloc);

    // TLS transport (only when --dot is set)
    var tls_t = TlsTransport.init(loop, gpa_alloc, .{
        .server_name = dot_host,
    }, ca_bundle);

    // Cache: 16MB cap, 10k max entries
    var cache = RRsetCache.init(gpa_alloc, 16 * 1024 * 1024, 10_000);
    defer cache.deinit();

    // DNS message data uses arena
    var arena = std.heap.ArenaAllocator.init(gpa_alloc);
    defer arena.deinit();

    const response = if (forward_mode) blk: {
        var resolver = ForwardingResolver.initWithTcp(&t, &tcp_t);
        if (dot_mode) {
            resolver.tls_transport = &tls_t;
        }
        const upstream = std.net.Address.initIp4(upstream_ip, 53);
        break :blk resolver.resolve(arena.allocator(), name, qtype, upstream) catch |err| {
            std.debug.print("Query failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    } else blk: {
        var enc_state = EncryptionStateCache.init(gpa_alloc);
        defer enc_state.deinit();

        var resolver = RecursiveResolver.initFull(&t, &tcp_t, &cache);
        if (no_qmin) resolver.qname_minimisation = false;
        resolver.dnssec_enabled = dnssec_enabled;
        if (opportunistic) {
            resolver.tls_transport = &tls_t;
            resolver.encryption_state = &enc_state;
        }
        break :blk resolver.resolve(arena.allocator(), name, qtype) catch |err| {
            std.debug.print("Query failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    };

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    dns.printMessage(response, stdout) catch |err| {
        std.debug.print("Failed to print response: {}\n", .{err});
        std.process.exit(1);
    };

    stdout.flush() catch {};
}

fn parseRType(s: []const u8) ?dns.RType {
    const lower = blk: {
        var buf: [16]u8 = undefined;
        if (s.len > buf.len) return null;
        for (s, 0..) |c, idx| {
            buf[idx] = std.ascii.toLower(c);
        }
        break :blk buf[0..s.len];
    };

    if (std.mem.eql(u8, lower, "a")) return .a;
    if (std.mem.eql(u8, lower, "aaaa")) return .aaaa;
    if (std.mem.eql(u8, lower, "ns")) return .ns;
    if (std.mem.eql(u8, lower, "cname")) return .cname;
    if (std.mem.eql(u8, lower, "soa")) return .soa;
    if (std.mem.eql(u8, lower, "ptr")) return .ptr;
    if (std.mem.eql(u8, lower, "mx")) return .mx;
    if (std.mem.eql(u8, lower, "txt")) return .txt;
    if (std.mem.eql(u8, lower, "ds")) return .ds;
    if (std.mem.eql(u8, lower, "rrsig")) return .rrsig;
    if (std.mem.eql(u8, lower, "nsec")) return .nsec;
    if (std.mem.eql(u8, lower, "dnskey")) return .dnskey;
    if (std.mem.eql(u8, lower, "nsec3")) return .nsec3;
    if (std.mem.eql(u8, lower, "nsec3param")) return .nsec3param;
    return null;
}

fn parseIpv4(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var iter = std.mem.splitScalar(u8, s, '.');
    while (iter.next()) |part| {
        if (octet_idx >= 4) return null;
        result[octet_idx] = std.fmt.parseInt(u8, part, 10) catch return null;
        octet_idx += 1;
    }
    if (octet_idx != 4) return null;
    return result;
}
