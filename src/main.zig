const std = @import("std");
const hark = @import("hark");
const dns = hark.dns;
const EventLoop = hark.event_loop.EventLoop;
const UdpTransport = hark.transport.UdpTransport;
const ForwardingResolver = hark.resolver.ForwardingResolver;
const RecursiveResolver = hark.recursive.RecursiveResolver;
const RRsetCache = hark.cache.RRsetCache;

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
        \\
        \\Defaults: type=A, mode=recursive
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

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--forward")) {
            forward_mode = true;
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

    // Cache: 16MB cap, 10k max entries
    var cache = RRsetCache.init(gpa_alloc, 16 * 1024 * 1024, 10_000);
    defer cache.deinit();

    // DNS message data uses arena
    var arena = std.heap.ArenaAllocator.init(gpa_alloc);
    defer arena.deinit();

    const response = if (forward_mode) blk: {
        var resolver = ForwardingResolver.init(&t);
        const upstream = std.net.Address.initIp4(upstream_ip, 53);
        break :blk resolver.resolve(arena.allocator(), name, qtype, upstream) catch |err| {
            std.debug.print("Query failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    } else blk: {
        var resolver = RecursiveResolver.initWithCache(&t, &cache);
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
