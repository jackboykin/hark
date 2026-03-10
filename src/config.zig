const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const toml = @import("toml.zig");

// ── ServerConfig ───────────────────────────────────────────────────────

pub const ServerConfig = struct {
    listen: []std.net.Address,
    mode: Mode,
    upstreams: []std.net.Address,
    cache_size: usize,
    cache_entries: u32,
    prefetch: bool,
    serve_stale_ttl: u32,
    min_ttl: u32,
    dnssec: bool,
    qname_minimization: bool,
    opportunistic: bool,
    workers: u16,
    log_queries: bool,

    allocator: Allocator,

    pub const Mode = enum { recursive, forward };

    pub fn deinit(self: *ServerConfig) void {
        self.allocator.free(self.listen);
        self.allocator.free(self.upstreams);
    }
};

pub const ConfigError = error{
    InvalidListenAddress,
    InvalidUpstreamAddress,
    InvalidMode,
    InvalidPort,
    InvalidWorkerCount,
    ForwardingRequiresUpstreams,
    OutOfMemory,
};

// ── Defaults ───────────────────────────────────────────────────────────

fn defaultConfig(allocator: Allocator) ConfigError!ServerConfig {
    const listen = allocator.alloc(std.net.Address, 2) catch return error.OutOfMemory;
    listen[0] = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 53);
    listen[1] = std.net.Address.initIp6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 53, 0, 0);

    const empty_upstreams = allocator.alloc(std.net.Address, 0) catch return error.OutOfMemory;

    return .{
        .listen = listen,
        .mode = .recursive,
        .upstreams = empty_upstreams,
        .cache_size = 16 * 1024 * 1024,
        .cache_entries = 10_000,
        .prefetch = false,
        .serve_stale_ttl = 0,
        .min_ttl = 0,
        .dnssec = false,
        .qname_minimization = true,
        .opportunistic = false,
        .workers = @intCast(@max(1, std.Thread.getCpuCount() catch 1)),
        .log_queries = false,
        .allocator = allocator,
    };
}

// ── Parser ─────────────────────────────────────────────────────────────

pub fn parseConfig(allocator: Allocator, contents: []const u8) (toml.ParseError || ConfigError)!ServerConfig {
    var parsed = try toml.parse(allocator, contents);
    defer parsed.deinit();

    var cfg = try defaultConfig(allocator);
    errdefer cfg.deinit();

    // [server] section
    if (parsed.table.getTable("server")) |server| {
        if (server.getStringArray("listen")) |addrs| {
            allocator.free(cfg.listen);
            cfg.listen = try parseAddressList(allocator, addrs, 53);
        }
        if (server.getInteger("workers")) |w| {
            if (w < 1 or w > 65535) return error.InvalidWorkerCount;
            cfg.workers = @intCast(w);
        }
    }

    // [resolver] section
    if (parsed.table.getTable("resolver")) |resolver| {
        if (resolver.getString("mode")) |mode_str| {
            if (mem.eql(u8, mode_str, "recursive")) {
                cfg.mode = .recursive;
            } else if (mem.eql(u8, mode_str, "forward")) {
                cfg.mode = .forward;
            } else {
                return error.InvalidMode;
            }
        }
        if (resolver.getStringArray("upstreams")) |addrs| {
            allocator.free(cfg.upstreams);
            cfg.upstreams = try parseAddressList(allocator, addrs, 53);
        }
        if (resolver.getBool("dnssec")) |d| cfg.dnssec = d;
        if (resolver.getBool("qname-minimization")) |q| cfg.qname_minimization = q;
        if (resolver.getBool("opportunistic")) |o| cfg.opportunistic = o;
    }

    // [cache] section
    if (parsed.table.getTable("cache")) |cache| {
        if (cache.getInteger("size")) |s| {
            cfg.cache_size = @intCast(@max(0, @min(s, std.math.maxInt(usize))));
        }
        if (cache.getInteger("entries")) |e| {
            cfg.cache_entries = @intCast(@max(0, @min(e, std.math.maxInt(u32))));
        }
        if (cache.getBool("prefetch")) |p| cfg.prefetch = p;
        if (cache.getInteger("serve-stale-ttl")) |s| {
            cfg.serve_stale_ttl = @intCast(@max(0, @min(s, std.math.maxInt(u32))));
        }
        if (cache.getInteger("min-ttl")) |m| {
            cfg.min_ttl = @intCast(@max(0, @min(m, std.math.maxInt(u32))));
        }
    }

    // [logging] section
    if (parsed.table.getTable("logging")) |logging| {
        if (logging.getBool("queries")) |q| cfg.log_queries = q;
    }

    // Validation
    if (cfg.mode == .forward and cfg.upstreams.len == 0) {
        return error.ForwardingRequiresUpstreams;
    }

    return cfg;
}

pub fn parseConfigFile(allocator: Allocator, path: []const u8) !ServerConfig {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    return parseConfig(allocator, contents);
}

fn parseAddressList(allocator: Allocator, strs: []const []const u8, default_port: u16) ConfigError![]std.net.Address {
    const addrs = allocator.alloc(std.net.Address, strs.len) catch return error.OutOfMemory;
    errdefer allocator.free(addrs);

    for (strs, 0..) |s, i| {
        addrs[i] = parseAddress(s, default_port) orelse return error.InvalidListenAddress;
    }
    return addrs;
}

pub fn parseAddress(s: []const u8, default_port: u16) ?std.net.Address {
    // IPv6 with brackets: [::1]:53 or [::1]
    if (s.len > 0 and s[0] == '[') {
        const close = mem.indexOfScalar(u8, s, ']') orelse return null;
        const ip6_str = s[1..close];
        const port = if (close + 1 < s.len and s[close + 1] == ':')
            std.fmt.parseInt(u16, s[close + 2 ..], 10) catch return null
        else
            default_port;
        const addr = std.net.Ip6Address.parse(ip6_str, port) catch return null;
        return std.net.Address.initIp6(addr.sa.addr, port, 0, 0);
    }

    // Check for IPv4 with port: 1.2.3.4:53
    // Count colons — IPv6 has multiple, IPv4:port has exactly one
    var colon_count: usize = 0;
    var last_colon: usize = 0;
    for (s, 0..) |c, i| {
        if (c == ':') {
            colon_count += 1;
            last_colon = i;
        }
    }

    if (colon_count == 1) {
        // IPv4 with port
        const ip_str = s[0..last_colon];
        const port_str = s[last_colon + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
        const ip4 = parseIpv4(ip_str) orelse return null;
        return std.net.Address.initIp4(ip4, port);
    }

    if (colon_count > 1) {
        // Bare IPv6 without brackets
        const addr = std.net.Ip6Address.parse(s, default_port) catch return null;
        return std.net.Address.initIp6(addr.sa.addr, default_port, 0, 0);
    }

    // Plain IPv4 (no port)
    const ip4 = parseIpv4(s) orelse return null;
    return std.net.Address.initIp4(ip4, default_port);
}

fn parseIpv4(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var iter = mem.splitScalar(u8, s, '.');
    while (iter.next()) |part| {
        if (octet_idx >= 4) return null;
        result[octet_idx] = std.fmt.parseInt(u8, part, 10) catch return null;
        octet_idx += 1;
    }
    if (octet_idx != 4) return null;
    return result;
}

// ── Tests ──────────────────────────────────────────────────────────────

test "default config" {
    var cfg = try defaultConfig(testing.allocator);
    defer cfg.deinit();

    try testing.expectEqual(@as(usize, 2), cfg.listen.len);
    try testing.expectEqual(ServerConfig.Mode.recursive, cfg.mode);
    try testing.expectEqual(@as(usize, 0), cfg.upstreams.len);
    try testing.expectEqual(@as(usize, 16 * 1024 * 1024), cfg.cache_size);
    try testing.expectEqual(@as(u32, 10_000), cfg.cache_entries);
    try testing.expectEqual(false, cfg.dnssec);
    try testing.expectEqual(true, cfg.qname_minimization);
    try testing.expect(cfg.workers >= 1);
}

test "parse full config" {
    var cfg = try parseConfig(testing.allocator,
        \\[server]
        \\listen = ["127.0.0.1:8053"]
        \\workers = 2
        \\
        \\[resolver]
        \\mode = "recursive"
        \\dnssec = true
        \\qname-minimization = false
        \\
        \\[cache]
        \\size = 8388608
        \\entries = 5000
    );
    defer cfg.deinit();

    try testing.expectEqual(@as(usize, 1), cfg.listen.len);
    try testing.expectEqual(@as(u16, 8053), cfg.listen[0].getPort());
    try testing.expectEqual(@as(u16, 2), cfg.workers);
    try testing.expectEqual(ServerConfig.Mode.recursive, cfg.mode);
    try testing.expectEqual(true, cfg.dnssec);
    try testing.expectEqual(false, cfg.qname_minimization);
    try testing.expectEqual(@as(usize, 8388608), cfg.cache_size);
    try testing.expectEqual(@as(u32, 5000), cfg.cache_entries);
}

test "parse forwarding config" {
    var cfg = try parseConfig(testing.allocator,
        \\[resolver]
        \\mode = "forward"
        \\upstreams = ["8.8.8.8", "1.1.1.1"]
    );
    defer cfg.deinit();

    try testing.expectEqual(ServerConfig.Mode.forward, cfg.mode);
    try testing.expectEqual(@as(usize, 2), cfg.upstreams.len);
}

test "forwarding without upstreams is error" {
    const result = parseConfig(testing.allocator,
        \\[resolver]
        \\mode = "forward"
    );
    try testing.expectError(error.ForwardingRequiresUpstreams, result);
}

test "invalid mode is error" {
    const result = parseConfig(testing.allocator,
        \\[resolver]
        \\mode = "bogus"
    );
    try testing.expectError(error.InvalidMode, result);
}

test "empty config uses defaults" {
    var cfg = try parseConfig(testing.allocator, "");
    defer cfg.deinit();

    try testing.expectEqual(@as(usize, 2), cfg.listen.len);
    try testing.expectEqual(ServerConfig.Mode.recursive, cfg.mode);
}

test "parse IPv6 listen address" {
    var cfg = try parseConfig(testing.allocator,
        \\[server]
        \\listen = ["[::1]:5353"]
    );
    defer cfg.deinit();

    try testing.expectEqual(@as(usize, 1), cfg.listen.len);
    try testing.expectEqual(@as(u16, 5353), cfg.listen[0].getPort());
}

test "parse address with default port" {
    const addr = parseAddress("192.168.1.1", 53).?;
    try testing.expectEqual(@as(u16, 53), addr.getPort());
}

test "parse address with explicit port" {
    const addr = parseAddress("192.168.1.1:8053", 53).?;
    try testing.expectEqual(@as(u16, 8053), addr.getPort());
}

test "invalid worker count" {
    const result = parseConfig(testing.allocator,
        \\[server]
        \\workers = 0
    );
    try testing.expectError(error.InvalidWorkerCount, result);
}

test "cache prefetch and stale config" {
    var cfg = try parseConfig(testing.allocator,
        \\[cache]
        \\prefetch = true
        \\serve-stale-ttl = 3600
        \\min-ttl = 300
    );
    defer cfg.deinit();

    try testing.expectEqual(true, cfg.prefetch);
    try testing.expectEqual(@as(u32, 3600), cfg.serve_stale_ttl);
    try testing.expectEqual(@as(u32, 300), cfg.min_ttl);
}

test "cache prefetch defaults to off" {
    var cfg = try parseConfig(testing.allocator, "");
    defer cfg.deinit();

    try testing.expectEqual(false, cfg.prefetch);
    try testing.expectEqual(@as(u32, 0), cfg.serve_stale_ttl);
    try testing.expectEqual(@as(u32, 0), cfg.min_ttl);
}

test "logging config" {
    // Default: log_queries is false
    var cfg1 = try parseConfig(testing.allocator, "");
    defer cfg1.deinit();
    try testing.expectEqual(false, cfg1.log_queries);

    // Explicit enable
    var cfg2 = try parseConfig(testing.allocator,
        \\[logging]
        \\queries = true
    );
    defer cfg2.deinit();
    try testing.expectEqual(true, cfg2.log_queries);
}
