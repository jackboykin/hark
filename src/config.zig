const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const toml = @import("toml.zig");
const net_addr = @import("net_address.zig");
const Address = net_addr.Address;

// ── ServerConfig ───────────────────────────────────────────────────────

pub const ServerConfig = struct {
    listen: []Address,
    mode: Mode,
    upstreams: []Address,
    cache_size: usize,
    cache_entries: u32,
    key_cache_size: usize,
    key_cache_entries: u32,
    prefetch: bool,
    prefetch_cousin: bool,
    serve_stale_ttl: u32,
    min_ttl: u32,
    dnssec: bool,
    qname_minimization: bool,
    query_memory_limit: usize,
    opportunistic: bool,
    workers: u16,
    resolution_threads: u16,
    stagger_ms: u32,
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
    InvalidValue,
    InvalidWorkerCount,
    InvalidQueryMemoryLimit,
    ForwardingRequiresUpstreams,
    OutOfMemory,
};

// ── Defaults ───────────────────────────────────────────────────────────

fn defaultConfig(allocator: Allocator) ConfigError!ServerConfig {
    const listen = allocator.alloc(Address, 2) catch return error.OutOfMemory;
    errdefer allocator.free(listen);
    listen[0] = net_addr.initIp4(.{ 127, 0, 0, 1 }, 53);
    listen[1] = net_addr.initIp6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 53, 0, 0);

    const empty_upstreams = allocator.alloc(Address, 0) catch return error.OutOfMemory;

    return .{
        .listen = listen,
        .mode = .recursive,
        .upstreams = empty_upstreams,
        .cache_size = 16 * 1024 * 1024,
        .cache_entries = 10_000,
        .key_cache_size = 4 * 1024 * 1024,
        .key_cache_entries = 2_000,
        .prefetch = false,
        .prefetch_cousin = false,
        .serve_stale_ttl = 0,
        .min_ttl = 0,
        .dnssec = false,
        .qname_minimization = true,
        .query_memory_limit = 2 * 1024 * 1024,
        .opportunistic = false,
        .workers = @intCast(@max(1, std.Thread.getCpuCount() catch 1)),
        .resolution_threads = 4,
        .stagger_ms = 150,
        .log_queries = false,
        .allocator = allocator,
    };
}

// ── Parser ─────────────────────────────────────────────────────────────

fn nonNegativeClamped(comptime T: type, table: toml.Table, key: []const u8) ConfigError!?T {
    const v = table.getInteger(key) orelse return null;
    if (v < 0) return error.InvalidValue;
    return @intCast(@min(v, std.math.maxInt(T)));
}

pub fn parseConfig(allocator: Allocator, contents: []const u8) (toml.ParseError || ConfigError)!ServerConfig {
    var parsed = try toml.parse(allocator, contents);
    defer parsed.deinit();

    var cfg = try defaultConfig(allocator);
    errdefer cfg.deinit();

    // [server] section
    if (parsed.table.getTable("server")) |server| {
        if (server.getStringArray("listen")) |addrs| {
            allocator.free(cfg.listen);
            cfg.listen = try parseAddressList(allocator, addrs, 53, error.InvalidListenAddress);
        }
        if (server.getInteger("workers")) |w| {
            if (w < 1 or w > 65535) return error.InvalidWorkerCount;
            cfg.workers = @intCast(w);
        }
        if (server.getInteger("resolution-threads")) |rt| {
            if (rt < 1 or rt > 256) return error.InvalidWorkerCount;
            cfg.resolution_threads = @intCast(rt);
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
            cfg.upstreams = try parseAddressList(allocator, addrs, 53, error.InvalidUpstreamAddress);
        }
        if (resolver.getBool("dnssec")) |d| cfg.dnssec = d;
        if (resolver.getBool("qname-minimization")) |q| cfg.qname_minimization = q;
        if (resolver.getBool("opportunistic")) |o| cfg.opportunistic = o;
        if (try nonNegativeClamped(usize, resolver, "query-memory-limit")) |val| {
            if (val != 0 and val < 65536) return error.InvalidQueryMemoryLimit;
            cfg.query_memory_limit = val;
        }
        if (try nonNegativeClamped(u32, resolver, "stagger-ms")) |v| cfg.stagger_ms = @min(v, 1000);
    }

    // [cache] section
    if (parsed.table.getTable("cache")) |cache| {
        if (try nonNegativeClamped(usize, cache, "size")) |v| cfg.cache_size = v;
        if (try nonNegativeClamped(u32, cache, "entries")) |v| cfg.cache_entries = v;
        if (try nonNegativeClamped(usize, cache, "key-cache-size")) |v| cfg.key_cache_size = v;
        if (try nonNegativeClamped(u32, cache, "key-cache-entries")) |v| cfg.key_cache_entries = v;
        if (cache.getBool("prefetch")) |p| cfg.prefetch = p;
        if (cache.getBool("prefetch-cousin")) |p| cfg.prefetch_cousin = p;
        if (try nonNegativeClamped(u32, cache, "serve-stale-ttl")) |v| cfg.serve_stale_ttl = v;
        if (try nonNegativeClamped(u32, cache, "min-ttl")) |v| cfg.min_ttl = v;
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
    const sys = @import("sys.zig");
    const posix = std.posix;
    // Null-terminate path for openat syscall
    var path_buf: [4096]u8 = undefined;
    if (path.len >= path_buf.len) return error.NameTooLong;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const path_z: [*:0]const u8 = path_buf[0..path.len :0];
    const fd = try sys.open(path_z, posix.O{}, 0);
    defer sys.close(fd);

    var contents = std.ArrayList(u8).empty;
    defer contents.deinit(allocator);
    var read_buf: [4096]u8 = undefined;
    while (true) {
        const n = try sys.read(fd, &read_buf);
        if (n == 0) break;
        contents.appendSlice(allocator, read_buf[0..n]) catch return error.OutOfMemory;
        if (contents.items.len > 1024 * 1024) return error.OutOfMemory;
    }

    return parseConfig(allocator, contents.items);
}

fn parseAddressList(allocator: Allocator, strs: []const []const u8, default_port: u16, comptime err: ConfigError) ConfigError![]Address {
    const addrs = allocator.alloc(Address, strs.len) catch return error.OutOfMemory;
    errdefer allocator.free(addrs);

    for (strs, 0..) |s, i| {
        addrs[i] = parseAddress(s, default_port) orelse return err;
    }
    return addrs;
}

pub fn parseAddress(s: []const u8, default_port: u16) ?Address {
    // IPv6 with brackets: [::1]:53 or [::1]
    if (s.len > 0 and s[0] == '[') {
        const close = mem.indexOfScalar(u8, s, ']') orelse return null;
        const ip6_str = s[1..close];
        const port = if (close + 1 < s.len and s[close + 1] == ':')
            std.fmt.parseInt(u16, s[close + 2 ..], 10) catch return null
        else
            default_port;
        const ip6 = net_addr.Ip6.parse(ip6_str, port) catch return null;
        return net_addr.initIp6(ip6.bytes, port, 0, 0);
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
        return net_addr.initIp4(ip4, port);
    }

    if (colon_count > 1) {
        // Bare IPv6 without brackets
        const ip6 = net_addr.Ip6.parse(s, default_port) catch return null;
        return net_addr.initIp6(ip6.bytes, default_port, 0, 0);
    }

    // Plain IPv4 (no port)
    const ip4 = parseIpv4(s) orelse return null;
    return net_addr.initIp4(ip4, default_port);
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

test "prefetch-cousin defaults off and parses" {
    var cfg1 = try parseConfig(testing.allocator, "");
    defer cfg1.deinit();
    try testing.expectEqual(false, cfg1.prefetch_cousin);

    var cfg2 = try parseConfig(testing.allocator,
        \\[cache]
        \\prefetch-cousin = true
    );
    defer cfg2.deinit();
    try testing.expectEqual(true, cfg2.prefetch_cousin);
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
