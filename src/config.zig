const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const toml = @import("toml.zig");
const net_addr = @import("net_address.zig");
const Address = net_addr.Address;
const acl = @import("acl.zig");
const dns = @import("dns.zig");
const rebinding = @import("rebinding.zig");
const build_options = @import("build_options");

// ── ServerConfig ───────────────────────────────────────────────────────

pub const ServerConfig = struct {
    listen: []Address,
    /// Override IANA root hints. Empty means "use the compile-time
    /// defaults from recursive.root_hints_default". Tests redirect at
    /// scripted authoritatives via this; operators in split-horizon
    /// deployments point at private roots. Applied at boot — hark does
    /// not hot-reload config, and the cache starts empty on restart, so
    /// no invalidation path is needed when this value changes.
    root_hints: []Address,
    /// Default port for glue-extracted upstreams. Production is always 53;
    /// the field exists so tests can point at non-privileged scripted
    /// authoritatives. Parsing of `[resolver] upstream-port` is gated behind
    /// `-Dtesting=true`; production binaries reject the key.
    upstream_port: u16,
    /// Bypass the 127/8 rebinding-defense check on upstream addresses.
    /// Tests only. Parsing of `[resolver] allow-loopback-upstreams` is gated
    /// behind `-Dtesting=true`; production binaries reject the key.
    allow_loopback_upstreams: bool,
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
    case_randomization: bool,
    query_memory_limit: usize,
    opportunistic: bool,
    workers: u16,
    resolution_threads: u16,
    stagger_ms: u32,
    log_queries: bool,
    max_udp_payload: u16,
    /// uid to drop to after binding privileged ports. Numeric only — looking
    /// up names would need NSS / /etc/passwd parsing; deploy via systemd
    /// User=hark or pass the resolved uid.
    drop_uid: ?u32,
    drop_gid: ?u32,

    /// BCP 140: per-listener client ACL. Empty list means "no ACL" — every
    /// client allowed. Operators binding non-loopback addresses MUST set
    /// this or accept that they have an open recursive resolver.
    allow_from: []acl.Cidr,

    /// Operator policy: when true (default) responses to clients carry only
    /// load-bearing records (answer, SOA on negatives, DNSSEC proofs on DO=1
    /// / CD=1). When false, the wire shaper passes the upstream's authority
    /// and additional sections through unchanged except for the RFC 4035
    /// §3.2.3 DO=0 strip (which remains mandatory). Mirrors Unbound's
    /// `minimal-responses` knob (default-on since 1.7.x). See
    /// `~/Documents/hark-notes/response-shaping-2026-05-11.md` for the matrix.
    minimal_responses: bool,

    /// RFC 7766 §6.2.1: TCP idle timeout. Hark closes a TCP client
    /// connection after this many ms of inactivity. 5000 matches the
    /// previous hard-coded default; raise for long-lived stub clients.
    tcp_idle_timeout_ms: u32,
    /// Cap on queries served over a single TCP connection before the
    /// server closes it (load-shedding + memory bound).
    tcp_queries_per_conn: u32,
    /// Upstream TCP / DoT connection-pool idle timeout (seconds). Closes
    /// pooled connections to authoritatives after this much inactivity.
    upstream_tcp_idle_sec: i64,

    /// Override the IANA root trust anchors. Empty falls back to
    /// `dnssec.root_ds_records`. Test-only; `-Dtesting=true` gates the
    /// `[resolver] trust-anchors` config key.
    trust_anchors: []dns.DsData,

    /// DNS rebinding protection. Default-on; localhost (127/8) is the
    /// primary attack vector and excluding it would defeat the headline
    /// use case. DNSBL operators opt out via `extra_allow = ["127.0.0.0/8"]`.
    /// See `src/rebinding.zig` for the policy semantics and the built-in
    /// CIDR set.
    rebinding: rebinding.Config,

    allocator: Allocator,

    pub fn deinit(self: *ServerConfig) void {
        self.allocator.free(self.listen);
        self.allocator.free(self.root_hints);
        self.allocator.free(self.allow_from);
        for (self.trust_anchors) |ta| self.allocator.free(ta.digest);
        self.allocator.free(self.trust_anchors);
        for (self.rebinding.allow_zones) |zone| {
            for (zone.labels) |label| self.allocator.free(label);
            self.allocator.free(zone.labels);
        }
        self.allocator.free(self.rebinding.allow_zones);
        self.allocator.free(self.rebinding.extra_block);
        self.allocator.free(self.rebinding.extra_allow);
    }

    /// Effective root-hints slice for the recursor: config-supplied if any,
    /// else the compile-time IANA defaults. Centralized so every
    /// RecursiveResolver construction site picks the same fallback.
    pub fn rootHints(self: ServerConfig) []const Address {
        const recursive = @import("recursive.zig");
        return if (self.root_hints.len > 0) self.root_hints else &recursive.root_hints_default;
    }

    /// Effective root trust anchors: config-supplied if any, else the
    /// compile-time IANA defaults. The override is only reachable on
    /// `-Dtesting=true` builds — the production branch is elided at
    /// compile time so the IANA anchors are the sole reachable choice.
    pub fn trustAnchors(self: ServerConfig) []const dns.DsData {
        const dnssec = @import("dnssec.zig");
        if (comptime !build_options.testing_enabled) return &dnssec.root_ds_records;
        return if (self.trust_anchors.len > 0) self.trust_anchors else &dnssec.root_ds_records;
    }
};

pub const ConfigError = error{
    InvalidListenAddress,
    InvalidRootHintAddress,
    InvalidValue,
    InvalidWorkerCount,
    InvalidQueryMemoryLimit,
    InvalidAclEntry,
    /// Operator set a key gated behind `-Dtesting=true` in a production build.
    TestOnlyConfigKey,
    ConfigFileTooLarge,
    OutOfMemory,
};

// ── Defaults ───────────────────────────────────────────────────────────

fn defaultConfig(allocator: Allocator) ConfigError!ServerConfig {
    const listen = try allocator.alloc(Address, 2);
    errdefer allocator.free(listen);
    listen[0] = net_addr.initIp4(.{ 127, 0, 0, 1 }, 53);
    listen[1] = net_addr.initIp6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 53, 0, 0);

    const empty_root_hints = try allocator.alloc(Address, 0);
    const empty_acl = try allocator.alloc(acl.Cidr, 0);
    const empty_trust_anchors = try allocator.alloc(dns.DsData, 0);
    const empty_zones = try allocator.alloc(dns.Name, 0);
    const empty_extra_block = try allocator.alloc(acl.Cidr, 0);
    const empty_extra_allow = try allocator.alloc(acl.Cidr, 0);

    return .{
        .listen = listen,
        .root_hints = empty_root_hints,
        .upstream_port = 53,
        .allow_loopback_upstreams = false,
        .cache_size = 16 * 1024 * 1024,
        .cache_entries = 10_000,
        .key_cache_size = 4 * 1024 * 1024,
        .key_cache_entries = 2_000,
        .prefetch = false,
        .prefetch_cousin = true,
        .serve_stale_ttl = 0,
        .min_ttl = 0,
        .dnssec = true,
        .qname_minimization = true,
        .case_randomization = true,
        .query_memory_limit = 2 * 1024 * 1024,
        .opportunistic = false,
        // 2 workers is enough for most deployments. Each worker is one
        // io_uring ring; per-worker resolution-threads handle upstream
        // concurrency. Raise this for high-QPS edge resolvers — io_uring
        // drainage is rarely the bottleneck; resolution work dominates.
        .workers = 2,
        .resolution_threads = 4,
        .stagger_ms = 150,
        .log_queries = false,
        .max_udp_payload = @import("dns.zig").edns_udp_payload,
        .drop_uid = null,
        .drop_gid = null,
        .allow_from = empty_acl,
        .minimal_responses = true,
        .tcp_idle_timeout_ms = 5_000,
        .tcp_queries_per_conn = 128,
        .upstream_tcp_idle_sec = 30,
        .trust_anchors = empty_trust_anchors,
        .rebinding = .{
            .enabled = true,
            .allow_zones = empty_zones,
            .extra_block = empty_extra_block,
            .extra_allow = empty_extra_allow,
        },
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
            const new_listen = try parseAddressList(allocator, addrs, 53, error.InvalidListenAddress);
            allocator.free(cfg.listen);
            cfg.listen = new_listen;
        }
        if (server.getInteger("workers")) |w| {
            if (w < 1 or w > 65535) return error.InvalidWorkerCount;
            cfg.workers = @intCast(w);
        }
        if (server.getInteger("resolution-threads")) |rt| {
            if (rt < 1 or rt > 256) return error.InvalidWorkerCount;
            cfg.resolution_threads = @intCast(rt);
        }
        if (server.getInteger("max-udp-payload")) |m| {
            const dns_mod = @import("dns.zig");
            if (m < dns_mod.max_udp_payload or m > dns_mod.max_message_len) return error.InvalidValue;
            cfg.max_udp_payload = @intCast(m);
        }
        if (try nonNegativeClamped(u32, server, "user")) |u| cfg.drop_uid = u;
        if (try nonNegativeClamped(u32, server, "group")) |g| cfg.drop_gid = g;
        if (server.getStringArray("allow-from")) |entries| {
            const new_allow = try parseCidrList(allocator, entries);
            allocator.free(cfg.allow_from);
            cfg.allow_from = new_allow;
        }
        if (try nonNegativeClamped(u32, server, "tcp-idle-timeout-ms")) |v| {
            // RFC 7828 §3.4 caps the wire TIMEOUT field (100-ms units) at u16.
            // Reject configs that would overflow the @intCast at emit time.
            if (v > 6_553_500) return error.InvalidValue;
            cfg.tcp_idle_timeout_ms = v;
        }
        if (try nonNegativeClamped(u32, server, "tcp-queries-per-conn")) |v| {
            if (v == 0) return error.InvalidValue;
            cfg.tcp_queries_per_conn = v;
        }
        if (try nonNegativeClamped(u32, server, "upstream-tcp-idle-sec")) |v| cfg.upstream_tcp_idle_sec = @intCast(v);
        if (server.getBool("minimal-responses")) |m| cfg.minimal_responses = m;
    }

    // [resolver] section
    if (parsed.table.getTable("resolver")) |resolver| {
        if (resolver.getStringArray("root-hints")) |addrs| {
            const new_hints = try parseAddressList(allocator, addrs, 53, error.InvalidRootHintAddress);
            allocator.free(cfg.root_hints);
            cfg.root_hints = new_hints;
        }
        // Test-only knobs. Each is gated by `build_options.testing_enabled`
        // so a production binary refuses the key — adding a new one means
        // adding one block, not synchronizing two branches.
        if (resolver.getInteger("upstream-port")) |p| {
            if (!build_options.testing_enabled) return error.TestOnlyConfigKey;
            if (p < 1 or p > 65535) return error.InvalidValue;
            cfg.upstream_port = @intCast(p);
        }
        if (resolver.getBool("allow-loopback-upstreams")) |b| {
            if (!build_options.testing_enabled) return error.TestOnlyConfigKey;
            cfg.allow_loopback_upstreams = b;
        }
        if (resolver.getStringArray("trust-anchors")) |entries| {
            if (!build_options.testing_enabled) return error.TestOnlyConfigKey;
            const new_anchors = try parseTrustAnchors(allocator, entries);
            allocator.free(cfg.trust_anchors);
            cfg.trust_anchors = new_anchors;
        }
        if (resolver.getBool("dnssec")) |d| cfg.dnssec = d;
        if (resolver.getBool("qname-minimization")) |q| cfg.qname_minimization = q;
        if (resolver.getBool("case-randomization")) |c| cfg.case_randomization = c;
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

    // [rebinding] section
    if (parsed.table.getTable("rebinding")) |reb| {
        if (reb.getBool("enabled")) |b| cfg.rebinding.enabled = b;
        if (reb.getStringArray("allow-zones")) |entries| {
            const new_zones = try parseZoneList(allocator, entries);
            for (cfg.rebinding.allow_zones) |zone| {
                for (zone.labels) |label| allocator.free(label);
                allocator.free(zone.labels);
            }
            allocator.free(cfg.rebinding.allow_zones);
            cfg.rebinding.allow_zones = new_zones;
        }
        if (reb.getStringArray("extra-block")) |entries| {
            const new_block = try parseCidrList(allocator, entries);
            allocator.free(cfg.rebinding.extra_block);
            cfg.rebinding.extra_block = new_block;
        }
        if (reb.getStringArray("extra-allow")) |entries| {
            const new_allow = try parseCidrList(allocator, entries);
            allocator.free(cfg.rebinding.extra_allow);
            cfg.rebinding.extra_allow = new_allow;
        }
    }

    // Root hints in 127/8 / private space create a self-referencing or
    // loopback-targeting recursor — a class of operator footgun that the
    // glue-time rebinding defence already blocks for delegated NSes. Reject
    // unless the operator opted in via allow-loopback-upstreams (tests do).
    if (!cfg.allow_loopback_upstreams) {
        for (cfg.root_hints) |addr| {
            if (net_addr.isNonRoutableNs(addr)) return error.InvalidRootHintAddress;
        }
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
        try contents.appendSlice(allocator, read_buf[0..n]);
        if (contents.items.len > 1024 * 1024) return error.ConfigFileTooLarge;
    }

    return parseConfig(allocator, contents.items);
}

/// Parse a list of trust-anchor strings in the form
/// `"<key-tag> <algorithm> <digest-type> <hex-digest>"` (whitespace-delimited).
/// All four fields are required. Algorithm and digest-type are decimal IANA
/// numbers (e.g. `8` = RSA/SHA-256, `2` = SHA-256). Owner name is implicit
/// root — the override targets the same anchor slot as `dnssec.root_ds_records`.
fn parseTrustAnchors(allocator: Allocator, strs: []const []const u8) ConfigError![]dns.DsData {
    const list = try allocator.alloc(dns.DsData, strs.len);
    var i: usize = 0;
    errdefer {
        for (list[0..i]) |ta| allocator.free(ta.digest);
        allocator.free(list);
    }
    while (i < strs.len) : (i += 1) {
        list[i] = try parseTrustAnchor(allocator, strs[i]);
    }
    return list;
}

fn parseTrustAnchor(allocator: Allocator, s: []const u8) ConfigError!dns.DsData {
    var it = mem.tokenizeAny(u8, s, " \t");
    const tag_str = it.next() orelse return error.InvalidValue;
    const alg_str = it.next() orelse return error.InvalidValue;
    const dtype_str = it.next() orelse return error.InvalidValue;
    const digest_str = it.next() orelse return error.InvalidValue;
    if (it.next() != null) return error.InvalidValue;

    const key_tag = std.fmt.parseInt(u16, tag_str, 10) catch return error.InvalidValue;
    const alg_int = std.fmt.parseInt(u8, alg_str, 10) catch return error.InvalidValue;
    const dtype_int = std.fmt.parseInt(u8, dtype_str, 10) catch return error.InvalidValue;
    // Reject unknown algorithm/digest-type at parse time. Both enums are
    // open (`_` trailing) so a typo in test configs would otherwise reach
    // the validator and surface as a cryptic SERVFAIL instead of a clear
    // config error.
    // Both enums are open (`_` trailing) so @enumFromInt accepts any u8;
    // tagName returns null for values that don't match a named variant —
    // the cheapest known-variant check for this shape.
    const algorithm: dns.DnssecAlgorithm = @enumFromInt(alg_int);
    if (std.enums.tagName(dns.DnssecAlgorithm, algorithm) == null) return error.InvalidValue;
    const digest_type: dns.DigestType = @enumFromInt(dtype_int);
    if (std.enums.tagName(dns.DigestType, digest_type) == null) return error.InvalidValue;
    if (digest_str.len % 2 != 0) return error.InvalidValue;
    const digest_len = digest_str.len / 2;
    // RFC 4034 §5.1.4 + RFC 6605 §3: digest length is fixed per digest type.
    const expected_len: usize = switch (digest_type) {
        .sha1 => 20,
        .sha256 => 32,
        .sha384 => 48,
        _ => unreachable, // tagName check above rejected unknown variants
    };
    if (digest_len != expected_len) return error.InvalidValue;

    const digest = try allocator.alloc(u8, digest_len);
    errdefer allocator.free(digest);
    _ = std.fmt.hexToBytes(digest, digest_str) catch return error.InvalidValue;

    return .{
        .key_tag = key_tag,
        .algorithm = algorithm,
        .digest_type = digest_type,
        .digest = digest,
    };
}

fn parseZoneList(allocator: Allocator, strs: []const []const u8) ConfigError![]dns.Name {
    const list = try allocator.alloc(dns.Name, strs.len);
    var i: usize = 0;
    errdefer {
        for (list[0..i]) |zone| {
            for (zone.labels) |label| allocator.free(label);
            allocator.free(zone.labels);
        }
        allocator.free(list);
    }
    while (i < strs.len) : (i += 1) {
        // Reject empty and root zone: `parseDottedName` accepts both as the
        // zero-label name, and `isSubdomainOf` treats the zero-label parent
        // as matching every RR — so a typo like `allow-zones = [""]` would
        // silently disable rebinding protection entirely. Fail loudly.
        if (strs[i].len == 0 or mem.eql(u8, strs[i], ".")) return error.InvalidValue;
        list[i] = dns.parseDottedName(allocator, strs[i]) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // Any other dns parse error (invalid label, name too long, …)
            // surfaces as InvalidValue — operators editing TOML need a clear
            // signal, not a dns-internal error variant.
            else => return error.InvalidValue,
        };
    }
    return list;
}

fn parseCidrList(allocator: Allocator, strs: []const []const u8) ConfigError![]acl.Cidr {
    const list = try allocator.alloc(acl.Cidr, strs.len);
    errdefer allocator.free(list);
    for (strs, 0..) |s, i| {
        list[i] = acl.parse(s) orelse return error.InvalidAclEntry;
    }
    return list;
}

fn parseAddressList(allocator: Allocator, strs: []const []const u8, default_port: u16, comptime err: ConfigError) ConfigError![]Address {
    const addrs = try allocator.alloc(Address, strs.len);
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

    // First vs last colon distinguish the three remaining shapes:
    //   no colons     → bare IPv4
    //   one colon     → IPv4:port (first == last)
    //   many colons   → bare IPv6 (first != last)
    const first = mem.indexOfScalar(u8, s, ':');
    const last = mem.lastIndexOfScalar(u8, s, ':');

    if (first) |f| {
        if (f == last.?) {
            const port = std.fmt.parseInt(u16, s[f + 1 ..], 10) catch return null;
            const ip4 = parseIpv4(s[0..f]) orelse return null;
            return net_addr.initIp4(ip4, port);
        }
        const ip6 = net_addr.Ip6.parse(s, default_port) catch return null;
        return net_addr.initIp6(ip6.bytes, default_port, 0, 0);
    }

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
    try testing.expectEqual(@as(usize, 16 * 1024 * 1024), cfg.cache_size);
    try testing.expectEqual(@as(u32, 10_000), cfg.cache_entries);
    try testing.expectEqual(true, cfg.dnssec);
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
    try testing.expectEqual(true, cfg.dnssec);
    try testing.expectEqual(false, cfg.qname_minimization);
    try testing.expectEqual(@as(usize, 8388608), cfg.cache_size);
    try testing.expectEqual(@as(u32, 5000), cfg.cache_entries);
}

test "empty config uses defaults" {
    var cfg = try parseConfig(testing.allocator, "");
    defer cfg.deinit();

    try testing.expectEqual(@as(usize, 2), cfg.listen.len);
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

// Regression: parseConfig used to free `cfg.listen` then `try parseAddressList`,
// so a malformed address left a dangling slice that cfg.deinit double-freed.
// `listen` is the only field with a non-empty default, so it's the only site
// where testing.allocator actually trips on the bug — the sibling fields parse
// into zero-length defaults whose double-free is a stdlib no-op.
test "malformed listen does not double-free default" {
    try testing.expectError(
        error.InvalidListenAddress,
        parseConfig(testing.allocator, "[server]\nlisten = [\"999.999.999.999:53\"]\n"),
    );
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

test "tcp idle/queries/upstream knobs parse and validate" {
    var cfg = try parseConfig(testing.allocator,
        \\[server]
        \\tcp-idle-timeout-ms = 8000
        \\tcp-queries-per-conn = 64
        \\upstream-tcp-idle-sec = 45
    );
    defer cfg.deinit();
    try testing.expectEqual(@as(u32, 8000), cfg.tcp_idle_timeout_ms);
    try testing.expectEqual(@as(u32, 64), cfg.tcp_queries_per_conn);
    try testing.expectEqual(@as(i64, 45), cfg.upstream_tcp_idle_sec);

    // Zero queries-per-conn would loop forever; parser must reject.
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\tcp-queries-per-conn = 0
    ));

    // RFC 7828 §3.4 caps the wire TIMEOUT field at u16 (100-ms units);
    // reject configs that would overflow the @intCast at emit time.
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\tcp-idle-timeout-ms = 7000000
    ));
}

test "prefetch-cousin defaults on and parses" {
    var cfg1 = try parseConfig(testing.allocator, "");
    defer cfg1.deinit();
    try testing.expectEqual(true, cfg1.prefetch_cousin);

    var cfg2 = try parseConfig(testing.allocator,
        \\[cache]
        \\prefetch-cousin = false
    );
    defer cfg2.deinit();
    try testing.expectEqual(false, cfg2.prefetch_cousin);
}

test "rebinding defaults are safe (enabled, empty extras)" {
    var cfg = try parseConfig(testing.allocator, "");
    defer cfg.deinit();
    try testing.expectEqual(true, cfg.rebinding.enabled);
    try testing.expectEqual(@as(usize, 0), cfg.rebinding.allow_zones.len);
    try testing.expectEqual(@as(usize, 0), cfg.rebinding.extra_block.len);
    try testing.expectEqual(@as(usize, 0), cfg.rebinding.extra_allow.len);
}

test "rebinding rejects empty / root zone in allow_zones (would silently disable scrub)" {
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[rebinding]
        \\allow-zones = [""]
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[rebinding]
        \\allow-zones = ["."]
    ));
    try testing.expectError(error.InvalidAclEntry, parseConfig(testing.allocator,
        \\[rebinding]
        \\extra-block = ["not-a-cidr"]
    ));
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

test "trust-anchors override parses and round-trips" {
    if (!build_options.testing_enabled) return;
    var cfg = try parseConfig(testing.allocator,
        \\[resolver]
        \\trust-anchors = ["20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]
    );
    defer cfg.deinit();

    try testing.expectEqual(@as(usize, 1), cfg.trust_anchors.len);
    const ta = cfg.trust_anchors[0];
    try testing.expectEqual(@as(u16, 20326), ta.key_tag);
    try testing.expectEqual(@as(u8, 8), @intFromEnum(ta.algorithm));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(ta.digest_type));
    try testing.expectEqual(@as(usize, 32), ta.digest.len);

    // Accessor returns config-supplied when non-empty.
    const eff = cfg.trustAnchors();
    try testing.expectEqual(@as(usize, 1), eff.len);
    try testing.expectEqual(@as(u16, 20326), eff[0].key_tag);
}

test "trust-anchors accessor falls back to IANA defaults when empty" {
    var cfg = try parseConfig(testing.allocator, "");
    defer cfg.deinit();
    const dnssec = @import("dnssec.zig");
    const eff = cfg.trustAnchors();
    try testing.expectEqual(dnssec.root_ds_records.len, eff.len);
    try testing.expectEqual(dnssec.root_ds_records[0].key_tag, eff[0].key_tag);
}

test "trust-anchors rejects malformed entries" {
    if (!build_options.testing_enabled) return;
    // Odd-length hex
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\trust-anchors = ["20326 8 2 ABC"]
    ));
    // Missing field
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\trust-anchors = ["20326 8 2"]
    ));
    // Extra field
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\trust-anchors = ["20326 8 2 AB EXTRA"]
    ));
    // Non-hex digest
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\trust-anchors = ["20326 8 2 ZZZZ"]
    ));
    // Unknown algorithm (255 is reserved/unassigned per IANA DNSSEC alg registry)
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\trust-anchors = ["20326 255 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]
    ));
    // Unknown digest type
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\trust-anchors = ["20326 8 99 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]
    ));
    // 16-byte digest is too short for any standard digest type
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\trust-anchors = ["20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D084"]
    ));
    // Digest length doesn't match digest type (SHA-256 declared, 20-byte SHA-1 supplied)
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\trust-anchors = ["20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E88040"]
    ));
}

test "test-only knobs gated on -Dtesting" {
    const cfg_text =
        \\[resolver]
        \\upstream-port = 5353
        \\allow-loopback-upstreams = true
        \\trust-anchors = ["20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]
    ;
    if (build_options.testing_enabled) {
        var cfg = try parseConfig(testing.allocator, cfg_text);
        defer cfg.deinit();
        try testing.expectEqual(@as(u16, 5353), cfg.upstream_port);
        try testing.expectEqual(true, cfg.allow_loopback_upstreams);
        try testing.expectEqual(@as(usize, 1), cfg.trust_anchors.len);
    } else {
        try testing.expectError(error.TestOnlyConfigKey, parseConfig(testing.allocator, cfg_text));
    }
}
