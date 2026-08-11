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

/// Error variants can't carry the offending key name, so log it at rejection
/// time. Silent under test: the schema tests trigger these intentionally and
/// the test runner fails on error-level logs.
fn errLog(comptime fmt: []const u8, args: anytype) void {
    if (@import("builtin").is_test) return;
    std.log.err(fmt, args);
}

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
    /// Hot-set expiry refresh: names re-demanded after death earn a
    /// refresh lease (see server.zig HotSet). Covers the query-interval >
    /// TTL demand that `prefetch`'s hit-time window structurally misses.
    prefetch_hot: bool,
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
    /// `minimal-responses` knob (default-on since 1.7.x). The full keep/strip
    /// matrix is implemented and documented in `response.zig:shapeResponse`.
    minimal_responses: bool,

    /// RFC 7766 §6.2.3: TCP idle timeout. Hark closes a TCP client
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

const ConfigError = error{
    InvalidListenAddress,
    InvalidRootHintAddress,
    InvalidValue,
    InvalidWorkerCount,
    InvalidQueryMemoryLimit,
    InvalidAclEntry,
    /// Operator set a key gated behind `-Dtesting=true` in a production build.
    TestOnlyConfigKey,
    /// Key or section not in the schema — almost always a typo. Fail loud
    /// rather than silently serve with the default.
    UnknownConfigKey,
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
        .prefetch_hot = false,
        .serve_stale_ttl = 0,
        .min_ttl = 0,
        .dnssec = true,
        .qname_minimization = true,
        .case_randomization = true,
        .query_memory_limit = 1024 * 1024,
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

// ── Schema ─────────────────────────────────────────────────────────────
// Every key the parser reads, with its expected TOML type — validated before
// parsing so a typo'd key or wrong-typed value (`dnssec = "true"`) errors
// instead of silently keeping the default. Test-only keys are listed too;
// their `-Dtesting` gate stays in the parser for the distinct error.

const KeySpec = struct { name: []const u8, kind: std.meta.Tag(toml.Value) };
const SectionSpec = struct { name: []const u8, keys: []const KeySpec };

const config_schema = [_]SectionSpec{
    .{ .name = "server", .keys = &.{
        .{ .name = "listen", .kind = .string_array },
        .{ .name = "workers", .kind = .integer },
        .{ .name = "resolution-threads", .kind = .integer },
        .{ .name = "max-udp-payload", .kind = .integer },
        .{ .name = "user", .kind = .integer },
        .{ .name = "group", .kind = .integer },
        .{ .name = "allow-from", .kind = .string_array },
        .{ .name = "tcp-idle-timeout-ms", .kind = .integer },
        .{ .name = "tcp-queries-per-conn", .kind = .integer },
        .{ .name = "upstream-tcp-idle-sec", .kind = .integer },
        .{ .name = "minimal-responses", .kind = .boolean },
    } },
    .{ .name = "resolver", .keys = &.{
        .{ .name = "root-hints", .kind = .string_array },
        .{ .name = "upstream-port", .kind = .integer },
        .{ .name = "allow-loopback-upstreams", .kind = .boolean },
        .{ .name = "trust-anchors", .kind = .string_array },
        .{ .name = "dnssec", .kind = .boolean },
        .{ .name = "qname-minimization", .kind = .boolean },
        .{ .name = "case-randomization", .kind = .boolean },
        .{ .name = "opportunistic", .kind = .boolean },
        .{ .name = "query-memory-limit", .kind = .integer },
        .{ .name = "stagger-ms", .kind = .integer },
    } },
    .{ .name = "cache", .keys = &.{
        .{ .name = "size", .kind = .integer },
        .{ .name = "entries", .kind = .integer },
        .{ .name = "key-cache-size", .kind = .integer },
        .{ .name = "key-cache-entries", .kind = .integer },
        .{ .name = "prefetch", .kind = .boolean },
        .{ .name = "prefetch-cousin", .kind = .boolean },
        .{ .name = "prefetch-hot", .kind = .boolean },
        .{ .name = "serve-stale-ttl", .kind = .integer },
        .{ .name = "min-ttl", .kind = .integer },
    } },
    .{ .name = "logging", .keys = &.{
        .{ .name = "queries", .kind = .boolean },
    } },
    .{ .name = "rebinding", .keys = &.{
        .{ .name = "enabled", .kind = .boolean },
        .{ .name = "allow-zones", .kind = .string_array },
        .{ .name = "extra-block", .kind = .string_array },
        .{ .name = "extra-allow", .kind = .string_array },
    } },
};

fn validateSchema(root: toml.Table) ConfigError!void {
    var sections = root.map.iterator();
    while (sections.next()) |entry| {
        const section_name = entry.key_ptr.*;
        const spec = for (config_schema) |s| {
            if (mem.eql(u8, s.name, section_name)) break s;
        } else {
            errLog("config: unknown section [{s}]", .{section_name});
            return error.UnknownConfigKey;
        };
        const table = switch (entry.value_ptr.*) {
            .table => |t| t,
            else => {
                errLog("config: top-level key '{s}' — every setting lives under a [section]", .{section_name});
                return error.UnknownConfigKey;
            },
        };
        var keys = table.map.iterator();
        while (keys.next()) |kv| {
            const key = kv.key_ptr.*;
            const kspec = for (spec.keys) |k| {
                if (mem.eql(u8, k.name, key)) break k;
            } else {
                errLog("config: unknown key '{s}' in [{s}]", .{ key, section_name });
                return error.UnknownConfigKey;
            };
            if (kv.value_ptr.* != kspec.kind) {
                errLog("config: [{s}] {s} expects {s}, got {s}", .{
                    section_name, key, @tagName(kspec.kind), @tagName(kv.value_ptr.*),
                });
                return error.InvalidValue;
            }
        }
    }
}

/// Upper bound for [resolver] stagger-ms. Staggering upstream probes by more
/// than a second would exceed most stub resolvers' own patience.
const max_stagger_ms: u32 = 1000;

// ── Parser ─────────────────────────────────────────────────────────────

/// Out-of-range is rejected, not clamped: silent folding to `maxInt(T)`
/// contradicts the strict schema the rest of this parser enforces, and it hid
/// a footgun — `user = <huge>` clamped to `(uid_t)-1`, setresuid's "leave
/// unchanged" sentinel, so the drop silently did nothing and reported success.
fn nonNegative(comptime T: type, table: toml.Table, key: []const u8) ConfigError!?T {
    const v = table.getInteger(key) orelse return null;
    if (v < 0) {
        errLog("config: {s} must not be negative, got {d}", .{ key, v });
        return error.InvalidValue;
    }
    if (v > std.math.maxInt(T)) {
        errLog("config: {s} must be at most {d}, got {d}", .{ key, std.math.maxInt(T), v });
        return error.InvalidValue;
    }
    return @intCast(v);
}

/// Neither `(uid_t)-1` (setresuid's "leave unchanged" sentinel) nor 0 is an id
/// worth dropping to; both make the drop a no-op that reports success.
fn credential(table: toml.Table, key: []const u8) ConfigError!?u32 {
    const v = try nonNegative(u32, table, key) orelse return null;
    if (v == std.math.maxInt(u32)) {
        errLog("config: {s} must be a real id, got the 'unchanged' sentinel {d}", .{ key, v });
        return error.InvalidValue;
    }
    // 0 reaches the same no-op by a likelier route than the sentinel: a
    // template substituting an unset variable. Dropping *to* root is not
    // something these keys can express; omitting them is how you stay put.
    if (v == 0) {
        errLog("config: {s} must not be 0 — omit the key to run as the current user", .{key});
        return error.InvalidValue;
    }
    return v;
}

pub fn parseConfig(allocator: Allocator, contents: []const u8) (toml.ParseError || ConfigError)!ServerConfig {
    var parsed = try toml.parse(allocator, contents);
    defer parsed.deinit();

    try validateSchema(parsed.table);

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
            if (w < 1 or w > 65535) {
                errLog("config: workers must be 1-65535, got {d}", .{w});
                return error.InvalidWorkerCount;
            }
            cfg.workers = @intCast(w);
        }
        if (server.getInteger("resolution-threads")) |rt| {
            if (rt < 1 or rt > 256) {
                errLog("config: resolution-threads must be 1-256, got {d}", .{rt});
                return error.InvalidWorkerCount;
            }
            cfg.resolution_threads = @intCast(rt);
        }
        if (server.getInteger("max-udp-payload")) |m| {
            const dns_mod = @import("dns.zig");
            if (m < dns_mod.max_udp_payload or m > dns_mod.max_message_len) {
                errLog("config: max-udp-payload must be {d}-{d}, got {d}", .{ dns_mod.max_udp_payload, dns_mod.max_message_len, m });
                return error.InvalidValue;
            }
            cfg.max_udp_payload = @intCast(m);
        }
        if (try credential(server, "user")) |u| cfg.drop_uid = u;
        if (try credential(server, "group")) |g| cfg.drop_gid = g;
        if (server.getStringArray("allow-from")) |entries| {
            const new_allow = try parseCidrList(allocator, entries);
            allocator.free(cfg.allow_from);
            cfg.allow_from = new_allow;
        }
        if (try nonNegative(u32, server, "tcp-idle-timeout-ms")) |v| {
            // RFC 7828 §3.1 caps the wire TIMEOUT field (100-ms units) at u16.
            // Reject configs that would overflow the @intCast at emit time.
            if (v > 6_553_500) {
                errLog("config: tcp-idle-timeout-ms must be at most 6553500, got {d}", .{v});
                return error.InvalidValue;
            }
            cfg.tcp_idle_timeout_ms = v;
        }
        if (try nonNegative(u32, server, "tcp-queries-per-conn")) |v| {
            if (v == 0) {
                errLog("config: tcp-queries-per-conn must not be 0", .{});
                return error.InvalidValue;
            }
            cfg.tcp_queries_per_conn = v;
        }
        if (try nonNegative(u32, server, "upstream-tcp-idle-sec")) |v| cfg.upstream_tcp_idle_sec = @intCast(v);
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
        if (try nonNegative(usize, resolver, "query-memory-limit")) |val| {
            if (val != 0 and val < 65536) return error.InvalidQueryMemoryLimit;
            // 0 = unlimited. Resolve the sentinel here so every cap site (worker
            // arena, NS-fanout helpers, bg-prefetch) honors it uniformly.
            cfg.query_memory_limit = if (val == 0) std.math.maxInt(usize) else val;
        }
        if (try nonNegative(u32, resolver, "stagger-ms")) |v| {
            // Rejected rather than clamped, for the same reason as the range
            // check itself: `stagger-ms = 5000` meant 5 seconds to whoever
            // wrote it.
            if (v > max_stagger_ms) {
                errLog("config: stagger-ms must be at most {d}, got {d}", .{ max_stagger_ms, v });
                return error.InvalidValue;
            }
            cfg.stagger_ms = v;
        }
    }

    // [cache] section
    if (parsed.table.getTable("cache")) |cache| {
        if (try nonNegative(usize, cache, "size")) |v| cfg.cache_size = v;
        if (try nonNegative(u32, cache, "entries")) |v| cfg.cache_entries = v;
        if (try nonNegative(usize, cache, "key-cache-size")) |v| cfg.key_cache_size = v;
        if (try nonNegative(u32, cache, "key-cache-entries")) |v| cfg.key_cache_entries = v;
        if (cache.getBool("prefetch")) |p| cfg.prefetch = p;
        if (cache.getBool("prefetch-cousin")) |p| cfg.prefetch_cousin = p;
        if (cache.getBool("prefetch-hot")) |p| cfg.prefetch_hot = p;
        if (try nonNegative(u32, cache, "serve-stale-ttl")) |v| cfg.serve_stale_ttl = v;
        if (try nonNegative(u32, cache, "min-ttl")) |v| cfg.min_ttl = v;
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

pub fn parseConfigFile(allocator: Allocator, io: std.Io, path: []const u8) !ServerConfig {
    const contents = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024)) catch |err| switch (err) {
        error.StreamTooLong => return error.ConfigFileTooLarge,
        else => |e| return e,
    };
    defer allocator.free(contents);
    return parseConfig(allocator, contents);
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
    // open (`_` trailing) so @enumFromInt accepts any u8; an unchecked typo
    // would surface as a cryptic SERVFAIL instead of a clear config error.
    // tagName returns null for values that don't match a named variant —
    // the cheapest known-variant check for this shape.
    const algorithm: dns.DnssecAlgorithm = @fromBackingInt(@intCast(alg_int));
    if (std.enums.tagName(dns.DnssecAlgorithm, algorithm) == null) return error.InvalidValue;
    const digest_type: dns.DigestType = @fromBackingInt(@intCast(dtype_int));
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
        if (strs[i].len == 0 or mem.eql(u8, strs[i], ".")) {
            errLog("config: allow-zones entry must name a zone, got '{s}'", .{strs[i]});
            return error.InvalidValue;
        }
        list[i] = dns.parseDottedName(allocator, strs[i]) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // Any other dns parse error (invalid label, name too long, …)
            // surfaces as InvalidValue — operators editing TOML need a clear
            // signal, not a dns-internal error variant.
            else => {
                errLog("config: invalid zone name '{s}'", .{strs[i]});
                return error.InvalidValue;
            },
        };
    }
    return list;
}

fn parseCidrList(allocator: Allocator, strs: []const []const u8) ConfigError![]acl.Cidr {
    const list = try allocator.alloc(acl.Cidr, strs.len);
    errdefer allocator.free(list);
    for (strs, 0..) |s, i| {
        list[i] = acl.parse(s) orelse {
            errLog("config: invalid CIDR entry '{s}'", .{s});
            return error.InvalidAclEntry;
        };
    }
    return list;
}

fn parseAddressList(allocator: Allocator, strs: []const []const u8, default_port: u16, comptime err: ConfigError) ConfigError![]Address {
    const addrs = try allocator.alloc(Address, strs.len);
    errdefer allocator.free(addrs);

    for (strs, 0..) |s, i| {
        addrs[i] = parseAddress(s, default_port) orelse {
            errLog("config: invalid address '{s}'", .{s});
            return err;
        };
    }
    return addrs;
}

fn parseAddress(s: []const u8, default_port: u16) ?Address {
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
            const ip4 = std.Io.net.Ip4Address.parse(s[0..f], port) catch return null;
            return .{ .ip4 = ip4 };
        }
        const ip6 = net_addr.Ip6.parse(s, default_port) catch return null;
        return net_addr.initIp6(ip6.bytes, default_port, 0, 0);
    }

    // Same strict dotted-quad grammar as acl.zig's allow-from parsing —
    // one config file, one IPv4 grammar.
    const ip4 = std.Io.net.Ip4Address.parse(s, default_port) catch return null;
    return .{ .ip4 = ip4 };
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

test "prefetch-hot defaults off and parses" {
    var cfg1 = try parseConfig(testing.allocator, "");
    defer cfg1.deinit();
    try testing.expectEqual(false, cfg1.prefetch_hot);

    var cfg2 = try parseConfig(testing.allocator,
        \\[cache]
        \\prefetch-hot = true
    );
    defer cfg2.deinit();
    try testing.expectEqual(true, cfg2.prefetch_hot);
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

    // RFC 7828 §3.1 caps the wire TIMEOUT field at u16 (100-ms units);
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

test "unknown key rejected, not silently ignored" {
    try testing.expectError(error.UnknownConfigKey, parseConfig(testing.allocator,
        \\[server]
        \\worker = 4
    ));
    try testing.expectError(error.UnknownConfigKey, parseConfig(testing.allocator,
        \\[resolvers]
        \\dnssec = true
    ));
    // Underscore instead of dash — the most likely real-world typo.
    try testing.expectError(error.UnknownConfigKey, parseConfig(testing.allocator,
        \\[resolver]
        \\qname_minimization = false
    ));
    // Top-level key outside any section.
    try testing.expectError(error.UnknownConfigKey, parseConfig(testing.allocator,
        \\dnssec = true
    ));
}

test "wrong-typed key rejected, default must not silently win" {
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\dnssec = "true"
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[rebinding]
        \\allow-zones = "homelab.lan"
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\workers = "2"
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
    try testing.expectEqual(@as(u8, 8), @backingInt(ta.algorithm));
    try testing.expectEqual(@as(u8, 2), @backingInt(ta.digest_type));
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

test "an out-of-range integer is rejected, never clamped" {
    // Regression: the parser used to fold anything larger down to
    // maxInt(u32). For `user` that is 4294967295 == (uid_t)-1, setresuid's
    // "leave unchanged" sentinel — the kernel returns success and hark
    // logged that it had dropped privileges while still running as root.
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\user = 99999999999
    ));
    // Written literally, the sentinel is just as wrong.
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\user = 4294967295
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\group = 4294967295
    ));
    // 0 reaches the same false "dropped user to uid=0" log by a much likelier
    // route: a template substituting an unset variable. setresuid(0,0,0)
    // succeeds trivially, so the report would be a lie while still root.
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\user = 0
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\group = 0
    ));
    // Semantic limits are rejected too, not silently clamped: stagger-ms = 5000
    // meant five seconds to whoever wrote it.
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\stagger-ms = 5000
    ));
    // Not credential-specific: silent clamping contradicts the strict schema
    // everywhere, so every nonNegative caller rejects too.
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[cache]
        \\entries = 99999999999
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[cache]
        \\min-ttl = 4294967296
    ));

    // Real ids still parse, including the largest legitimate one.
    var cfg = try parseConfig(testing.allocator,
        \\[server]
        \\user = 4294967294
        \\group = 65534
    );
    defer cfg.deinit();
    try testing.expectEqual(@as(?u32, 4294967294), cfg.drop_uid);
    try testing.expectEqual(@as(?u32, 65534), cfg.drop_gid);
}

/// Exercises every allocating key at once: the address, CIDR, zone and
/// trust-anchor list parsers, plus `defaultConfig`'s own allocations, which
/// each overriding key frees and replaces — the ordering most likely to
/// double-free or strand a slice when an allocation midway through fails.
fn parseConfigOomProbe(allocator: Allocator, contents: []const u8) !void {
    var cfg = try parseConfig(allocator, contents);
    cfg.deinit();
}

test "parseConfig handles OOM without leaking" {
    const contents =
        \\[server]
        \\listen = ["127.0.0.1:8053", "[::1]:8053"]
        \\allow-from = ["127.0.0.0/8", "10.0.0.0/8"]
        \\
        \\[resolver]
        \\root-hints = ["198.41.0.4:53", "199.9.14.201:53"]
        \\
        \\[rebinding]
        \\enabled = true
        \\allow-zones = ["home.arpa", "lan"]
        \\extra-block = ["192.0.2.0/24"]
        \\extra-allow = ["203.0.113.0/24"]
    ;
    try testing.checkAllAllocationFailures(testing.allocator, parseConfigOomProbe, .{contents});
}

/// `trust-anchors` is gated behind `-Dtesting=true`, so `parseConfig` cannot
/// reach `parseTrustAnchors` in a default test build. Probe it directly:
/// it allocates the list, then a digest per entry, and unwinds both.
fn parseTrustAnchorsOomProbe(allocator: Allocator, strs: []const []const u8) !void {
    const anchors = try parseTrustAnchors(allocator, strs);
    for (anchors) |ta| allocator.free(ta.digest);
    allocator.free(anchors);
}

test "parseTrustAnchors handles OOM without leaking" {
    const strs = [_][]const u8{
        "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        "19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5",
    };
    try testing.checkAllAllocationFailures(testing.allocator, parseTrustAnchorsOomProbe, .{&strs});
}
