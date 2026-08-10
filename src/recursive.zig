const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");
const special_use = @import("special_use.zig");
const synthesizedMessage = @import("response.zig").synthesizedMessage;
const blocking_transport = @import("blocking_transport.zig");
const BlockingUdpTransport = blocking_transport.BlockingUdpTransport;
const TlsTransport = @import("tls_transport.zig").TlsTransport;

pub const Transports = struct {
    udp: *BlockingUdpTransport,
    tcp_enabled: bool,
    tls: ?*TlsTransport = null,
};
const encrypted_ns = @import("encrypted_ns.zig");
const EncryptedNsCache = encrypted_ns.EncryptedNsCache;
const AddressKey = @import("net_address.zig").AddressKey;
const TcpConnectionPool = @import("connection_pool.zig").TcpConnectionPool;
const RttCache = @import("ns_rtt.zig").RttCache;
const rand = @import("rand.zig");
const monotonic = @import("monotonic.zig");
const na = @import("net_address.zig");
const CountingAllocator = @import("counting_allocator.zig").CountingAllocator;
const NsSelector = @import("ns_selector.zig").NsSelector;
const NsOutcome = @import("ns_selector.zig").Outcome;
const cache_mod = @import("cache.zig");
const RRsetCache = cache_mod.RRsetCache;
const InFlightTable = @import("dedup.zig").InFlightTable;
const NsecCache = @import("nsec_cache.zig").NsecCache;
const CaseState = @import("case_state.zig").CaseState;
const ServerConfig = @import("config.zig").ServerConfig;
const log = std.log.scoped(.resolver);

// ── Root Hints ─────────────────────────────────────────────────────────
// IPv4 + IPv6 addresses for a.root-servers.net through m.root-servers.net.
// Source: https://www.internic.net/domain/named.root

pub const root_hints_default: [26]na.Address = .{
    // IPv4
    na.initIp4(.{ 198, 41, 0, 4 }, 53), // a
    na.initIp4(.{ 170, 247, 170, 2 }, 53), // b
    na.initIp4(.{ 192, 33, 4, 12 }, 53), // c
    na.initIp4(.{ 199, 7, 91, 13 }, 53), // d
    na.initIp4(.{ 192, 203, 230, 10 }, 53), // e
    na.initIp4(.{ 192, 5, 5, 241 }, 53), // f
    na.initIp4(.{ 192, 112, 36, 4 }, 53), // g
    na.initIp4(.{ 198, 97, 190, 53 }, 53), // h
    na.initIp4(.{ 192, 36, 148, 17 }, 53), // i
    na.initIp4(.{ 192, 58, 128, 30 }, 53), // j
    na.initIp4(.{ 193, 0, 14, 129 }, 53), // k
    na.initIp4(.{ 199, 7, 83, 42 }, 53), // l
    na.initIp4(.{ 202, 12, 27, 33 }, 53), // m
    // IPv6
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x03, 0xba, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x30 }, 53, 0, 0), // a
    na.initIp6(.{ 0x28, 0x01, 0x01, 0xb8, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b }, 53, 0, 0), // b
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c }, 53, 0, 0), // c
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x2d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d }, 53, 0, 0), // d
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0xa8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e }, 53, 0, 0), // e
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x2f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f }, 53, 0, 0), // f
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0x0d }, 53, 0, 0), // g
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 }, 53, 0, 0), // h
    na.initIp6(.{ 0x20, 0x01, 0x07, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 }, 53, 0, 0), // i
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x03, 0x0c, 0x27, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x30 }, 53, 0, 0), // j
    na.initIp6(.{ 0x20, 0x01, 0x07, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }, 53, 0, 0), // k
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x9f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 }, 53, 0, 0), // l
    na.initIp6(.{ 0x20, 0x01, 0x0d, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35 }, 53, 0, 0), // m
};

// Per-resolveImpl-call ceiling on calls to queryAuthoritativeServers.
// Resets on every sub-resolution and CNAME hop — it bounds a single name's
// resolution, NOT the whole tree (that is `max_global_queries`, below).
// Analogous to BIND's `max-recursion-queries`. Same-zone CNAME continuations,
// QMIN cache-hit advances, and other zero-I/O loop iterations cost zero
// against this. Picked to clear an 8-hop CDN chain (`ba.dn.nexoncdn.co.kr`)
// observed at ~9 queries with comfortable headroom for DNSSEC retries.
const max_upstream_queries = 32;
// Tree-wide ceiling on upstream queries for one client-facing resolution,
// shared by pointer across every sub-resolution (glueless NS-address fetches,
// DNSKEY/DS chases) and never reset on CNAME — the counter `max_upstream_queries`
// is not. Without it, NXNSAttack (CVE-2020-12667) glueless-NS fan-out hands
// each depth+1 sub-resolution a fresh `max_upstream_queries` budget, amplifying
// one client query into hundreds of upstream queries. Mirrors Unbound's
// `max-global-quota` (200) and BIND's `max-query-count` (200); set tighter
// because hark already caps delegation depth at 3 and NS fan-out at 3/2/1,
// so a legitimate cold-cache DNSSEC + QMIN resolution stays well under this.
const max_global_queries = 100;
// Sizes `seen_zones` and bounds the per-cross-zone-walk delegation count.
// Real DNS depth tops out around 5; 16 covers QMIN-with-referrals stacks
// without giving up loop-detection.
const max_delegations = 16;
const max_servers_per_level = 26;
// Total CNAME hops per resolveImpl call. Bumped from 8 to clear the same
// 8-hop CDN chain (Akamai/edgesuite stacks); matches PowerDNS post-fix
// and Hickory.
const max_cname_chain = 16;

/// CNAME records collected over one resolveImpl chain walk, plus the
/// wildcard-expansion proofs authenticating them. Always paired and
/// same-lifetime, so they travel as one struct.
const CnameChain = struct {
    records: std.ArrayListUnmanaged(dns.ResourceRecord) = .empty,
    /// RFC 4035 §3.1.3.4 wildcard-expansion proofs from each CNAME hop's
    /// authority (cf. Unbound `iter_add_prepend_auth`). Members borrow the
    /// per-query arena's parse buffers — would dangle under a heap allocator.
    wildcard_proofs: std.ArrayListUnmanaged(dns.ResourceRecord) = .empty,
    /// Cleared by the first hop that was not proven `.secure`. AD is a claim
    /// about the whole answer, and an unsigned CNAME redirecting into a
    /// signed zone yields a signed *tail* and nothing more — the redirect
    /// itself is unauthenticated, so it could point anywhere (RFC 4035
    /// §3.2.3). `withCnameChain` is the single funnel every chained answer
    /// exits through, so folding it in there covers the negative and error
    /// chains too.
    all_secure: bool = true,

    fn hop(self: *CnameChain, allocator: mem.Allocator, rr: dns.ResourceRecord, status: cache_mod.SecurityStatus) !void {
        try self.records.append(allocator, rr);
        self.all_secure = self.all_secure and status == .secure;
    }

    fn deinit(self: *CnameChain, allocator: mem.Allocator) void {
        self.records.deinit(allocator);
        self.wildcard_proofs.deinit(allocator);
    }
};
const max_minimize_count = 10;

/// Parse a DNS message, propagating OOM and converting other parse
/// errors to null so callers can skip malformed responses. Logs the
/// server address and error name at debug level — warn would be a DoS
/// amplifier for an attacker controlling an authoritative server.
///
/// After parse, lowercases the owner `name` and every embedded RData
/// name so upstream-randomized case cannot leak into client responses
/// or downstream queries (e.g. DNSKEY lookups built from RRSIG signer).
/// Leaves the question section alone — `eqlExact` compares it byte-for-
/// byte against the outgoing 0x20-echo query.
fn tryParseMessage(allocator: mem.Allocator, data: []const u8, server: na.Address) error{OutOfMemory}!?dns.Message {
    var msg = dns.parseMessage(allocator, data) catch |err| switch (err) {
        error.OutOfMemory => {
            @branchHint(.cold);
            return error.OutOfMemory;
        },
        else => {
            @branchHint(.cold);
            var addr_buf: [64]u8 = undefined;
            log.debug("dropping malformed reply from {s}: {s}", .{ na.format(server, &addr_buf), @errorName(err) });
            return null;
        },
    };

    // RFC 1035 §4.1.1: qr=0 is a query, not a response — as unusable as a
    // parse failure to every consumer. Reject before the lowercase scrub
    // so garbage doesn't pay for name clones.
    if (!msg.header.flags.qr) return null;

    // RFC 4035 §3.2.3: AD is a validator's *output*. Authoritative servers
    // have no business setting it, but Route 53 sets it on every DO=1 reply,
    // including for zones with no DS at all — and hark carried the bit
    // through resolution into the client reply (response.zig only ANDs it
    // with the client's DO/AD bit). Every unsigned domain on Route 53 was
    // therefore answered "DNSSEC-authenticated". hark's own verdict re-sets
    // the bit in validateAnswer and the negative-proof paths; nothing
    // upstream may.
    msg.header.flags.ad = false;

    // `@constCast` is sound — parseMessage returns ArrayList-backed
    // mutable storage typed `[]const`. The pre-scrub label bytes alias
    // the upstream wire buffer; cloneNameLower's arena allocation
    // replaces them.
    inline for (.{ msg.answers, msg.authorities, msg.additionals }) |section| {
        for (@constCast(section)) |*rr| {
            rr.name = try dns.cloneNameLower(allocator, rr.name);
            try dns.lowercaseRDataNames(allocator, &rr.rdata);
        }
    }

    return msg;
}

// ── RecursiveResolver ──────────────────────────────────────────────────

/// Tree-wide outbound-query budget for one client-facing resolution.
///
/// Lives on the stack of `resolve()` and is shared *by pointer* across the
/// entire resolution tree — `cloneForThread` copies the pointer and never
/// resets it (exactly as it now treats `validation_budget`), so the concurrent
/// NS-address fan-out helpers all draw from the same counter. The atomic makes
/// that race-free.
///
/// This is the structural defense against NXNSAttack (CVE-2020-12667): the
/// per-call `max_upstream_queries` counter resets on every `resolveImpl`
/// sub-call, so glueless-NS fan-out would otherwise grant unbounded total
/// work. Mirrors Unbound's refcounted `target_count[GLOBAL_QUOTA]` and BIND's
/// `max-query-count`. Never reset mid-resolution (BIND's bug #4741 was a
/// per-name counter that reset on CNAME — useless against a redirect chain).
pub const QueryBudget = struct {
    spent: std.atomic.Value(u32) = .init(0),
    max: u32 = max_global_queries,

    /// Reserve one upstream query. Returns the error once the ceiling is hit;
    /// callers propagate it and the server maps it to SERVFAIL.
    fn consume(self: *QueryBudget) error{GlobalQueryBudgetExhausted}!void {
        if (self.spent.fetchAdd(1, .monotonic) >= self.max)
            return error.GlobalQueryBudgetExhausted;
    }
};

pub const RecursiveResolver = struct {
    /// `null` IFF `cache_only` — the type-level invariant lets the resolver
    /// short-circuit before any transport access on the recv-thread fast path.
    transports: ?Transports,
    io: std.Io,
    /// Override the built-in IANA root hints. Defaults to the hardcoded
    /// production list. The server passes a config-supplied slice when
    /// `[resolver] root-hints = [...]` is set — used by tests to redirect
    /// at scripted authoritatives, and by operators running split-horizon
    /// deployments against private root servers.
    root_hints: []const na.Address = &root_hints_default,
    /// Default port for upstream queries. Used when constructing addresses
    /// from glue records (which have no port field per RFC 1035). Production
    /// is always 53. The corresponding `[resolver] upstream-port` config key
    /// is gated behind `-Dtesting=true`.
    upstream_port: u16 = 53,
    /// Bypass the 127/8 rebinding defense for upstream addresses. Tests only.
    /// The corresponding `[resolver] allow-loopback-upstreams` config key is
    /// gated behind `-Dtesting=true`.
    allow_loopback_upstreams: bool = false,
    /// Root trust anchors. Defaults to the hardcoded IANA list. The server
    /// passes a config-supplied slice when `[resolver] trust-anchors = [...]`
    /// is set (test-only key) — used by the scripted DNSSEC harness to
    /// validate against zone-keys it generated itself.
    trust_anchors: []const dns.DsData = &dnssec.root_ds_records,
    cache: ?*RRsetCache = null,
    qname_minimization: bool = true,
    /// Whether to validate DNSSEC signatures (may be disabled per-query by CD bit)
    dnssec_enabled: bool = false,
    /// Whether to request DNSSEC data (DO bit) — always true if server is DNSSEC-capable.
    /// RFC 4035 §3.2.1: MUST set DO regardless of CD bit or per-query validation.
    dnssec_aware: bool = false,
    encrypted_ns_cache: ?*EncryptedNsCache = null,
    rtt_cache: ?*RttCache = null,
    ns_selector: ?*NsSelector = null,
    bypass_cache: bool = false,
    /// When set, any upstream attempt returns `error.CacheOnlyMiss`.
    cache_only: bool = false,
    dedup: ?*InFlightTable = null,
    nsec_cache: ?*NsecCache = null,
    key_cache: ?*RRsetCache = null,
    tcp_pool: ?*TcpConnectionPool = null,
    /// Persistent allocator for helper thread arenas (parallel NS resolution).
    gpa: ?mem.Allocator = null,
    /// Per-resolution memory cap: the main query arena and each NS-fanout
    /// helper arena independently. Above legitimate signed traffic (~350 KiB),
    /// below the 2 MiB wire ceiling (32 upstream × 64 KiB) — a stuffing
    /// tripwire. Mirrors config.zig defaultConfig.
    query_memory_limit: usize = 1024 * 1024,
    /// Staggered NS racing interval in ms (0 = disabled).
    stagger_ms: u32 = 0,

    /// QNAME 0x20 case randomization (RFC draft Vixie/Dagon). null when
    /// disabled.
    case_state: ?*CaseState = null,

    /// Re-entrancy guard: prevents fetchDsFromParent → resolveNsAddresses →
    /// resolveImpl → validateAnswer → fetchDnskey → fetchDsFromParent loops.
    resolving_ds: bool = false,

    /// DNSKEY zone needing proactive refresh — stored in fixed buffer (set
    /// deep in recursion, far from any caller allocator), duped into the
    /// query arena at `resolve()`'s tail.
    pending_dnskey_prefetch: ?[]const u8 = null,
    pending_dnskey_buf: [dns.max_name_len + 1]u8 = undefined,

    /// Mirrors config `prefetch-cousin`; gates SVCB cousin extraction.
    prefetch_cousin: bool = true,

    /// A CNAME-chain member (head redirect or a mid-chain/tail RRset) was
    /// served from cache inside its prefetch window. Consumed in `resolve()`:
    /// the prefetch targets (head name, qtype) — a bg re-walk of the whole
    /// chain refreshes whichever member is aging. Chain members can't flow
    /// through `prefetch_name` at the hit site because mid-chain hits happen
    /// before the final result exists; the head name is the stable handle.
    pending_chain_prefetch: bool = false,

    /// Tree-wide DNSSEC CPU budget for the in-flight query — a `dnssec.ValidationBudget`
    /// on `resolve()`'s stack, shared (not reset) across `cloneForThread` so the fan-out
    /// can't multiply the KeyTrap/NSEC3 ceilings. null outside `resolve()` (cache-only +
    /// unit tests, both crypto-free). Mirrors `query_budget`.
    validation_budget: ?*dnssec.ValidationBudget = null,

    /// Tree-wide upstream-query budget for the in-flight client query. Points
    /// at a `QueryBudget` on `resolve()`'s stack; shared (not reset) across
    /// `cloneForThread` so fan-out helpers draw from the same ceiling. null
    /// outside an active `resolve()` (e.g. cache-only unit tests).
    query_budget: ?*QueryBudget = null,

    /// Stable inputs that come from the surrounding Server / WorkerState.
    /// Both server-side construction sites build one of these and call
    /// `fromContext` — the single source of truth for the field mapping.
    pub const Context = struct {
        config: *const ServerConfig,
        io: std.Io,
        gpa: mem.Allocator,
        cache: *RRsetCache,
        rtt_cache: *RttCache,
        ns_selector: *NsSelector,
        encrypted_ns_cache: ?*EncryptedNsCache,
        case_state: ?*CaseState,
        dedup: ?*InFlightTable,
        nsec_cache: ?*NsecCache,
        key_cache: ?*RRsetCache,
        tcp_pool: ?*TcpConnectionPool,
    };

    /// Per-query knobs that vary across calls within the same Context.
    pub const RuntimeOpts = struct {
        /// Client CD bit (RFC 4035 §3.2.2): when true, skip our validation
        /// — the client validates itself. Also disables the NSEC cache for
        /// this query so a downstream validator gets the raw proof.
        cd: bool = false,
        /// Skip the response cache (bg prefetch path; per-query overrides).
        bypass_cache: bool = false,
        /// Cache-only fast path. See `RecursiveResolver.cache_only`.
        cache_only: bool = false,
    };

    pub fn fromContext(ctx: Context, transports: ?Transports, opts: RuntimeOpts) RecursiveResolver {
        std.debug.assert((transports == null) == opts.cache_only);
        return .{
            .transports = transports,
            .io = ctx.io,
            .root_hints = ctx.config.rootHints(),
            .upstream_port = ctx.config.upstream_port,
            .allow_loopback_upstreams = ctx.config.allow_loopback_upstreams,
            .trust_anchors = ctx.config.trustAnchors(),
            .cache = ctx.cache,
            .qname_minimization = ctx.config.qname_minimization,
            // RFC 4035 §3.2.1: always request DNSSEC data (DO bit) if capable.
            .dnssec_aware = ctx.config.dnssec,
            // RFC 4035 §3.2.2: CD=1 means client handles validation — skip ours.
            .dnssec_enabled = ctx.config.dnssec and !opts.cd,
            .encrypted_ns_cache = ctx.encrypted_ns_cache,
            .rtt_cache = ctx.rtt_cache,
            .ns_selector = ctx.ns_selector,
            .bypass_cache = opts.bypass_cache,
            .cache_only = opts.cache_only,
            .stagger_ms = ctx.config.stagger_ms,
            .prefetch_cousin = ctx.config.prefetch_cousin,
            .case_state = ctx.case_state,
            .dedup = ctx.dedup,
            .tcp_pool = ctx.tcp_pool,
            .gpa = ctx.gpa,
            .query_memory_limit = ctx.config.query_memory_limit,
            .nsec_cache = if (ctx.config.dnssec and !opts.cd) ctx.nsec_cache else null,
            .key_cache = if (ctx.config.dnssec) ctx.key_cache else null,
        };
    }

    /// Create a thread-local resolver clone with fresh transports. Shared
    /// caches and config are inherited; per-query mutable state is reset.
    fn cloneForThread(self: *RecursiveResolver, transports: Transports) RecursiveResolver {
        std.debug.assert(!self.cache_only); // clone implies real upstream work
        var resolver = self.*;
        resolver.transports = transports;
        resolver.gpa = null;
        resolver.resolving_ds = false;
        resolver.pending_dnskey_prefetch = null;
        resolver.pending_chain_prefetch = false;
        // Neither budget is reset: `self.*` copies the pointers, so clones share the
        // parent's counters. Resetting either re-opens fan-out amplification (NXNS /
        // KeyTrap). Both are atomic, so concurrent draws are safe.
        return resolver;
    }

    /// Charge one upstream query against the tree-wide budget. No-op when
    /// unset (cache-only paths and unit tests run without a budget).
    fn consumeQuery(self: *RecursiveResolver) error{GlobalQueryBudgetExhausted}!void {
        if (self.query_budget) |qb| try qb.consume();
    }

    /// The in-flight query's DNSSEC CPU budget. Set wherever crypto runs
    /// (every validation site is downstream of an upstream response, impossible
    /// under cache-only); the unwrap enforces that invariant — dnssec verify
    /// functions take a non-optional budget so no verify site can fail open.
    fn validationBudget(self: *RecursiveResolver) *dnssec.ValidationBudget {
        return self.validation_budget.?;
    }

    /// Return the dedicated key cache for DNSKEY/DS, falling back to the main cache.
    fn keyCache(self: *RecursiveResolver) ?*RRsetCache {
        if (self.key_cache) |kc| return kc;
        std.debug.assert(!self.dnssec_enabled or self.cache != null);
        return self.cache;
    }

    fn referralPolicy(self: *RecursiveResolver) ReferralAddrPolicy {
        return .{
            .upstream_port = self.upstream_port,
            .allow_loopback = self.allow_loopback_upstreams,
        };
    }

    /// Non-last server timeout cap (Knot KR_CONN_RTT_MAX, RFC 1035 §4.2.1 ≥2s).
    const failover_timeout_cap: u32 = 2000;

    fn serverTimeout(self: *RecursiveResolver, addr_key: AddressKey, is_last: bool) u32 {
        const base: u32 = if (self.rtt_cache) |rc| rc.getTimeout(addr_key) else self.transports.?.udp.config.timeout_ms;
        return if (is_last) base else @min(base, failover_timeout_cap);
    }

    pub const ResolveResult = struct {
        message: dns.Message,
        prefetch_name: ?[]const u8 = null,
        prefetch_qtype: dns.RType = .a,
        /// DNSKEY zone needing async refresh (TTL < 10%). Server handles after responding.
        prefetch_dnskey_zone: ?[]const u8 = null,
        /// Happy-Eyeballs (RFC 8305) cousin qtype — A↔AAAA pairing.
        cousin_prefetch_qtype: ?dns.RType = null,
        /// HEv3 §4.2.1 cousin — SVCB/HTTPS TargetName the client can only
        /// chase with A/AAAA queries after this answer arrives.
        cousin_prefetch_name: ?[]const u8 = null,
        /// True iff the answer was produced with zero upstream queries
        /// (cache hit, NSEC aggressive-use synthesis, or RFC 8020 NX cut).
        /// Drives the server's client-facing hit accounting — unlike the
        /// RRsetCache counters, which count every internal lookup during
        /// recursion. The server flips this to false for dedup followers:
        /// they waited on a leader's upstream resolve.
        from_cache: bool = false,
    };

    pub fn resolve(self: *RecursiveResolver, allocator: mem.Allocator, name: []const u8, qtype: dns.RType) !ResolveResult {
        // Both per-query budgets are stack locals here, shared by pointer through
        // the whole tree (incl. clones). Helpers join before this frame returns, so
        // the pointers stay live.
        var query_budget: QueryBudget = .{};
        self.query_budget = &query_budget;
        defer self.query_budget = null;
        var validation_budget: dnssec.ValidationBudget = .{};
        self.validation_budget = &validation_budget;
        defer self.validation_budget = null;
        var result = try self.resolveImpl(allocator, name, qtype, 0);
        // ResolveResult names are caller- or arena-owned, never resolver-owned:
        // dupe out of the stack-local pending buffer before returning.
        if (self.pending_dnskey_prefetch) |z| {
            result.prefetch_dnskey_zone = allocator.dupe(u8, z) catch null;
        }
        // Chain-member prefetch window: refresh via the head so the bg
        // resolve re-walks the whole chain. `name` is caller-owned and
        // outlives the result — same lifetime contract as the head-hit
        // prefetch_name set in tryServeFromCache.
        if (self.pending_chain_prefetch and result.prefetch_name == null) {
            result.prefetch_name = name;
            result.prefetch_qtype = qtype;
        }
        result.from_cache = query_budget.spent.load(.monotonic) == 0;
        // Non-NOERROR answers never earn a cousin: NXDOMAIN is
        // qtype-independent (RFC 8020) and SERVFAIL would re-walk a
        // path that just failed.
        if (result.message.header.flags.rcode == .no_error) switch (qtype) {
            .a => result.cousin_prefetch_qtype = .aaaa,
            .aaaa => result.cousin_prefetch_qtype = .a,
            .svcb, .https => if (self.prefetch_cousin) {
                var buf: [dns.max_name_len + 1]u8 = undefined;
                if (svcbCousinTarget(result.message.answers, qtype, name, &buf)) |t| {
                    result.cousin_prefetch_name = allocator.dupe(u8, t) catch null;
                }
            },
            else => {},
        };
        return result;
    }

    /// First SVCB/HTTPS answer whose TargetName the client must chase
    /// serially — "." and qname/owner-equal targets are already covered by
    /// the client's parallel A/AAAA queries (HEv3 §4.2.1). Strict parse,
    /// LDH-only labels: anything else forfeits the cousin rather than
    /// risking a mangled prefetch name.
    fn svcbCousinTarget(
        answers: []const dns.ResourceRecord,
        qtype: dns.RType,
        qname: []const u8,
        buf: *[dns.max_name_len + 1]u8,
    ) ?[]const u8 {
        rr_loop: for (answers) |rr| {
            if (rr.rtype != qtype) continue;
            const rdata = rr.rdata.unknown;
            var pos: usize = 2; // SvcPriority
            var len: usize = 0;
            while (true) {
                if (pos >= rdata.len) continue :rr_loop;
                const label_len = rdata[pos];
                pos += 1;
                if (label_len == 0) break;
                if (label_len > dns.max_label_len) continue :rr_loop;
                if (pos + label_len > rdata.len) continue :rr_loop;
                if (len + label_len + @intFromBool(len > 0) > dns.max_name_len) continue :rr_loop;
                if (len > 0) {
                    buf[len] = '.';
                    len += 1;
                }
                for (rdata[pos..][0..label_len]) |c| {
                    buf[len] = switch (c) {
                        'a'...'z', '0'...'9', '-', '_' => c,
                        'A'...'Z' => c | 0x20,
                        else => continue :rr_loop,
                    };
                    len += 1;
                }
                pos += label_len;
            }
            if (len == 0) continue;
            const target = buf[0..len];
            if (std.ascii.eqlIgnoreCase(target, qname)) continue;
            var owner_buf: [dns.max_name_len + 1]u8 = undefined;
            if (mem.eql(u8, target, rr.name.formatLower(&owner_buf))) continue;
            return target;
        }
        return null;
    }

    const max_resolve_depth = 3;

    fn resolveImpl(self: *RecursiveResolver, allocator: mem.Allocator, name: []const u8, qtype: dns.RType, depth: usize) anyerror!ResolveResult {
        var current_name: []const u8 = name;
        // Counts queryAuthoritativeServers calls only; total_probes
        // bounds QMIN iterations (including cache-hit advances).
        var upstream_queries: usize = 0;
        var total_probes: usize = 0;
        var cname_chain: CnameChain = .{};
        defer cname_chain.deinit(allocator);

        // DNSSEC chain of trust state — starts as secure at root
        var security_state: dnssec.SecurityStatus = if (self.dnssec_enabled) .secure else .unchecked;

        cname_loop: while (true) {
            // RFC 6761 / 7686 / 8375: short-circuit special-use names before
            // any cache lookup or upstream traffic. Pure synthesis — no I/O,
            // no privacy leak to root.
            const action = special_use.classify(current_name, qtype);
            if (action != .none) {
                const synth = try special_use.synthesize(allocator, current_name, action);
                return .{ .message = try withCnameChain(allocator, &cname_chain, synth) };
            }

            // RFC 8482: minimize ANY responses to a synthetic HINFO answer
            // to deny amplification. Modern resolvers refuse ANY entirely or
            // return RFC8482; we choose the latter so legacy clients still
            // get a valid response.
            if (qtype == .any) {
                const synth = try synthesizeAnyHinfo(allocator, current_name);
                return .{ .message = try withCnameChain(allocator, &cname_chain, synth) };
            }

            // CACHE CHECK 1: Do we already have a cached answer?
            switch (try self.tryServeFromCache(allocator, name, current_name, qtype, depth, &cname_chain)) {
                .none => {},
                .served => |served| return served,
                .follow_cname => |dispatch| {
                    if (cname_chain.records.items.len >= max_cname_chain) return error.CnameChainTooLong;
                    if (cnameTargetRevisitsChain(cname_chain.records.items, dispatch.cname_rr.rdata.cname)) {
                        logCnameLoop(dispatch.cname_rr.rdata.cname, "cache-served");
                        return self.bogusServfail(current_name, qtype);
                    }
                    try cname_chain.hop(allocator, dispatch.cname_rr, dispatch.security_status);
                    try aggregateCachedCnameWildcardProofs(allocator, dispatch.security_status, dispatch.nsec_proofs, &cname_chain.wildcard_proofs);
                    current_name = try nameToDotted(allocator, dispatch.cname_rr.rdata.cname);
                    // Mirror the upstream CNAME branch: re-resolve the
                    // target with fresh security state, but preserve
                    // .insecure so an unauthenticated cached CNAME can't
                    // launder AD onto downstream answers.
                    if (security_state != .insecure) {
                        security_state = if (self.dnssec_enabled) .secure else .unchecked;
                    }
                    continue :cname_loop;
                },
            }

            if (try self.tryServeFromNxdomainAncestor(allocator, current_name, qtype, &cname_chain)) |result| return result;

            var target_name = try dns.parseDottedName(allocator, current_name);

            if (try self.tryServeFromAggressiveNsec(allocator, target_name, current_name, qtype, &cname_chain)) |result| return result;

            var servers: [max_servers_per_level]na.Address = undefined;
            var server_count: usize = undefined;
            var parent_zone: dns.Name = undefined;
            try self.seedServersForQuery(allocator, current_name, qtype, &servers, &server_count, &parent_zone, &security_state);

            var seen_zones: [max_delegations]dns.Name = undefined;
            var seen_zone_count: usize = 0;

            // QNAME minimization (RFC 9156): start probing one label past the
            // current zone cut and advance toward the full target name.
            var minimize_label_count: usize = if (self.qname_minimization)
                parent_zone.labels.len + 1
            else
                target_name.labels.len; // disabled: always send full name

            while (true) {
                // Determine if this iteration sends the full (final) query or a probe.
                const is_final = minimize_label_count >= target_name.labels.len or
                    !self.qname_minimization or total_probes >= max_minimize_count;

                // Build probe name from target's trailing labels, or use the full name.
                const query_name: []const u8 = if (is_final) current_name else blk: {
                    const child_view = dns.Name{ .labels = target_name.labels[target_name.labels.len - minimize_label_count ..] };
                    var child_buf: [dns.max_name_len + 1]u8 = undefined;
                    break :blk try allocator.dupe(u8, child_view.formatInto(&child_buf));
                };
                const query_type: dns.RType = if (is_final) qtype else .a;

                if (!is_final) total_probes += 1;

                // QMIN cache check: see if the probe answer is already cached.
                if (!is_final) {
                    if (self.cache) |c| {
                        if (c.lookup(allocator, query_name, query_type, .in)) |result| {
                            switch (result) {
                                .hit => {
                                    minimize_label_count += 1;
                                    continue;
                                },
                                .negative => |n| {
                                    if (n.rcode == .name_error) {
                                        // Cached NXDOMAIN — relaxed mode: stop minimizing
                                        minimize_label_count = target_name.labels.len;
                                        continue;
                                    }
                                    // Cached NODATA — name exists, advance
                                    minimize_label_count += 1;
                                    continue;
                                },
                            }
                        }
                    }
                }

                if (upstream_queries >= max_upstream_queries) return error.MaxQueriesExceeded;
                try self.consumeQuery();
                upstream_queries += 1;
                const sqr = try self.queryAuthoritativeServers(allocator, query_name, query_type, &servers, server_count, parent_zone);
                var response = sqr.message;
                const responding_server = sqr.responding_server;

                // ── Probe response handling (non-final queries) ──
                if (!is_final) {
                    const probe_name = dns.Name{ .labels = target_name.labels[target_name.labels.len - minimize_label_count ..] };
                    // Check for referral — only from successful responses (error responses
                    // may contain NS records in authority that are not valid delegations)
                    if (response.header.flags.rcode == .no_error) {
                        if (extractReferral(response, target_name, parent_zone, self.referralPolicy())) |referral| {
                            if (self.cache) |c| c.storeResponse(response, parent_zone, .unchecked, std.math.maxInt(u32));
                            try self.followReferral(allocator, referral, response.authorities, depth, &security_state, &parent_zone, &servers, &server_count, &seen_zones, &seen_zone_count);
                            // Flood/exhaustion classifies the delegation .bogus; fail
                            // closed here — a later CNAME hop would re-elevate it to
                            // .secure and serve unsigned.
                            if (security_state == .bogus) return self.bogusServfail(current_name, qtype);
                            minimize_label_count = parent_zone.labels.len + 1;
                            continue;
                        }
                    }

                    if (response.header.flags.rcode == .name_error) {
                        // RFC 9156 §4 + RFC 8020 interaction: an unsigned-zone
                        // probe NXDOMAIN from an RFC 8020 violator (e.g.,
                        // dynect.net returning NXDOMAIN at empty non-terminals
                        // like p07.dynect.net) would otherwise poison the
                        // NX-cut consumer at cache.lookupNxdomainAncestor —
                        // it returns negatives when security_status != .secure,
                        // so an .insecure or .unchecked probe-NX entry there
                        // makes every child name appear non-existent, bricking
                        // e.g. ns1.p07.dynect.net under x.com's delegation for
                        // the negative TTL window (up to 3 hours).
                        //
                        // Stop minimizing (relaxed mode) but only cache when
                        // DNSSEC NSEC has proved the cut. Secure-cached entries
                        // are then doubly inert: the NX-cut path's `!= .secure`
                        // filter routes them through the dedicated NSEC
                        // aggressive-use cache instead, so this branch caches
                        // *only* entries the NX-cut will skip by design.
                        var neg_ttl_cap: u32 = std.math.maxInt(u32);
                        switch (self.verifiedNegativeResponse(allocator, security_state, response.authorities, probe_name, query_type, true, parent_zone, servers[0..server_count], &neg_ttl_cap)) {
                            .proceed => |status| {
                                // .secure here means verifiedNegativeResponse
                                // ran NSEC and accepted it; AA is redundant
                                // (cryptographic proof supersedes the bit).
                                // `.insecure` is excluded: an Opt-Out denial
                                // leaves the intermediate name possibly existing
                                // as an unsigned delegation, too thin to cache
                                // against the full query name (RFC 8020).
                                if (status == .secure) {
                                    if (self.cache) |c| c.storeNegative(query_name, query_type, .in, .name_error, response.authorities, parent_zone, status, neg_ttl_cap);
                                }
                            },
                            // .bogus falls through to the same stop-minimizing
                            // epilogue as .proceed/.skip_cache — one home for it.
                            .skip_cache, .bogus => {},
                        }
                        minimize_label_count = target_name.labels.len;
                        continue;
                    }

                    if (response.header.flags.rcode != .no_error and response.header.flags.rcode != .name_error) {
                        // Probe error (SERVFAIL, REFUSED, FORMERR, etc.) — stop minimizing, send full QNAME
                        minimize_label_count = target_name.labels.len;
                        continue;
                    }

                    if (response.answers.len > 0) {
                        minimize_label_count += 1;
                        continue;
                    }

                    // NODATA (no answers, no referral) — name exists, cache negative, advance
                    {
                        var neg_ttl_cap: u32 = std.math.maxInt(u32);
                        switch (self.verifiedNegativeResponse(allocator, security_state, response.authorities, probe_name, query_type, false, parent_zone, servers[0..server_count], &neg_ttl_cap)) {
                            .proceed => |status| {
                                if (response.header.flags.aa) {
                                    if (self.cache) |c| {
                                        c.storeResponse(response, parent_zone, .unchecked, std.math.maxInt(u32));
                                        c.storeNegative(query_name, query_type, .in, .no_error, response.authorities, parent_zone, status, neg_ttl_cap);
                                    }
                                }
                            },
                            .skip_cache => {},
                            .bogus => {
                                minimize_label_count = target_name.labels.len;
                                continue;
                            },
                        }
                    }
                    minimize_label_count += 1;
                    continue;
                }

                // ── Scrub out-of-bailiwick answer records ──
                // Authoritative servers may include cross-zone records in answers
                // (e.g., CNAME target's A/AAAA from a different zone). Discard
                // them so validation only sees records from the queried zone.
                if (parent_zone.labels.len > 0 and response.answers.len > 0) {
                    const filtered = try allocator.alloc(dns.ResourceRecord, response.answers.len);
                    var filtered_count: usize = 0;
                    for (response.answers) |rr| {
                        if (rr.name.isSubdomainOf(parent_zone)) {
                            filtered[filtered_count] = rr;
                            filtered_count += 1;
                        }
                    }
                    response.answers = filtered[0..filtered_count];
                }

                // ── Final query response handling ──

                self.probeParentChildCut(allocator, target_name, parent_zone, &response, servers[0..server_count], &security_state);

                if (response.header.flags.rcode != .no_error)
                    return self.handleErrorResponse(allocator, &response, current_name, name, qtype, depth, security_state, target_name, parent_zone, servers[0..server_count], &cname_chain);

                if (response.answers.len > 0) {
                    // Follow CNAME if the answer doesn't contain the queried type
                    if (qtype != .cname) {
                        var has_target_type = false;
                        for (response.answers) |rr| {
                            if (rr.rtype == qtype) {
                                has_target_type = true;
                                break;
                            }
                        }

                        if (!has_target_type) {
                            // Validate CNAME RRset before following in secure zones.
                            // RFC 4035 §3.1: every authoritative RRset in a secure zone
                            // must carry an RRSIG. validateAnswer returns .bogus when no
                            // RRSIG is present, which closes the strip-RRSIG downgrade.
                            var cname_status: cache_mod.SecurityStatus = .unchecked;
                            var cname_ttl_cap: u32 = std.math.maxInt(u32);
                            if (self.dnssec_enabled and security_state == .secure) {
                                switch (try self.validateAnswer(allocator, &response, .cname, security_state, parent_zone, servers[0..server_count])) {
                                    .bogus => {
                                        self.recordNsOutcome(parent_zone, responding_server, .validation_failure, 0);
                                        return self.bogusServfail(current_name, qtype);
                                    },
                                    .valid => |cap| {
                                        cname_status = .secure;
                                        cname_ttl_cap = cap;
                                    },
                                    .skip => {},
                                }
                            }
                            if (findCnameRecord(response, target_name)) |cname_rr| {
                                const is_same_zone = parent_zone.labels.len > 0 and
                                    cname_rr.rdata.cname.isSubdomainOf(parent_zone);

                                // Store before following CNAME — won't reach final answer validation
                                if (self.cache) |c| c.storeResponse(response, parent_zone, cname_status, cname_ttl_cap);
                                if (cname_chain.records.items.len >= max_cname_chain) return error.CnameChainTooLong;
                                if (cnameTargetRevisitsChain(cname_chain.records.items, cname_rr.rdata.cname)) {
                                    logCnameLoop(cname_rr.rdata.cname, "upstream-served");
                                    return self.bogusServfail(current_name, qtype);
                                }
                                try cname_chain.hop(allocator, cname_rr, cname_status);

                                try self.aggregateCnameWildcardProofs(allocator, cname_status, response.authorities, parent_zone, servers[0..server_count], &cname_chain.wildcard_proofs);

                                // Same-zone CNAME: keep current auth servers, delegation,
                                // and security_state. The DNSSEC chain of trust is
                                // unchanged within a zone, so re-walking from root would
                                // only redo cache lookups. Skip back to the inner
                                // referral loop with the new target.
                                if (is_same_zone) {
                                    current_name = try nameToDotted(allocator, cname_rr.rdata.cname);
                                    target_name = try dns.cloneName(allocator, cname_rr.rdata.cname);
                                    minimize_label_count = if (self.qname_minimization)
                                        parent_zone.labels.len + 1
                                    else
                                        target_name.labels.len;
                                    continue;
                                }

                                current_name = try nameToDotted(allocator, cname_rr.rdata.cname);
                                // Re-resolve CNAME target from root with fresh security state.
                                // Preserve .insecure: an unauthenticated CNAME could redirect
                                // anywhere, so the answer must not carry AD (RFC 4035 §3.2.3).
                                if (security_state != .insecure) {
                                    security_state = if (self.dnssec_enabled) .secure else .unchecked;
                                }
                                continue :cname_loop;
                            }
                            // No CNAME found — fall through to final answer validation
                        }
                    }

                    return self.finalizeAnswer(allocator, &response, current_name, qtype, security_state, parent_zone, servers[0..server_count], responding_server, &cname_chain);
                }

                const referral = extractReferral(response, target_name, parent_zone, self.referralPolicy()) orelse
                    return self.finalizeNodata(allocator, &response, current_name, name, qtype, depth, security_state, target_name, parent_zone, servers[0..server_count], &cname_chain);

                if (self.cache) |c| c.storeResponse(response, parent_zone, .unchecked, std.math.maxInt(u32));
                try self.followReferral(allocator, referral, response.authorities, depth, &security_state, &parent_zone, &servers, &server_count, &seen_zones, &seen_zone_count);
                // Flood/exhaustion → .bogus delegation; fail closed (see above).
                if (security_state == .bogus) return self.bogusServfail(current_name, qtype);
                minimize_label_count = parent_zone.labels.len + 1;
            }

            unreachable; // while(true) only exits via inner returns / continue :cname_loop
        }
    }

    // ── Initial server seeding ──────────────────────────────────────────

    /// Seed the per-query authority server set from the closest cached
    /// delegation, or root hints if none. Starts `parent_zone` at root
    /// (empty labels = `.`). Demotes `security_state` to `.insecure`
    /// when the cached delegation has a known negative DS — the live
    /// referral path would have caught this via `classifyDelegation`,
    /// but a cache shortcut skips that call, so `hasCachedInsecureDelegation`
    /// stands in.
    fn seedServersForQuery(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        current_name: []const u8,
        qtype: dns.RType,
        servers: *[max_servers_per_level]na.Address,
        server_count: *usize,
        parent_zone: *dns.Name,
        security_state: *dnssec.SecurityStatus,
    ) !void {
        parent_zone.* = dns.Name{ .labels = &.{} };

        // RFC 4035 §5: DS lives in the *parent*. Seeding from the closest
        // cached delegation for the name itself sends a client's DS query to
        // the child's own servers, which answer NODATA with their apex
        // NSEC/NSEC3 — a record that never carries DS and so reads as proof
        // the delegation is unsigned. The validator now refuses that (RFC
        // 6840 §4.4), which would turn a wrong answer into a SERVFAIL; seed
        // one label up instead so the query reaches someone who can answer it.
        // Deliberately not label arithmetic on a zone name (see 09283b6): the
        // walk starts at the TLD and keeps the deepest cached hit, so any cut
        // at or above the parent is found, ENT gaps included. parentZoneOf here
        // is a plain leftmost-label strip picking the walk's starting point —
        // never a claim about where a cut is; keep it dumb.
        const seed_name = if (qtype == .ds) parentZoneOf(current_name) else current_name;

        if (try self.findClosestCachedDelegation(allocator, seed_name)) |deleg| {
            server_count.* = deleg.count;
            @memcpy(servers[0..deleg.count], deleg.addrs[0..deleg.count]);
            parent_zone.* = deleg.zone;

            if (security_state.* == .secure and self.dnssec_enabled) {
                if (hasCachedInsecureDelegation(self.keyCache(), allocator, deleg.zone))
                    security_state.* = .insecure;
            }
            return;
        }

        const hints = self.root_hints;
        std.debug.assert(hints.len <= max_servers_per_level);
        server_count.* = hints.len;
        @memcpy(servers[0..hints.len], hints);
    }

    // ── Cache-served short-circuits ─────────────────────────────────────

    /// Dispatch from `tryServeFromCache`: either a terminal answer, a
    /// CNAME follow-up the outer loop drives, or no usable cache hit.
    /// The `follow_cname` arm is the dual-stack win — when a downstream
    /// AAAA query reuses the CNAME its sibling A query already cached.
    const CacheDispatch = union(enum) {
        none,
        served: ResolveResult,
        follow_cname: struct {
            cname_rr: dns.ResourceRecord,
            security_status: cache_mod.SecurityStatus,
            /// Pre-validated wildcard-expansion proofs from the cache.
            /// Trust-at-store; aggregated without re-verifying signatures.
            nsec_proofs: []const dns.ResourceRecord,
        },
    };

    /// Cache check 1: positive or negative hit on the main RRset cache.
    /// Returns `.none` on miss. RFC 8767 §6 requires trying fresh once
    /// before serving a stale entry; the `bypass_cache` save/restore
    /// lives inside this helper so the recursive call doesn't leak the
    /// flag to other callers. Both stale recursion and prefetch-window
    /// signalling are gated to the head of the CNAME chain
    /// (empty chain) — mid-chain re-entry would re-walk preceding
    /// labels.
    ///
    /// CNAME-follow fallback: when the direct `(current_name, qtype)`
    /// lookup misses and qtype isn't .cname, probe for a cached CNAME.
    /// A fresh hit returns `.follow_cname`; the outer loop pushes it
    /// onto the chain and continues. Stale CNAMEs at the head of the
    /// chain are skipped so the direct upstream path can run — the
    /// stale-revalidate gate (empty chain) protects against
    /// silently serving a stale redirect when fresh resolution is on
    /// the table.
    fn tryServeFromCache(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        name: []const u8,
        current_name: []const u8,
        qtype: dns.RType,
        depth: usize,
        chain: *const CnameChain,
    ) !CacheDispatch {
        if (self.bypass_cache) return .none;
        const c = self.cache orelse return .none;
        if (c.lookup(allocator, current_name, qtype, .in)) |result| {
            const meta = switch (result) {
                inline .hit, .negative => |entry| .{
                    .needs_prefetch = entry.needs_prefetch,
                    .is_stale = entry.is_stale,
                },
            };
            const at_chain_head = chain.records.items.len == 0;
            const prefetch_out: ?[]const u8 = if (meta.needs_prefetch and at_chain_head) name else null;
            // Mid-chain member (the short-TTL tail of a CNAME chain, in
            // practice) inside its prefetch window: can't re-enter here as
            // prefetch_name — flag the resolver so resolve() targets the
            // head instead. Covers stale mid-chain hits too (needs_prefetch
            // is always set on stale), so a silently-followed stale link
            // at least triggers a bg refresh.
            if (meta.needs_prefetch and !at_chain_head) self.pending_chain_prefetch = true;

            // RFC 8767 §6: a stale cache entry must not be the first answer
            // when fresh resolution is achievable. Try fresh once with
            // bypass_cache; on any failure fall back to the stale answer.
            if (meta.is_stale and chain.records.items.len == 0) {
                // Save/restore so a future caller that arrives here with
                // bypass_cache already set doesn't get its flag silently
                // flipped to false.
                const prev_bypass = self.bypass_cache;
                self.bypass_cache = true;
                defer self.bypass_cache = prev_bypass;
                if (self.resolveImpl(allocator, current_name, qtype, depth)) |fresh| {
                    return .{ .served = fresh };
                } else |_| {
                    // Fresh attempt failed; fall through to the stale return below.
                }
            }

            switch (result) {
                .hit => |h| return .{
                    .served = .{
                        // RFC 4035 §5.3.1: RRSIGs travel in the same section as
                        // their covered RRset. Concatenate sigs onto the answer-
                        // section records so a DO=1 / CD=1 cache-served client
                        // can validate; the wire shaper strips them for DO=0.
                        // For wildcard-expanded answers, h.nsec_proofs carries
                        // the §3.1.3.4 "no closer match" NSEC proofs from the
                        // original response.
                        .message = try withCnameChain(allocator, chain, synthesizedMessage(try concatRRs(allocator, h.records, h.sigs), h.nsec_proofs, .no_error, h.security_status == .secure)),
                        .prefetch_name = prefetch_out,
                        .prefetch_qtype = qtype,
                    },
                },
                .negative => |n| return .{ .served = try negativeResolveResult(allocator, n.soa, n.nsec_proofs, n.rcode, n.security_status == .secure, prefetch_out, qtype, chain) },
            }
        }

        // Direct miss. Probe (current_name, .cname): the dual-stack win.
        // A prior A query may have cached the redirect; a subsequent AAAA
        // can reuse it instead of re-walking from root. Unbound / BIND /
        // PowerDNS / Knot all collapse this path.
        if (qtype == .cname) return .none;
        const cname_result = c.lookup(allocator, current_name, .cname, .in) orelse return .none;
        switch (cname_result) {
            .hit => |h| {
                // Stale CNAME at the head of the chain: skip the follow
                // and let the upstream path run. Mid-chain stale is
                // already a degraded answer — the chain head was fresh
                // when we entered — so following is acceptable there.
                if (h.is_stale and chain.records.items.len == 0) return .none;
                if (h.records.len == 0) return .none;
                // The redirect itself is aging. This was previously dropped
                // on the floor — the CNAME RRset near expiry never triggered
                // a refresh from the follow path, only from a direct
                // (name, .cname) hit, which stub queries never produce.
                if (h.needs_prefetch) self.pending_chain_prefetch = true;
                return .{ .follow_cname = .{
                    .cname_rr = h.records[0],
                    .security_status = h.security_status,
                    .nsec_proofs = h.nsec_proofs,
                } };
            },
            .negative => return .none, // cached NXDOMAIN/NODATA on .cname → upstream path handles it
        }
    }

    /// RFC 8198 aggressive NSEC use: synthesize negative or wildcard
    /// responses from cached NSEC proofs without an upstream round-trip.
    /// Returns null when no usable proof is cached, when a wildcard
    /// match's target RRset isn't cached (caller falls through to
    /// upstream per RFC 8198 §5.3 MUST), or when the cache is bypassed
    /// / DNSSEC is disabled.
    fn tryServeFromAggressiveNsec(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        target_name: dns.Name,
        current_name: []const u8,
        qtype: dns.RType,
        chain: *const CnameChain,
    ) !?ResolveResult {
        if (self.bypass_cache or !self.dnssec_enabled) return null;
        const nc = self.nsec_cache orelse return null;
        const synth = nc.lookupSuffixes(allocator, target_name, qtype, current_name) orelse return null;
        switch (synth.rcode) {
            .nxdomain, .nodata => |rc| {
                const rcode: dns.RCode = if (rc == .nxdomain) .name_error else .no_error;
                return try negativeResolveResult(allocator, synth.soa, synth.proofs, rcode, true, null, qtype, chain);
            },
            .wildcard_match => {
                if (try self.tryWildcardSynth(allocator, synth.ce_label_count, synth.soa, synth.proofs, target_name, qtype, chain)) |result| {
                    return .{ .message = result };
                }
                return null;
            },
        }
    }

    /// RFC 8020: NXDOMAIN means there is nothing underneath. If any
    /// unsigned ancestor has a cached NXDOMAIN, this child does not
    /// exist either — short-circuit. Signed-zone NXDOMAIN cuts go
    /// through the NSEC aggressive-use path in `resolveImpl`.
    ///
    /// Always served as AD=0: the cached entry proves the ancestor
    /// doesn't exist, not the descendant qname. `n.nsec_proofs` flows
    /// through anyway so a CD=1 client can chase the proof itself.
    fn tryServeFromNxdomainAncestor(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        current_name: []const u8,
        qtype: dns.RType,
        chain: *const CnameChain,
    ) !?ResolveResult {
        if (self.bypass_cache) return null;
        const c = self.cache orelse return null;
        const result = c.lookupNxdomainAncestor(allocator, current_name, qtype, .in) orelse return null;
        switch (result) {
            .negative => |n| return try negativeResolveResult(allocator, n.soa, n.nsec_proofs, .name_error, false, null, qtype, chain),
            .hit => return null, // ancestor exists positively — no RFC 8020 cut applies
        }
    }

    /// DNSSEC: a server authoritative for both parent and child can
    /// answer directly without a referral, so `classifyDelegation` never
    /// ran. Probe DS at every depth from parent+1 to the leaf — one of
    /// those names is the real cut. Demotes `security_state` to
    /// `.insecure` on the first cached insecure-DS hit.
    fn probeParentChildCut(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        target_name: dns.Name,
        parent_zone: dns.Name,
        response: *const dns.Message,
        servers: []const na.Address,
        security_state: *dnssec.SecurityStatus,
    ) void {
        if (!self.dnssec_enabled or security_state.* != .secure) return;
        if (target_name.labels.len <= parent_zone.labels.len) return;
        if (!response.header.flags.aa or hasSignedRecords(response.*)) return;

        var probe_depth: usize = parent_zone.labels.len + 1;
        while (probe_depth <= target_name.labels.len) : (probe_depth += 1) {
            const cut_labels = target_name.labels[target_name.labels.len - probe_depth ..];
            const candidate_cut = dns.Name{ .labels = cut_labels };
            var cut_buf: [dns.max_name_len + 1]u8 = undefined;
            const cut_name = candidate_cut.formatInto(&cut_buf);
            if (self.reproveDelegationSecurity(allocator, cut_name, servers) == null and
                hasCachedInsecureDelegation(self.keyCache(), allocator, candidate_cut))
            {
                security_state.* = .insecure;
                break;
            }
        }
    }

    /// Aggregate wildcard-expansion NSEC/NSEC3 proofs from this hop's
    /// authority before moving past it. Three gates: secure CNAME
    /// (DNSKEY warm), proof-material pre-scan with cheap bailiwick to
    /// skip the DNSKEY fetch on the common no-proof case, then
    /// `verifyAuthoritySigs` for crypto truth. An unverified scoop here
    /// is an injection path — attacker stuffs forged NSEC into a
    /// `.secure` chain and AD-trusting downstream believes it.
    fn aggregateCnameWildcardProofs(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        cname_status: cache_mod.SecurityStatus,
        authorities: []const dns.ResourceRecord,
        parent_zone: dns.Name,
        servers: []const na.Address,
        cname_auth_aggregate: *std.ArrayListUnmanaged(dns.ResourceRecord),
    ) !void {
        if (cname_status != .secure or authorities.len == 0) return;
        var has_proof = false;
        for (authorities) |auth_rr| {
            if (dns.isNsecProofMaterial(auth_rr) and auth_rr.name.isSubdomainOf(parent_zone)) {
                has_proof = true;
                break;
            }
        }
        if (!has_proof) return;
        if (self.verifyAuthoritySigs(allocator, authorities, servers, null) != .secure) return;
        for (authorities) |auth_rr| {
            if (dns.isNsecProofMaterial(auth_rr))
                try cname_auth_aggregate.append(allocator, auth_rr);
        }
    }

    // ── Referral following ──────────────────────────────────────────────

    /// Process a referral: classify DNSSEC delegation, detect loops,
    /// resolve glueless NS if needed, and update iteration state.
    fn followReferral(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        referral: ReferralResult,
        authorities: []const dns.ResourceRecord,
        depth: usize,
        security_state: *dnssec.SecurityStatus,
        parent_zone: *dns.Name,
        servers: *[max_servers_per_level]na.Address,
        server_count: *usize,
        seen_zones: *[max_delegations]dns.Name,
        seen_zone_count: *usize,
    ) !void {
        const zone_cut = switch (referral) {
            .referral => |ref| ref.zone_cut,
            .no_glue => |ng| ng.zone_cut,
        };

        // DNSSEC: classify delegation security (RFC 4035 §5.2)
        if (security_state.* == .secure) {
            security_state.* = self.ensureDelegationSecurity(allocator, zone_cut, authorities, servers.*[0..server_count.*]);
        }

        const addrs: NsAddrResult = switch (referral) {
            .referral => |ref| .{ .addrs = ref.addrs, .count = ref.count },
            .no_glue => |ng| blk: {
                if (try self.lookupCachedNsAddresses(allocator, ng.ns_names[0..ng.ns_count])) |res| break :blk res;
                const resolved = try self.resolveNsAddresses(allocator, ng.ns_names[0..ng.ns_count], depth);
                break :blk resolved orelse return error.NoGlueRecords;
            },
        };

        // Depth cap first: cheaper than the dup-scan and prevents the
        // OOB write at the bottom (seen_zones is sized to max_delegations).
        if (seen_zone_count.* >= max_delegations) return error.MaxDelegationsExceeded;
        for (seen_zones.*[0..seen_zone_count.*]) |sz| {
            if (sz.eql(zone_cut)) return error.ReferralLoop;
        }
        seen_zones.*[seen_zone_count.*] = zone_cut;
        seen_zone_count.* += 1;

        parent_zone.* = zone_cut;
        server_count.* = addrs.count;
        @memcpy(servers.*[0..addrs.count], addrs.addrs[0..addrs.count]);
    }

    // ── Final response handling ─────────────────────────────────────────

    /// RFC 9520 §3: cache a resolution failure so the next stub retry
    /// doesn't re-walk the whole upstream chain. Pinned against the
    /// original qname (`name`) so mid-CNAME failures still short-circuit
    /// the stub's retry of the outer query. 5 s TTL enforced by
    /// `storeNegativeBare`.
    ///
    /// Only at the user-facing query (depth == 0). At sub-recursion
    /// depths the caller is the resolver itself (NS A/AAAA fanout,
    /// internal DS probes); a cached failure there collapses sibling
    /// fanout and turns one transient blip into a 5 s outage for every
    /// name whose delegation NSes overlap with the failed lookup —
    /// which is exactly the NoGlueRecords path on out-of-bailiwick NS
    /// like dynect.net.
    fn cacheResolutionFailure(self: *RecursiveResolver, name: []const u8, qtype: dns.RType, depth: usize) void {
        @branchHint(.cold);
        if (depth != 0) return;
        if (self.cache) |c| c.cacheServfail(name, qtype);
    }

    /// Final-query response with `rcode != no_error`. AA-NXDOMAIN runs
    /// the verified-negative dance and caches the proven negative;
    /// SERVFAIL/REFUSED routes through `cacheResolutionFailure`. Other
    /// rcodes (FORMERR, NOTIMP, …) fall through uncached — caller
    /// receives the raw response.
    fn handleErrorResponse(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        response: *dns.Message,
        current_name: []const u8,
        name: []const u8,
        qtype: dns.RType,
        depth: usize,
        security_state: dnssec.SecurityStatus,
        target_name: dns.Name,
        parent_zone: dns.Name,
        servers: []const na.Address,
        chain: *const CnameChain,
    ) !ResolveResult {
        if (response.header.flags.rcode == .name_error and response.header.flags.aa) {
            var neg_ttl_cap: u32 = std.math.maxInt(u32);
            switch (self.verifiedNegativeResponse(allocator, security_state, response.authorities, target_name, qtype, true, parent_zone, servers, &neg_ttl_cap)) {
                .proceed => |status| {
                    if (self.cache) |c| c.storeNegative(current_name, qtype, .in, .name_error, response.authorities, parent_zone, status, neg_ttl_cap);
                    if (status == .secure) {
                        response.header.flags.ad = true;
                        self.storeNsec(response.authorities, parent_zone, neg_ttl_cap);
                        try trimSectionTtls(allocator, &response.authorities, neg_ttl_cap);
                    }
                },
                .skip_cache => {},
                .bogus => return self.bogusServfail(current_name, qtype),
            }
        } else if (response.header.flags.rcode == .server_failure or response.header.flags.rcode == .refused) {
            self.cacheResolutionFailure(name, qtype, depth);
        }
        return .{ .message = try withCnameChain(allocator, chain, response.*) };
    }

    /// Validate the final answer RRsets (DNSSEC) and cache them, then
    /// return through the active CNAME chain. ANY responses are not
    /// cached — RFC 8482 makes them server-policy, so unauthenticated
    /// constituents would become a poisoning channel for later per-type
    /// lookups.
    fn finalizeAnswer(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        response: *dns.Message,
        current_name: []const u8,
        qtype: dns.RType,
        security_state: dnssec.SecurityStatus,
        parent_zone: dns.Name,
        servers: []const na.Address,
        responding_server: ?na.Address,
        chain: *const CnameChain,
    ) !ResolveResult {
        var answer_status: cache_mod.SecurityStatus = .unchecked;
        var answer_ttl_cap: u32 = std.math.maxInt(u32);
        if (self.dnssec_enabled) {
            switch (try self.validateAnswer(allocator, response, qtype, security_state, parent_zone, servers)) {
                .bogus => {
                    self.recordNsOutcome(parent_zone, responding_server, .validation_failure, 0);
                    return self.bogusServfail(current_name, qtype);
                },
                .valid => |cap| {
                    answer_status = .secure;
                    answer_ttl_cap = cap;
                },
                .skip => {},
            }
        }
        if (self.cache) |c| if (qtype != .any) {
            c.storeResponse(response.*, parent_zone, answer_status, answer_ttl_cap);
            if (answer_status == .secure and self.nsec_cache != null) {
                self.storeWildcardRRsets(response.answers, qtype, answer_ttl_cap);
            }
        };
        return .{ .message = try withCnameChain(allocator, chain, response.*) };
    }

    /// NODATA terminal (no answers, no referral). AA responses run the
    /// verified-negative dance and cache the proven negative. Non-AA
    /// responses route through `cacheResolutionFailure` — a
    /// non-authoritative server returning empty without a referral can't
    /// advance resolution.
    fn finalizeNodata(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        response: *dns.Message,
        current_name: []const u8,
        name: []const u8,
        qtype: dns.RType,
        depth: usize,
        security_state: dnssec.SecurityStatus,
        target_name: dns.Name,
        parent_zone: dns.Name,
        servers: []const na.Address,
        chain: *const CnameChain,
    ) !ResolveResult {
        if (response.header.flags.aa) {
            var neg_ttl_cap: u32 = std.math.maxInt(u32);
            switch (self.verifiedNegativeResponse(allocator, security_state, response.authorities, target_name, qtype, false, parent_zone, servers, &neg_ttl_cap)) {
                .proceed => |status| {
                    if (self.cache) |c| {
                        c.storeResponse(response.*, parent_zone, .unchecked, std.math.maxInt(u32));
                        c.storeNegative(current_name, qtype, .in, .no_error, response.authorities, parent_zone, status, neg_ttl_cap);
                    }
                    if (status == .secure) {
                        response.header.flags.ad = true;
                        self.storeNsec(response.authorities, parent_zone, neg_ttl_cap);
                        try trimSectionTtls(allocator, &response.authorities, neg_ttl_cap);
                    }
                },
                .skip_cache => {},
                .bogus => return self.bogusServfail(current_name, qtype),
            }
        } else {
            self.cacheResolutionFailure(name, qtype, depth);
        }
        return .{ .message = try withCnameChain(allocator, chain, response.*) };
    }

    // ── Delegation security ────────────────────────────────────────────

    /// Determine delegation security for a zone cut (RFC 4035 §5.2).
    /// Tries verified NSEC/NSEC3 from referral authorities first, then
    /// falls back to cached/fetched DS status from parent servers.
    fn ensureDelegationSecurity(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_cut: dns.Name,
        authorities: []const dns.ResourceRecord,
        parent_servers: []const na.Address,
    ) dnssec.SecurityStatus {
        if (authorities.len > 0) {
            var proof_ttl_cap: u32 = std.math.maxInt(u32);
            const auth_status = self.verifyAuthoritySigs(allocator, authorities, parent_servers, &proof_ttl_cap);
            if (auth_status == .secure) {
                const status = dnssec.classifyDelegation(authorities, zone_cut, self.validationBudget());
                cacheInsecureDelegation(self.keyCache(), status, zone_cut, authorities, proof_ttl_cap);
                return status;
            }
            if (auth_status == .bogus) return .secure; // forged NSEC — don't downgrade
        }
        // No verified NSEC — check/fetch DS from parent (RFC 4035 §5.2).
        var zone_buf: [dns.max_name_len + 1]u8 = undefined;
        if (self.reproveDelegationSecurity(allocator, zone_cut.formatInto(&zone_buf), parent_servers) != null)
            return .secure;
        return if (hasCachedInsecureDelegation(self.keyCache(), allocator, zone_cut)) .insecure else .secure;
    }

    /// Try to synthesize a wildcard answer from the main RRset cache.
    /// Returns a synthesized message on success, or null to fall through to upstream.
    fn tryWildcardSynth(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ce_label_count: u8,
        soa: dns.ResourceRecord,
        nsec_proofs: []const dns.ResourceRecord,
        target_name: dns.Name,
        qtype: dns.RType,
        chain: *const CnameChain,
    ) !?dns.Message {
        if (ce_label_count == 0 or target_name.labels.len < ce_label_count) return null;
        // Build *.CE from qname labels and format as dotted string for cache lookup
        const ce = dns.Name{ .labels = target_name.labels[target_name.labels.len - ce_label_count ..] };
        var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
        const wc_name = dns.makeWildcardName(&wc_labels_buf, ce) orelse return null;
        var wc_buf: [dns.max_name_len + 1]u8 = undefined;
        const wc_dotted = wc_name.formatInto(&wc_buf);

        const c = self.cache orelse return null;
        const wc_result = c.lookup(allocator, wc_dotted, qtype, .in) orelse return null;
        switch (wc_result) {
            .hit => |h| {
                // Rewrite owner names to the queried name (RFC 4592 §2.2).
                // Lowercase to keep client-typed case out of the
                // synthesized owner. Clear `rr.wire` / `rr.wire_ttl_offset`
                // so `writeResourceRecord`'s fast path does not memcpy the
                // cached `*.CE` wire blob and overwrite our rewrite. RFC
                // 4035 §3.1.3.4: the RRSIG's labels field stays at the
                // wildcard depth so a DO=1 client reconstructs `*.CE`
                // from qname and revalidates.
                const lc_target = try dns.cloneNameLower(allocator, target_name);
                for (h.records) |*rr| {
                    rr.name = lc_target;
                    rr.wire = null;
                    rr.wire_ttl_offset = 0;
                }
                for (h.sigs) |*rr| {
                    rr.name = lc_target;
                    rr.wire = null;
                    rr.wire_ttl_offset = 0;
                }
                const answer = try concatRRs(allocator, h.records, h.sigs);
                const authority = try buildNegativeAuthority(allocator, soa, nsec_proofs);
                return try withCnameChain(allocator, chain, synthesizedMessage(answer, authority, .no_error, h.security_status == .secure));
            },
            .negative => return null,
        }
    }

    /// Store validated NSEC records in the aggressive NSEC cache.
    fn storeNsec(self: *RecursiveResolver, authorities: []const dns.ResourceRecord, zone: dns.Name, ttl_cap: u32) void {
        if (self.nsec_cache) |nc| {
            nc.storeFromAuthority(authorities, zone, ttl_cap);
        }
    }

    /// Null-guard wrapper: report an exchange outcome to the NS selector,
    /// tolerating both a missing selector and an unknown responding server.
    fn recordNsOutcome(self: *RecursiveResolver, zone: dns.Name, server: ?na.Address, outcome: NsOutcome, elapsed_us: i64) void {
        const ns = self.ns_selector orelse return;
        ns.recordOutcome(zone, server orelse return, outcome, elapsed_us);
    }

    /// Detect wildcard expansion in validated answers and store the wildcard RRset
    /// in the main cache under the wildcard name (e.g. *.example.com) for later
    /// synthesis by the NSEC cache (RFC 8198 §5.3).
    fn storeWildcardRRsets(
        self: *RecursiveResolver,
        answers: []const dns.ResourceRecord,
        qtype: dns.RType,
        ttl_cap: u32,
    ) void {
        // Pick the RRSIG covering qtype with the highest `labels` count
        // (narrowest wildcard). A smaller-labels forgery alongside the
        // real RRSIG would otherwise widen the cached wildcard owner —
        // e.g. forge labels=1 against real labels=2 to install *.com.
        // Larger-labels forgeries only narrow scope (DoS on aggressive
        // NSEC at this zone, no poisoning).
        var rrsig: ?dns.RrsigData = null;
        for (answers) |rr| {
            if (dns.rrsigCovers(rr) != qtype) continue;
            if (rrsig == null or rr.rdata.rrsig.labels > rrsig.?.labels) {
                rrsig = rr.rdata.rrsig;
            }
        }
        const sig = rrsig orelse return;

        // Single pass: detect wildcard expansion from the first expanded answer record,
        // then collect all qtype records + covering RRSIGs with wildcard owner name.
        var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
        var wildcard_owner: ?dns.Name = null;
        // Typical wildcard RRsets are 1-3 records. Overflow abandons the store
        // rather than truncating: this writes `.secure`, and tryWildcardSynth
        // serves it as an AD=1 answer with no TC=1 for the whole TTL, so a
        // silently-short set here is the "wrong-and-cached" shape the store
        // path elsewhere refuses. `dominated` counts RRSIGs too, so a dual-algo
        // A RRset reaches this at ~14 addresses.
        var wc_records: [16]dns.ResourceRecord = undefined;
        var wc_count: usize = 0;
        for (answers) |ans_rr| {
            if (wildcard_owner == null and ans_rr.rtype == qtype and ans_rr.name.labels.len > sig.labels) {
                const ce = dns.Name{ .labels = ans_rr.name.labels[ans_rr.name.labels.len - sig.labels ..] };
                wildcard_owner = dns.makeWildcardName(&wc_labels_buf, ce);
            }
            const wco = wildcard_owner orelse continue;
            const dominated = ans_rr.rtype == qtype or dns.rrsigCovers(ans_rr) == qtype;
            if (dominated) {
                // Only a record that genuinely does not fit abandons the
                // store — a full buffer with only non-dominated records left
                // to scan is a complete collect.
                if (wc_count == wc_records.len) return;
                wc_records[wc_count] = ans_rr;
                wc_records[wc_count].name = wco;
                wc_count += 1;
            }
        }
        if (wc_count == 0) return;

        const signer_zone = sig.signer_name;
        if (self.cache) |c| {
            // storeResponse reads only rcode + record sections, so the
            // synthesizedMessage header vehicle is as good as a bespoke one.
            c.storeResponse(synthesizedMessage(wc_records[0..wc_count], &.{}, .no_error, false), signer_zone, .secure, ttl_cap);
        }
    }

    // ── UDP+TCP query helper ──────────────────────────────────────────

    /// Send a UDP query to a single server with TC-bit TCP fallback and RTT tracking.
    /// Returns the parsed response, or null on failure (timeout, parse error, etc.).
    fn queryServerUdp(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        wire_query: []const u8,
        query_id: u16,
        server: na.Address,
        timeout: u32,
    ) error{OutOfMemory}!?dns.Message {
        const addr_key = AddressKey.fromAddress(server);
        const query_start = monotonic.nowUs();

        // Fresh per-hop response_buf in the caller arena: parsed Name/rdata
        // slices alias this buffer, and state such as parent_zone,
        // seen_zones, and cname_chain keeps referring to earlier-hop parse
        // output across loop iterations — each hop needs its own buffer so
        // those slices survive until the arena resets.
        const response_buf = try allocator.alloc(u8, dns.edns_udp_payload);
        const response_data = self.transports.?.udp.queryWithTimeout(
            wire_query,
            query_id,
            server,
            timeout,
            response_buf,
        ) catch |err| {
            if (self.rtt_cache) |rc| rc.recordTimeout(addr_key);
            if (err != error.Timeout) {
                var addr_buf: [64]u8 = undefined;
                log.debug("UDP query to {s} failed: {s}", .{ na.format(server, &addr_buf), @errorName(err) });
            }
            return null;
        };
        const elapsed_us = monotonic.nowUs() - query_start;

        // Record liveness — truncated responses still prove server is alive
        if (self.rtt_cache) |rc| rc.recordSuccess(addr_key, elapsed_us);

        // RFC 2181 §9: TC-set UDP response must be retried over TCP.
        if (dns.hasTcBit(response_data)) {
            return self.tcpFallback(allocator, wire_query, server);
        }

        return try tryParseMessage(allocator, response_data, server);
    }

    /// Issue the query over TCP (pooled if available). Returns null if TCP
    /// isn't configured, the request fails, or the response is malformed.
    /// Caller is responsible for question-match validation when needed.
    fn tcpFallback(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        wire_query: []const u8,
        server: na.Address,
    ) error{OutOfMemory}!?dns.Message {
        if (!self.transports.?.tcp_enabled) return null;
        const tcp_buf = try allocator.alloc(u8, dns.max_message_len);
        const tcp_data = blocking_transport.queryTcp(self.io, wire_query, server, tcp_buf, self.tcp_pool) catch |err| {
            var addr_buf: [64]u8 = undefined;
            log.debug("TCP fallback to {s} failed: {s}", .{ na.format(server, &addr_buf), @errorName(err) });
            return null;
        };
        return try tryParseMessage(allocator, tcp_data, server);
    }

    /// Returns the RNG to randomize an outgoing query to `addr_key`, or
    /// null if 0x20 is disabled or this server has been marked mangling.
    fn caseRng(self: *RecursiveResolver, addr_key: AddressKey) ?std.Io {
        const cs = self.case_state orelse return null;
        return if (cs.shouldRandomize(addr_key)) self.io else null;
    }

    /// Mark a server as 0x20 case-mangling. Subsequent queries to it skip
    /// randomization for `reprobe_sec`.
    fn markCaseBroken(self: *RecursiveResolver, server: na.Address) void {
        const cs = self.case_state orelse return;
        cs.markBroken(AddressKey.fromAddress(server));
        var addr_buf: [64]u8 = undefined;
        log.debug("0x20 case mangled by {s}; marking non-conformant", .{na.format(server, &addr_buf)});
    }

    /// True only when the echoed question is the query name with mangled
    /// byte case. Error rcodes are exempt from question-match (RFC 9619 /
    /// validateResponse), so a reply can arrive question-less or carrying
    /// an unrelated question — neither is evidence of case-mangling and
    /// must not mark the server broken.
    fn caseMangledEcho(query_name: dns.Name, response: dns.Message) bool {
        return response.questions.len == 1 and
            query_name.eql(response.questions[0].name) and
            !query_name.eqlExact(response.questions[0].name);
    }

    /// Result of one case-hardened Do53 exchange with a single server.
    const Do53Result = union(enum) {
        /// Question echo verified; rcode policy stays with the caller.
        response: struct { message: dns.Message, elapsed_us: i64 },
        /// Transport timeout/error or unparseable reply.
        timeout,
        /// A reply arrived but failed question validation (RFC 5452 §9.1).
        mismatch,
    };

    /// The 0x20 retry kernel — single home for case-hardened Do53 (both
    /// queryAuthoritativeServers and fetchRRset go through here). Build
    /// the query with per-server case randomization and a fresh TXID per
    /// attempt (RFC 5452 §9.2), send over UDP (TC falls back to TCP inside
    /// queryServerUdp), and verify the exact-case QNAME echo: a mangled
    /// echo means the server (or a middlebox in front of it) mangled case
    /// — mark it and resend once in lowercase; the reprobe TTL on the
    /// marker recovers automatically if the middlebox is later removed.
    /// The echo check goes through caseMangledEcho — see its doc for why
    /// question-less and unrelated-question replies are exempt.
    fn do53CaseHardened(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        name: []const u8,
        qtype: dns.RType,
        server: na.Address,
        timeout: u32,
        do_bit: bool,
    ) !Do53Result {
        var case_rng = self.caseRng(AddressKey.fromAddress(server));
        while (true) {
            const query_id = rand.queryId(self.io);
            const query_msg = try dns.buildQuery(allocator, query_id, name, qtype, .{
                .rd = false,
                .edns = .{ .do_bit = do_bit },
                .case_rng = case_rng,
            });
            var wire_buf: [dns.edns_udp_payload]u8 = undefined;
            const wire_query = try dns.serializeMessage(&wire_buf, query_msg);

            const start_us = monotonic.nowUs();
            const response = try self.queryServerUdp(allocator, wire_query, query_id, server, timeout) orelse
                return .timeout;
            const elapsed_us = monotonic.nowUs() - start_us;

            // RFC 5452 §9.1 / RFC 9619: question must match; error rcodes exempt.
            dns.validateResponse(response, query_msg.questions[0].name, qtype) catch return .mismatch;

            if (case_rng != null and caseMangledEcho(query_msg.questions[0].name, response)) {
                self.markCaseBroken(server);
                case_rng = null;
                continue;
            }
            return .{ .response = .{ .message = response, .elapsed_us = elapsed_us } };
        }
    }

    /// RFC 9539: opportunistic encrypted query to a known-capable server.
    /// TLS authenticates the channel, so 0x20 is redundant — the QNAME goes
    /// lowercase, padded per RFC 8467. Returns the validated response
    /// (rcode policy is the caller's); null falls back to Do53.
    fn tryOpportunisticTls(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        name: []const u8,
        qtype: dns.RType,
        server: na.Address,
    ) !?dns.Message {
        // Caller gates on `.capable`; a stale read costs at worst one
        // wasted pooled attempt.
        const tls_t = self.transports.?.tls orelse return null;
        const oc = self.encrypted_ns_cache orelse return null;
        const tls_key = AddressKey.fromAddressWithPort(server, TlsTransport.port);

        const query_id = rand.queryId(self.io);
        const padded_msg = try dns.buildQuery(allocator, query_id, name, qtype, .{
            .rd = false,
            .edns = .{ .do_bit = self.dnssec_aware, .padding_block = dns.dot_padding_block },
        });
        var padded_buf: [dns.edns_udp_payload]u8 = undefined;
        const padded_query = try dns.serializeMessage(&padded_buf, padded_msg);

        // Fixed 4s: encryption may cost more than Do53 — accepted trade.
        const deadline_ns = monotonic.nowNs() + 4000 * std.time.ns_per_ms;
        const tls_data = switch (tls_t.queryPooled(allocator, padded_query, server, deadline_ns)) {
            .data => |data| data,
            .none => {
                // Cold pool: serve over Do53 now, re-dial in background.
                tls_t.probeInBackground(server, oc, .rewarm);
                return null;
            },
            // RFC 9539 §4.3: transport failure on a known-capable server
            // is soft (timeout, RST, transient).
            .broken => {
                oc.setStatus(tls_key, .soft_failed);
                return null;
            },
        };
        // Semantic rejection over a healthy transport (bad parse, FORMERR
        // — likely the padding option — question mismatch) is deterministic
        // per-server: hard band.
        const response = try tryParseMessage(allocator, tls_data, server) orelse {
            oc.setStatus(tls_key, .failed);
            return null;
        };
        if (response.header.flags.rcode == .format_error) {
            oc.setStatus(tls_key, .failed);
            return null;
        }
        if (!dns.validateQuestionMatch(response, padded_msg.questions[0].name, qtype)) {
            // RFC 9619: error replies may omit the question section, as on
            // the Do53 path — no demotion for that shape.
            if (response.questions.len == 0 and response.header.flags.rcode.isServerError()) return null;
            oc.setStatus(tls_key, .failed);
            return null;
        }
        // Clear the Do53 death ratchet; RTT estimates stay untouched.
        if (self.rtt_cache) |rc| rc.recordAlive(AddressKey.fromAddress(server));
        _ = oc.dot_answers.fetchAdd(1, .monotonic);
        return response;
    }

    // ── Staggered NS Racing ─────────────────────────────────────────────

    const StaggeredResponse = struct {
        message: dns.Message,
        server: na.Address,
    };

    /// Cap on simultaneous staggered legs. Matches typical ns_fetch_limit at
    /// depth 0; must not exceed `BlockingUdpTransport.max_staggered_legs`.
    const max_staggered_legs: usize = 3;

    comptime {
        std.debug.assert(max_staggered_legs <= BlockingUdpTransport.max_staggered_legs);
    }

    fn tryStaggeredQuery(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        query_name: []const u8,
        query_type: dns.RType,
        servers: *[max_servers_per_level]na.Address,
        sel: NsSelector.Selection,
        parent_zone: dns.Name,
    ) error{OutOfMemory}!?StaggeredResponse {
        // Collect up to max_staggered_legs distinct-IP servers from the
        // live prefix of `sel.order`. selectServers already classified
        // dead-vs-live via RttCache.isDead and put live first; iterating
        // `[0..sel.live_count]` skips the dead tail without a second
        // lock+probe per server. Racing duplicate IPs wouldn't add
        // birthday entropy (RFC 5452) or latency diversity — dedupe by IP.
        var leg_idxs: [max_staggered_legs]usize = undefined;
        var leg_count: usize = 0;
        outer: for (sel.order[0..sel.live_count]) |idx| {
            for (leg_idxs[0..leg_count]) |prev| {
                if (na.ipEqual(servers[idx], servers[prev])) continue :outer;
            }
            leg_idxs[leg_count] = idx;
            leg_count += 1;
            if (leg_count >= max_staggered_legs) break;
        }
        if (leg_count < 2) return null;

        const stagger = if (self.rtt_cache) |rc|
            rc.getHedgeStagger(AddressKey.fromAddress(servers[leg_idxs[0]]))
        else
            self.stagger_ms;

        const overall_timeout = self.transports.?.udp.config.timeout_ms;

        // Build leg 0 once, memcpy + patch ID for the rest. One stack buffer
        // per leg because each socket's send holds the wire bytes past the
        // individual call.
        var wires_storage: [max_staggered_legs][dns.edns_udp_payload]u8 = undefined;
        var wires: [max_staggered_legs][]const u8 = undefined;
        var qids: [max_staggered_legs]u16 = undefined;
        var leg_addrs: [max_staggered_legs]na.Address = undefined;

        // All legs share one case pattern (memcpy + ID-patch optimization),
        // so disable 0x20 if any leg is marked. Per-leg builds would let
        // unmarked legs keep 0x20, but cost extra serializes and a per-leg
        // sent-name table to verify the winner against. The sequential
        // fallback preserves per-server protection, so the staggered path
        // can take the simpler hit. Trade reconsidered if measurement
        // shows the sequential fallback is firing often.
        var case_rng: ?std.Io = self.caseRng(AddressKey.fromAddress(servers[leg_idxs[0]]));
        if (case_rng != null) {
            for (leg_idxs[1..leg_count]) |idx| {
                if (self.caseRng(AddressKey.fromAddress(servers[idx])) == null) {
                    case_rng = null;
                    break;
                }
            }
        }

        qids[0] = rand.queryId(self.io);
        const msg0 = dns.buildQuery(allocator, qids[0], query_name, query_type, .{
            .rd = false,
            .edns = .{ .do_bit = self.dnssec_aware },
            .case_rng = case_rng,
        }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else null;
        const w0 = dns.serializeMessage(&wires_storage[0], msg0) catch |err|
            return if (err == error.OutOfMemory) error.OutOfMemory else null;
        wires[0] = w0;
        leg_addrs[0] = servers[leg_idxs[0]];

        for (1..leg_count) |i| {
            qids[i] = rand.queryId(self.io);
            @memcpy(wires_storage[i][0..w0.len], w0);
            dns.patchQueryId(wires_storage[i][0..w0.len], qids[i]);
            wires[i] = wires_storage[i][0..w0.len];
            leg_addrs[i] = servers[leg_idxs[i]];
        }

        const query_start = monotonic.nowUs();
        const response_buf = try allocator.alloc(u8, dns.edns_udp_payload);
        const stag_result = self.transports.?.udp.queryStaggered(
            wires[0..leg_count],
            qids[0..leg_count],
            leg_addrs[0..leg_count],
            stagger,
            overall_timeout,
            response_buf,
        ) catch return null;

        const elapsed_us = monotonic.nowUs() - query_start;
        const winner = stag_result.responding_idx;
        const responding_addr = leg_addrs[winner];
        const addr_key = AddressKey.fromAddress(responding_addr);

        // RFC 2181 §9: TC-set response cannot be used. Retry the winning
        // server over TCP immediately; falling through to the sequential loop
        // would re-query servers that already lost the race (wasted UDP RTTs).
        const resp = if (dns.hasTcBit(stag_result.response_data))
            try self.tcpFallback(allocator, wires[winner], responding_addr) orelse return null
        else
            try tryParseMessage(allocator, stag_result.response_data, responding_addr) orelse return null;

        // RFC 5452 §9.1 / RFC 9619: reject responses whose question doesn't echo
        // the query. (The sequential path enforces this via queryAuthoritativeServers.)
        dns.validateResponse(resp, msg0.questions[0].name, query_type) catch return null;

        // 0x20 echo verify. Mark and bail to sequential, which will rebuild
        // lowercase against the same server and retry properly.
        if (case_rng != null and caseMangledEcho(msg0.questions[0].name, resp)) {
            self.markCaseBroken(responding_addr);
            return null;
        }

        // RFC 1034 §4.3.5 lame-NS fallthrough. The sequential server_loop
        // handles this via `last_server_failure`, but the race path returns
        // first-by-latency — so a fast-failing NS would propagate verbatim
        // without this check. Score and bail to sequential. FORMERR counts
        // (an EDNS-hostile auth shouldn't condemn the zone — try a sibling).
        if (resp.header.flags.rcode.shouldTrySiblingNs()) {
            self.recordNsOutcome(parent_zone, responding_addr, .server_error, elapsed_us);
            return null;
        }

        // Bookkeeping fires *after* every bail-out path above, so a fast
        // SERVFAIL / 0x20-mismatch / TC-then-TCP-failed winner isn't
        // double-counted as a healthy success on the Thompson arm.
        if (self.rtt_cache) |rc| rc.recordSuccess(addr_key, elapsed_us);
        self.recordNsOutcome(parent_zone, responding_addr, .success, elapsed_us);

        return .{ .message = resp, .server = responding_addr };
    }

    // ── Authoritative Server Query ────────────────────────────────────

    const ServerQueryResult = struct {
        message: dns.Message,
        responding_server: ?na.Address,
    };

    /// Query authoritative nameservers in selection order, with staggered
    /// racing and opportunistic TLS. Returns the first useful response.
    fn queryAuthoritativeServers(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        query_name: []const u8,
        query_type: dns.RType,
        servers: *[max_servers_per_level]na.Address,
        server_count: usize,
        parent_zone: dns.Name,
    ) anyerror!ServerQueryResult {
        if (self.cache_only) return error.CacheOnlyMiss;

        // Order servers: Thompson Sampling if available, Fisher-Yates otherwise
        var order_buf: [max_servers_per_level]usize = undefined;
        const sel = if (self.ns_selector) |ns|
            ns.selectServers(parent_zone, servers[0..server_count], self.rtt_cache, &order_buf)
        else blk: {
            rand.fastShuffle(na.Address, self.io, servers[0..server_count]);
            for (0..server_count) |idx| order_buf[idx] = idx;
            break :blk NsSelector.Selection{
                .order = order_buf[0..server_count],
                .live_count = server_count,
            };
        };

        var last_server_failure: ?dns.Message = null;

        // ── RFC 9539: capability discovery + encrypted-first ──
        // Probe the top-ranked candidates (not just responders — a capable
        // server can lose the race forever), then spend one TLS attempt on
        // the best-ranked capable one; the race below is UDP-only. Any
        // failure falls through to Do53. Probe surface to attacker-chosen
        // IPs is bounded by the special-use egress filter, per-IP claim
        // damping, and max_probes. All-Do53-dead zones get no discovery
        // until a server revives.
        if (self.encrypted_ns_cache) |oc| {
            if (self.transports.?.tls) |tls_t| {
                for (sel.order[0..@min(sel.live_count, max_staggered_legs)]) |idx|
                    tls_t.probeInBackground(servers[idx], oc, .discover);
                for (sel.order[0..sel.live_count]) |idx| {
                    const tls_key = AddressKey.fromAddressWithPort(servers[idx], TlsTransport.port);
                    if (oc.getStatus(tls_key) != .capable) continue;
                    if (try self.tryOpportunisticTls(allocator, query_name, query_type, servers[idx])) |tls_response| {
                        if (tls_response.header.flags.rcode.isServerError()) {
                            last_server_failure = tls_response;
                        } else {
                            // No RTT/selector feedback from TLS: its latency
                            // would poison the Do53 estimates.
                            return .{ .message = tls_response, .responding_server = null };
                        }
                    }
                    break;
                }
            }
        }

        // ── Staggered NS racing ──
        if (sel.order.len >= 2 and self.stagger_ms > 0) {
            if (try self.tryStaggeredQuery(allocator, query_name, query_type, servers, sel, parent_zone)) |stag| {
                if (self.encrypted_ns_cache) |oc| _ = oc.do53_answers.fetchAdd(1, .monotonic);
                return .{ .message = stag.message, .responding_server = stag.server };
            }
        }

        server_loop: for (sel.order, 0..) |server_idx, server_i| {
            const server = servers[server_idx];
            const addr_key = AddressKey.fromAddress(server);

            // Live servers come first; dead are appended at the tail. Skip
            // dead servers unless we have no live ones (`live_count == 0`,
            // partial-zone outage — every NS gets a retry shot, matching the
            // pre-dedupe behavior) or this is the very last entry (always
            // try *something*).
            const is_last_server = (server_i + 1 >= sel.order.len);
            const dead_skip = server_i >= sel.live_count and sel.live_count > 0 and !is_last_server;
            if (dead_skip) continue;

            const per_server_timeout = self.serverTimeout(addr_key, is_last_server);

            // ── Do53: UDP with TCP fallback, 0x20-hardened ──
            const exchange = switch (try self.do53CaseHardened(allocator, query_name, query_type, server, per_server_timeout, self.dnssec_aware)) {
                .timeout => {
                    self.recordNsOutcome(parent_zone, server, .timeout, 0);
                    continue :server_loop;
                },
                .mismatch => continue :server_loop,
                .response => |r| r,
            };
            const response = exchange.message;

            // Lame detection (RFC 4697): SERVFAIL/REFUSED → try next server.
            // FORMERR too (RFC 1034 §4.3.5): one parse-hostile NS must not
            // condemn a zone its siblings can still serve. recordNsOutcome
            // is the persistent per-zone+IP penalty (Thompson arm, reward
            // 0.1 — still selectable if siblings degrade).
            if (response.header.flags.rcode.shouldTrySiblingNs()) {
                self.recordNsOutcome(parent_zone, server, .server_error, exchange.elapsed_us);
                last_server_failure = response;
                continue :server_loop;
            }

            self.recordNsOutcome(parent_zone, server, .success, exchange.elapsed_us);
            if (self.encrypted_ns_cache) |oc| _ = oc.do53_answers.fetchAdd(1, .monotonic);
            return .{ .message = response, .responding_server = server };
        }

        // Fall back to last SERVFAIL/REFUSED if all servers failed
        if (last_server_failure) |sf| {
            return .{ .message = sf, .responding_server = null };
        }
        return error.Timeout;
    }

    // ── DNSSEC Answer Validation ───────────────────────────────────────

    /// RFC 9520 §3.2: minimum negative-cache TTL for DNSSEC validation failures.
    const dnssec_bogus_ttl: u32 = 1;

    /// Dedup follower timeout for DNSKEY fetches. Cold-cache DNSSEC chains
    /// (root → TLD → SLD → DNSKEY) can take 3-5s; 6s provides headroom.
    const dnskey_dedup_timeout_ns: u64 = 6 * std.time.ns_per_s;

    /// Dedup follower timeout for DS fetches. DS queries go to already-known
    /// parent servers (no chain walk), so 3s is sufficient.
    const ds_dedup_timeout_ns: u64 = 3 * std.time.ns_per_s;

    /// `.valid` carries the longest the answer may be cached, from the
    /// signatures that verified. Threaded to the store so the `min_ttl` floor
    /// cannot lift an entry back past its own proof.
    const AnswerValidation = union(enum) { valid: u32, bogus, skip };

    /// RFC 9520 §3.4: MUST cache DNSSEC validation failures.
    /// Caches a SERVFAIL with dnssec_bogus_ttl and returns SERVFAIL to the client.
    fn bogusServfail(self: *RecursiveResolver, name: []const u8, qtype: dns.RType) ResolveResult {
        @branchHint(.cold);
        if (self.cache) |c| c.storeNegativeBare(name, qtype, .in, .server_failure, dnssec_bogus_ttl, .unchecked, .unless_fresh);
        return .{ .message = synthesizedMessage(&.{}, &.{}, .server_failure, false) };
    }

    /// Sliced cache result the dedup helper hands back to its follower
    /// paths. `hit` carries the records, `negative` is the cached
    /// NXDOMAIN/NODATA sentinel — both come from a `CacheLookupResult`
    /// whose extra fields the dedup gate doesn't care about.
    const DedupCacheResult = union(enum) {
        hit: []const dns.ResourceRecord,
        negative,

        fn from(result: ?cache_mod.CacheLookupResult) ?DedupCacheResult {
            return switch (result orelse return null) {
                .hit => |h| .{ .hit = h.records },
                .negative => .negative,
            };
        }
    };

    /// Coalesce concurrent fetches for the same `(name, rtype)` through the
    /// dedup table. Leader runs `ctx.fetch`; followers wait, re-check the
    /// key cache, and if the leader produced nothing one follower retries
    /// as leader at half the timeout (the leader's partial work warmed
    /// intermediate caches, so a full timeout would over-wait). With no
    /// dedup table, calls `ctx.fetch` directly.
    ///
    /// Return type tracks `ctx.fetch` so non-erroring callers don't pay
    /// for an `anyerror` wrap and a matching `catch` at the call site.
    ///
    /// The caller does its own initial fast-path cache lookup so any read
    /// side effects (e.g. DNSKEY near-expiry prefetch flag) stay co-located
    /// with the lookup that triggered them.
    fn dedupedFetch(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        name: []const u8,
        rtype: dns.RType,
        timeout_ns: u64,
        ctx: anytype,
    ) @TypeOf(ctx.fetch()) {
        const dedup = self.dedup orelse return ctx.fetch();
        // Follower re-check of the key cache: same `(name, rtype)` the
        // leader just ran. Pulled into a closure so both follower hops
        // share one body.
        const recheck = struct {
            fn call(r: *RecursiveResolver, a: mem.Allocator, n: []const u8, t: dns.RType) ?DedupCacheResult {
                const cache = r.keyCache() orelse return null;
                return DedupCacheResult.from(cache.lookup(a, n, t, .in));
            }
        }.call;
        switch (dedup.acquireOrWaitWithTimeout(name, rtype, 0, monotonic.nowNs() + timeout_ns)) {
            .leader => {
                defer dedup.releaseLeader(name, rtype, 0);
                return ctx.fetch();
            },
            .follower => {
                if (recheck(self, allocator, name, rtype)) |r| return switch (r) {
                    .hit => |rr| rr,
                    .negative => null,
                };
                switch (dedup.acquireOrWaitWithTimeout(name, rtype, 0, monotonic.nowNs() + timeout_ns / 2)) {
                    .leader => {
                        defer dedup.releaseLeader(name, rtype, 0);
                        return ctx.fetch();
                    },
                    .follower => return switch (recheck(self, allocator, name, rtype) orelse return null) {
                        .hit => |rr| rr,
                        .negative => null,
                    },
                }
            },
        }
    }

    /// Fetch DNSKEY records for a zone, checking cache first.
    /// Uses the dedup table to coalesce concurrent DNSKEY fetches for the
    /// same zone — prevents N parallel queries from each firing their own
    /// DNSKEY network request on cold cache.
    fn fetchDnskey(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_name: []const u8,
        servers: []const na.Address,
    ) !?[]const dns.ResourceRecord {
        // Fast path: cache hit. The needs_prefetch side effect lives here,
        // not in the follower re-check — a leader that just populated fresh
        // records can't be near-expiry.
        if (self.keyCache()) |c| {
            if (c.lookup(allocator, zone_name, .dnskey, .in)) |result| switch (result) {
                .hit => |h| {
                    if (h.needs_prefetch and self.pending_dnskey_prefetch == null) {
                        @memcpy(self.pending_dnskey_buf[0..zone_name.len], zone_name);
                        self.pending_dnskey_prefetch = self.pending_dnskey_buf[0..zone_name.len];
                    }
                    return h.records;
                },
                .negative => return null,
            };
        }

        const Ctx = struct {
            self: *RecursiveResolver,
            allocator: mem.Allocator,
            zone_name: []const u8,
            servers: []const na.Address,

            fn fetch(c: @This()) !?[]const dns.ResourceRecord {
                return c.self.fetchAndValidateDnskey(c.allocator, c.zone_name, c.servers);
            }
        };

        return self.dedupedFetch(allocator, zone_name, .dnskey, dnskey_dedup_timeout_ns, Ctx{
            .self = self,
            .allocator = allocator,
            .zone_name = zone_name,
            .servers = servers,
        });
    }

    /// Fetch DNSKEY from network, validate against cached DS (RFC 4035 §5.3),
    /// and only cache after validation passes.
    fn fetchAndValidateDnskey(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_name: []const u8,
        servers: []const na.Address,
    ) !?[]const dns.ResourceRecord {
        // Network fetch — don't cache yet (RFC 4035 §5.3: validate first)
        const resp = try self.fetchRRset(allocator, zone_name, .dnskey, servers, 3, true, false) orelse return null;
        if (resp.answers.len == 0) return null;

        const zone_parsed = try dns.parseDottedName(allocator, zone_name);

        // Validate DNSKEY against cached DS before caching (RFC 4035 §5.2).
        // Only .secure DS is a valid trust anchor — any other status means
        // the parent-zone RRSIG never verified, so trusting it would let
        // forged DS + forged DNSKEY self-validate.
        const kc = self.keyCache();
        if (kc) |c| {
            if (c.lookup(allocator, zone_name, .ds, .in)) |result| {
                switch (result) {
                    .hit => |h| {
                        if (h.security_status != .secure) {
                            if (self.fetchDsFromParent(allocator, zone_name)) |ds_records| {
                                validateDnskeyAgainstDs(resp.answers, ds_records, zone_parsed, self.validationBudget()) catch return null;
                            } else return null;
                        } else {
                            validateDnskeyAgainstDs(resp.answers, h.records, zone_parsed, self.validationBudget()) catch return null;
                        }
                    },
                    // Proven-insecure delegation: no signed DNSKEYs to anchor.
                    // Returning the unvalidated answers would let the caller
                    // verify forged RRSIGs against forged DNSKEYs and stamp AD.
                    .negative => return null,
                }
            } else if (zone_name.len > 0) {
                // DS not in cache. Re-fetch from parent and validate against the
                // freshly fetched records — RFC 1035 §3.2.1 permits using TTL=0
                // RRs "for the transaction in progress" even though they will
                // not be retained in the cache. The negative-DS cache (with
                // NSEC TTL, not the suppressed DS TTL) still distinguishes
                // insecure delegations from outright failures.
                if (self.fetchDsFromParent(allocator, zone_name)) |ds_records| {
                    validateDnskeyAgainstDs(resp.answers, ds_records, zone_parsed, self.validationBudget()) catch return null;
                } else if (c.lookup(allocator, zone_name, .ds, .in)) |result| {
                    switch (result) {
                        // Insecure delegation proven during fetch — see above.
                        .negative => return null,
                        .hit => |h| validateDnskeyAgainstDs(resp.answers, h.records, zone_parsed, self.validationBudget()) catch return null,
                    }
                } else return null;
            } else {
                // Root zone: validate against the configured trust anchors
                // (default IANA; test harness overrides via ServerConfig).
                const now_u32 = epochNowU32();
                dnssec.validateDnskeyRrset(resp.answers, self.trust_anchors, zone_parsed, now_u32, self.validationBudget()) catch return null;
            }
        }

        // RFC 4035 §5.3: "the validator SHOULD cache the RRset" — after validation.
        // Store only answers to avoid polluting the key cache with NS/glue.
        if (kc) |c| c.storeResponse(answersOnly(resp), zone_parsed, .unchecked, std.math.maxInt(u32));

        return resp.answers;
    }

    /// Query authoritative servers for a specific RRset, with RTT tracking
    /// and dead-server skipping.  Returns the full message so callers that
    /// need the authority section (e.g. DS probes) can use it.
    fn fetchRRset(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_name: []const u8,
        qtype: dns.RType,
        servers: []const na.Address,
        max_servers: usize,
        do_bit: bool,
        store_response: bool,
    ) !?dns.Message {
        // Second upstream-touching entry alongside queryAuthoritativeServers.
        // findClosestCachedDelegation → reproveDelegationSecurity → here
        // reaches the UDP transport directly; without this guard the recv-
        // thread fast path crashes on `transports.?.udp` when the cached
        // delegation needs DS/DNSKEY re-prove.
        if (self.cache_only) return error.CacheOnlyMiss;
        if (servers.len == 0) return null;

        const authority_zone = try dns.parseDottedName(allocator, zone_name);

        const try_count = @min(servers.len, max_servers);
        // 0 when no rtt_cache — `RttCache.isDead` returns false against now=0,
        // which is the right "always live" fallback.
        const now_ms: i64 = if (self.rtt_cache) |rc| rc.nowMs() else 0;
        for (servers[0..try_count], 0..) |server, i| {
            const addr_key = AddressKey.fromAddress(server);

            if (self.rtt_cache) |rc| {
                if (rc.isDead(addr_key, now_ms) and i + 1 < try_count) continue;
            }

            // DS/DNSKEY fetches are upstream packets too; draw from the same
            // tree-wide budget so a signed-zone variant can't sidestep it.
            try self.consumeQuery();

            const timeout = self.serverTimeout(addr_key, i + 1 >= try_count);
            const response = switch (try self.do53CaseHardened(allocator, zone_name, qtype, server, timeout, do_bit)) {
                .timeout, .mismatch => continue,
                .response => |r| r.message,
            };
            if (response.header.flags.rcode != .no_error) continue;
            if (store_response) {
                if (self.cache) |c| c.storeResponse(response, authority_zone, .unchecked, std.math.maxInt(u32));
            }
            return response;
        }
        return null;
    }

    /// Re-fetch DS for a zone by finding the parent zone's NS in cache
    /// and querying them. Falls back to resolving NS addresses from the
    /// network when cached addresses have expired (simultaneous DS+DNSKEY
    /// TTL expiry). Returns the DS records on signed delegation, null on
    /// insecure (negative cached) or failure.
    fn fetchDsFromParent(self: *RecursiveResolver, allocator: mem.Allocator, zone_name: []const u8) ?[]const dns.ResourceRecord {
        if (self.resolving_ds) return null; // re-entrancy guard

        // Nearest ancestor with a cached NS RRset — the true parent zone can
        // be several labels up when ENTs sit between cuts (ip6.arpa's nibble
        // tree). Cached negatives at ENTs (qmin NS probes) are walked past;
        // ancestors exhausted → root parent, query root hints (RFC 4035
        // §3.1.4.1).
        const cache = self.cache orelse return null;
        var parent_zone = parentZoneOf(zone_name);
        const ns_hit = while (parent_zone.len > 0) : (parent_zone = parentZoneOf(parent_zone)) {
            if (cache.lookup(allocator, parent_zone, .ns, .in)) |result| switch (result) {
                .hit => |h| break h,
                .negative => {},
            };
        } else return self.reproveDelegationSecurity(allocator, zone_name, self.root_hints);
        var ns_names: [max_servers_per_level]dns.Name = undefined;
        var ns_count: usize = 0;
        for (ns_hit.records) |rr| {
            if (rr.rtype == .ns and ns_count < max_servers_per_level) {
                ns_names[ns_count] = rr.rdata.ns;
                ns_count += 1;
            }
        }
        // Try cached addresses first; fall back to network resolution when
        // addresses have expired alongside DS/DNSKEY (common with equal TTLs).
        const addrs = (self.lookupCachedNsAddresses(allocator, ns_names[0..ns_count]) catch null) orelse blk: {
            self.resolving_ds = true;
            defer self.resolving_ds = false;
            break :blk (self.resolveNsAddresses(allocator, ns_names[0..ns_count], 1) catch null) orelse return null;
        };
        return self.reproveDelegationSecurity(allocator, zone_name, addrs.addrs[0..addrs.count]);
    }

    /// Refresh expired DS status by querying parent servers directly. Uses
    /// dedup to coalesce concurrent fetches. Returns the fresh DS records
    /// (slice lives on `allocator`, the per-query arena) when the zone is
    /// signed; null when the delegation is proven insecure (negative DS
    /// cached) or when the fetch failed. The records themselves are not
    /// cached if their TTL is 0 (RFC 1035 §3.2.1) — callers therefore use
    /// the returned slice in-flight rather than relying on a cache lookup.
    fn reproveDelegationSecurity(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_name: []const u8,
        parent_servers: []const na.Address,
    ) ?[]const dns.ResourceRecord {
        // Fast path: DS already in cache (another thread may have fetched it).
        if (self.keyCache()) |c| {
            if (c.lookup(allocator, zone_name, .ds, .in)) |result| return switch (result) {
                .hit => |h| h.records,
                .negative => null,
            };
        }

        const Ctx = struct {
            self: *RecursiveResolver,
            allocator: mem.Allocator,
            zone_name: []const u8,
            parent_servers: []const na.Address,

            fn fetch(c: @This()) ?[]const dns.ResourceRecord {
                return c.self.reproveDelegationSecurityImpl(c.allocator, c.zone_name, c.parent_servers);
            }
        };

        // Note: a TTL=0 DS that the cache silently drops will land the
        // follower in dedupedFetch's cache-miss-after-leader retry path
        // even though the leader succeeded. The retry-as-leader covers
        // it; one extra fetch under that rare combination is acceptable.
        return self.dedupedFetch(allocator, zone_name, .ds, ds_dedup_timeout_ns, Ctx{
            .self = self,
            .allocator = allocator,
            .zone_name = zone_name,
            .parent_servers = parent_servers,
        });
    }

    fn reproveDelegationSecurityImpl(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_name: []const u8,
        parent_servers: []const na.Address,
    ) ?[]const dns.ResourceRecord {
        // Root has no parent to reprove DS against — caller chose root_hints
        // anchor, not this path. parentZoneOf("") returns "" and would loop.
        std.debug.assert(zone_name.len > 0);
        const response = (self.fetchRRset(allocator, zone_name, .ds, parent_servers, 2, self.dnssec_aware, false) catch return null) orelse return null;
        const zone = dns.parseDottedName(allocator, zone_name) catch return null;

        // Locate the section that carries the DS RRset (RFC 4035 §5.2: DS
        // travels in answers when the parent answers a DS query directly).
        const ds_section: []const dns.ResourceRecord = blk: {
            for (response.answers) |rr| {
                if (rr.rtype == .ds) break :blk response.answers;
            }
            for (response.authorities) |rr| {
                if (rr.rtype == .ds) break :blk response.authorities;
            }
            break :blk &.{};
        };

        if (ds_section.len > 0) {
            // RFC 4035 §5.2: the DS RRset MUST be authenticated by an RRSIG
            // signed with the parent zone's DNSKEY before it can anchor child
            // trust. Without this verify step, an on-path attacker who forges
            // both DS and DNSKEY can mint a self-validating chain.
            //
            // The parent-zone name comes from the DS RRSIG's signer, not
            // label arithmetic: with ENTs between cuts the parent sits
            // several labels up (parent of 0.6.2.ip6.arpa is ip6.arpa;
            // parentZoneOf names the ENT 6.2.ip6.arpa, whose DNSKEY is
            // NODATA — the whole reverse tree SERVFAILed). A lying signer
            // can't anchor: its DNSKEY must chain to the root trust anchor.
            // The proper-ancestor guard pins it to the qname chain.
            // Narrow to *this zone's* DS RRset first. One filter closes three
            // compounding holes: the signer below came off the first RRSIG
            // covering any DS, the validator reports `.secure` when
            // *some* owner-group verifies, and the cache loop copied every `.ds`
            // in the section — so an unsigned DS for an unrelated name could ride
            // along and be cached `.secure`. A DS is a digest commitment, so a
            // planted one is what that name's DNSKEY is then checked against:
            // its subtree SERVFAILs for the DS TTL, and planting needs no key at
            // all. Scenario 903. The filter drops nothing legitimate — a DS
            // answer's owner is the qname, a referral's is the child zone.
            var zone_ds_buf: [32]dns.ResourceRecord = undefined;
            var ds_count: usize = 0;
            for (ds_section) |rr| {
                if (rr.rtype != .ds or !rr.name.eql(zone)) continue;
                // Fail closed rather than truncate: verifying a prefix and
                // caching the whole is the A1/C2 laundering shape.
                if (ds_count == zone_ds_buf.len / 2) return null;
                zone_ds_buf[ds_count] = rr;
                ds_count += 1;
            }
            if (ds_count == 0) return null;
            var zone_ds_len = ds_count;
            for (ds_section) |rr| {
                if (rr.rtype != .rrsig or rr.rdata.rrsig.type_covered != .ds) continue;
                if (!rr.name.eql(zone)) continue;
                if (zone_ds_len == zone_ds_buf.len) return null;
                zone_ds_buf[zone_ds_len] = rr;
                zone_ds_len += 1;
            }
            const zone_ds = zone_ds_buf[0..zone_ds_len];

            const signer = for (zone_ds[ds_count..]) |rr| {
                break rr.rdata.rrsig.signer_name;
            } else return null;
            if (!zone.isSubdomainOf(signer) or zone.eql(signer)) return null;
            var signer_buf: [dns.max_name_len + 1]u8 = undefined;
            const parent_dotted = signer.formatInto(&signer_buf);
            const parent_dnskeys = (self.fetchDnskey(allocator, parent_dotted, parent_servers) catch null) orelse return null;
            var ds_ttl_cap: u32 = std.math.maxInt(u32);
            const ds_status = dnssec.validateRrset(
                zone_ds,
                zone,
                .ds,
                parent_dnskeys,
                epochNowU32(),
                self.validationBudget(),
                &ds_ttl_cap,
            );
            if (ds_status != .secure) return null;

            // RFC 4035 §5.2: authenticated DS RRset, but no member hark can
            // use — same as a proven no-DS delegation. Cache the negative so
            // every consumer of the null-plus-negative contract sees insecure.
            if (!dnssec.anySupportedDs(zone_ds_buf[0..ds_count])) {
                if (self.cache) |c| c.storeResponse(response, zone, .unchecked, std.math.maxInt(u32));
                cacheInsecureDelegation(self.keyCache(), .insecure, zone, zone_ds_buf[0..ds_count], ds_ttl_cap);
                return null;
            }

            // Cache only after the parent-signed DS verifies.
            if (self.cache) |c| c.storeResponse(response, zone, .unchecked, std.math.maxInt(u32));
            if (self.key_cache) |kc| {
                // DS records alone: the key cache reads only DS and DNSKEY, so
                // RRSIGs and any NSEC riding along would be unreachable weight.
                // Bounded by the signature that just verified them. fetchRRset
                // only returns .no_error, so the synthesized header is faithful.
                kc.storeResponse(synthesizedMessage(zone_ds_buf[0..ds_count], &.{}, .no_error, false), zone, .secure, ds_ttl_cap);
            }
            return ds_section;
        }

        // No DS section — verify NSEC/NSEC3 proof of insecure delegation. NS
        // and glue are still useful for resolution, so cache them.
        if (self.cache) |c| c.storeResponse(response, zone, .unchecked, std.math.maxInt(u32));
        var proof_ttl_cap: u32 = std.math.maxInt(u32);
        const auth_status = self.verifyAuthoritySigs(allocator, response.authorities, parent_servers, &proof_ttl_cap);
        if (auth_status == .secure) {
            const status = dnssec.classifyDelegation(response.authorities, zone, self.validationBudget());
            if (status == .insecure) {
                cacheInsecureDelegation(self.keyCache(), status, zone, response.authorities, proof_ttl_cap);
            }
        }
        return null;
    }

    /// Validate answer RRsets for a response from a secure zone.
    /// Returns .valid (AD bit set), .bogus (should SERVFAIL), or .skip (insecure zone).
    ///
    /// `zone` is the delegation point the query was routed to. RFC 4035 §5.3.1
    /// requires the signer to be "the name of the zone that contains the RRset"
    /// but never says how to determine that zone, so both Unbound
    /// (`validator.c` sets its key lookup name *to the signer*) and BIND fall
    /// back to the weaker RFC 4034 §3.1.3 ancestor test. That weaker test is
    /// vacuous: the signer is an ancestor of the owner for every non-apex
    /// record in DNS. `zone` is the one piece of cut evidence hark always has.
    fn validateAnswer(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        response: *dns.Message,
        qtype: dns.RType,
        security_state: dnssec.SecurityStatus,
        zone: dns.Name,
        servers: []const na.Address,
    ) !AnswerValidation {
        if (security_state != .secure) return .skip;

        // RFC 8482: ANY responses are server-policy and have no single
        // type_covered RRSIG; treat as unauthenticated rather than bogus.
        if (qtype == .any) return .skip;

        const now_u32 = epochNowU32();

        // Every RRset in the section, under its own signer's keys, weakest
        // verdict wins. Narrower scoping has twice produced AD=1 over records
        // nothing signed; the section ships whole under one AD bit.
        //
        // TODO: DNAME (RFC 6672) needs a carve-out — a server-synthesized CNAME
        // is unsigned, so this rejects it. Not "inherit the DNAME's signer",
        // which would hand an injector the redirect target: re-derive the
        // expected target from the DNAME and accept only an exact match.
        var status: dnssec.SecurityStatus = .secure;
        var keys: SignerKeys = .{};
        var groups: usize = 0;
        var ttl_cap: u32 = std.math.maxInt(u32);
        for (response.answers, 0..) |rr, i| {
            // An RRSIG is the proof, not a thing needing one.
            if (rr.rtype == .rrsig) continue;
            if (!firstOfRrset(response.answers, i)) continue;
            groups += 1;

            const group_keys = (try keys.forRrset(self, allocator, response.answers, rr, zone, servers)) orelse return .bogus;
            var group_cap: u32 = std.math.maxInt(u32);
            const verdict = dnssec.validateRrset(response.answers, rr.name, rr.rtype, group_keys, now_u32, self.validationBudget(), &group_cap);
            if (verdict == .bogus) return .bogus;
            status = dnssec.weakest(status, verdict);
            ttl_cap = @min(ttl_cap, group_cap);
        }
        // Signatures alone: AD would be a claim about an empty set.
        if (groups == 0) return .bogus;

        switch (status) {
            .secure => {
                try trimSectionTtls(allocator, &response.answers, ttl_cap);
                response.header.flags.ad = true;
                return .{ .valid = ttl_cap };
            },
            .bogus => return .bogus,
            .unchecked, .insecure => return .skip,
        }
    }

    /// Keysets resolved so far in one answer, by signer; a chain inside one
    /// zone repeats its signer. Past capacity it stops memoising rather than
    /// failing — fan-out is bounded by the query quota `fetchRRset` charges.
    const SignerKeys = struct {
        const capacity = 4;
        signers: [capacity]dns.Name = undefined,
        sets: [capacity][]const dns.ResourceRecord = undefined,
        len: usize = 0,

        /// Keys that may authenticate `rr`'s RRset; null means bogus.
        fn forRrset(
            self: *SignerKeys,
            resolver: *RecursiveResolver,
            allocator: mem.Allocator,
            answers: []const dns.ResourceRecord,
            rr: dns.ResourceRecord,
            zone: dns.Name,
            servers: []const na.Address,
        ) !?[]const dns.ResourceRecord {
            const rrsig = dnssec.findRrsigAt(answers, rr.name, rr.rtype) orelse return null;

            // RFC 4034 §3.1.3: signer must be at or above the RRset owner name
            if (!rr.name.isSubdomainOf(rrsig.signer_name)) return null;

            // A secure `zone` is validated cut evidence, so a signer strictly
            // above it authenticates nothing here (BIND's
            // `closer_secure_ds_exists`). Bogus, not soft: this runs before any
            // key fetch, so a softer verdict would beat simply stripping the
            // RRSIGs. Cuts *below* `zone` stay undetected by design — scenario
            // 901.
            if (!rrsig.signer_name.isSubdomainOf(zone)) return null;

            for (self.signers[0..self.len], self.sets[0..self.len]) |signer, set| {
                if (signer.eql(rrsig.signer_name)) return set;
            }
            const signer_dotted = try nameToDotted(allocator, rrsig.signer_name);
            const set = (try resolver.fetchDnskey(allocator, signer_dotted, servers)) orelse return null;
            if (self.len < capacity) {
                self.signers[self.len] = rrsig.signer_name;
                self.sets[self.len] = set;
                self.len += 1;
            }
            return set;
        }
    };

    /// Lower a section's TTLs to `cap`, so the *client* on a miss gets the
    /// trimmed value too — a downstream validator caching past the signature
    /// it was shown would reject its own copy. Allocates only when something
    /// exceeds the cap, which for real zones is never.
    fn trimSectionTtls(
        allocator: mem.Allocator,
        section: *[]const dns.ResourceRecord,
        cap: u32,
    ) !void {
        var needs_trim = false;
        for (section.*) |rr| {
            if (rr.ttl > cap) {
                needs_trim = true;
                break;
            }
        }
        if (!needs_trim) return;
        const trimmed = try allocator.alloc(dns.ResourceRecord, section.len);
        for (section.*, trimmed) |src, *dst| {
            dst.* = src;
            dst.ttl = @min(src.ttl, cap);
        }
        section.* = trimmed;
    }

    /// True when `records[i]` opens its (owner, type) RRset, so a loop over
    /// records visits each RRset once.
    fn firstOfRrset(records: []const dns.ResourceRecord, i: usize) bool {
        for (records[0..i]) |prev| {
            if (prev.rtype == records[i].rtype and prev.name.eql(records[i].name)) return false;
        }
        return true;
    }

    /// Verify RRSIG signatures over NSEC/NSEC3 records in authorities.
    /// Fetches DNSKEY from cache or network (per RFC 4035 §5.2: signatures
    /// must be authenticated before accepting NSEC proofs).
    fn verifyAuthoritySigs(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        authorities: []const dns.ResourceRecord,
        parent_servers: []const na.Address,
        ttl_cap: ?*u32,
    ) dnssec.SecurityStatus {
        const signer = dnssec.authoritySigner(authorities) orelse return .unchecked;

        // RFC 4034 §3.1.3: verify authority record owners are under the signer zone
        for (authorities) |rr| if (rr.rtype == .nsec or rr.rtype == .nsec3) {
            if (!rr.name.isSubdomainOf(signer)) return .unchecked;
        };

        const signer_dotted = nameToDotted(allocator, signer) catch return .unchecked;
        const dnskey_records = (self.fetchDnskey(allocator, signer_dotted, parent_servers) catch return .unchecked) orelse return .unchecked;

        const now_u32 = epochNowU32();
        return dnssec.verifyAuthorityProofSigs(authorities, dnskey_records, now_u32, self.validationBudget(), ttl_cap);
    }

    /// Verify authority NSEC/NSEC3 signatures, then validate the negative proof.
    fn verifiedNegativeResponse(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        security_state: dnssec.SecurityStatus,
        authorities: []const dns.ResourceRecord,
        qname: dns.Name,
        qtype: dns.RType,
        is_nxdomain: bool,
        zone: dns.Name,
        zone_servers: []const na.Address,
        ttl_cap: *u32,
    ) NegativeValidation {
        if (security_state != .secure) return .{ .proceed = cacheSecurityStatus(security_state) };

        const auth_status = self.verifyAuthoritySigs(allocator, authorities, zone_servers, ttl_cap);
        if (auth_status == .bogus) return .bogus;
        if (auth_status != .secure) return .skip_cache;

        // `zone` is the deepest *cached* delegation, not the answering
        // server's real apex. A child folded back into its parent while hark
        // still holds the cut leaves a server legitimately signing as the
        // parent — above our tracked zone. That is a lame-cut condition, not
        // a forgery, so it degrades to unauthenticated-and-uncached rather
        // than SERVFAIL. Refusing here would be perverse in the other
        // direction too: an attacker who simply strips the RRSIGs lands on
        // `.unchecked` above and gets the answer *served*, so the verified
        // path must not be harsher than the absent one.
        const signer = dnssec.authoritySigner(authorities) orelse return .skip_cache;
        if (!signer.isSubdomainOf(zone)) return .skip_cache;

        // Past here the signer is authenticated and at-or-below the cut, so it
        // is the authority the proof rests on — the zone geometry is judged
        // against.
        return validateNegativeResponse(security_state, authorities, qname, qtype, is_nxdomain, signer, self.validationBudget());
    }

    fn resolveNsAddresses(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_names: []const dns.Name,
        depth: usize,
    ) !?NsAddrResult {
        if (depth >= max_resolve_depth) return null;

        // Fetch policy (Unbound-style): resolve more NS names at shallow depths
        // to warm cache for sibling queries. At least 1 at all depths.
        const ns_fetch_limit: usize = switch (depth) {
            0 => 3,
            1 => 2,
            else => 1,
        };

        // Per-query Fisher-Yates so distinct queries to the same delegation
        // don't repeatedly attempt the same prefix and strand the same tail.
        // Auth servers often return NS records in a stable order; without
        // randomization the fanout's `[0..ns_fetch_limit]` slice would be
        // deterministic, and a partial outage on those specific names would
        // consistently hit the serial-fallback path (or fail entirely when
        // ns_names.len <= ns_fetch_limit). Matches PowerDNS's std::sample
        // over s_maxnsperresolve and Unbound's RTT-weighted random selection.
        std.debug.assert(ns_names.len <= max_servers_per_level);
        var shuffled: [max_servers_per_level]dns.Name = undefined;
        @memcpy(shuffled[0..ns_names.len], ns_names);
        rand.fastShuffle(dns.Name, self.io, shuffled[0..ns_names.len]);
        const names = shuffled[0..ns_names.len];

        // Parallel path: one helper thread per (ns_name × rtype) task beyond
        // the caller's. Bounded by ns_fetch_limit so the worst-case fanout is
        // `ns_fetch_limit * 2 - 1` helpers (5 at depth 0). Fanout caps attempts
        // (not successes) at ns_fetch_limit, so on null fall back to serial
        // over the remaining NS names — matches serial's recovery behavior
        // for partially-broken delegations.
        if (self.gpa != null) {
            if (try self.resolveNsAddressesFanout(allocator, names, depth, ns_fetch_limit)) |r| return r;
            if (names.len > ns_fetch_limit) {
                return self.resolveNsAddressesSerial(allocator, names[ns_fetch_limit..], depth, ns_fetch_limit);
            }
            return null;
        }

        return self.resolveNsAddressesSerial(allocator, names, depth, ns_fetch_limit);
    }

    const address_rtypes = [_]dns.RType{ .a, .aaaa };
    /// Largest ns_fetch_limit used by resolveNsAddresses (depth 0). Bounds the
    /// stack-allocated task-context array in resolveNsAddressesFanout.
    const max_ns_fetch_limit: usize = 3;
    const max_ns_parallel_tasks: usize = max_ns_fetch_limit * address_rtypes.len;

    /// Append A+AAAA addresses from `records` to `addrs`, skipping non-routable.
    /// Returns true if at least one address was appended.
    fn appendAddressesFromRecords(
        self: *RecursiveResolver,
        records: []const dns.ResourceRecord,
        addrs: *[max_servers_per_level]na.Address,
        count: *usize,
    ) bool {
        var added = false;
        for (records) |rr| {
            if (count.* >= max_servers_per_level) break;
            const addr: na.Address = switch (rr.rtype) {
                .a => na.initIp4(rr.rdata.a, self.upstream_port),
                .aaaa => na.initIp6(rr.rdata.aaaa, self.upstream_port, 0, 0),
                else => continue,
            };
            if (!self.allow_loopback_upstreams and na.isNonRoutableNs(addr)) continue;
            addrs[count.*] = addr;
            count.* += 1;
            added = true;
        }
        return added;
    }

    const ns_addr_dedup_timeout_ns: u64 = 2 * std.time.ns_per_s;

    /// Resolve one (ns_name, rtype) pair and append any resulting addresses
    /// to `addrs[count..]`. Non-OOM resolution failures are swallowed.
    /// Wrapped in dedup so concurrent recursions hitting the same NS collapse;
    /// bounded timeout prevents follower-deadlock under cross-NS dependencies.
    fn resolveNsNameOne(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_dotted: []const u8,
        rtype: dns.RType,
        depth: usize,
        addrs: *[max_servers_per_level]na.Address,
        count: *usize,
    ) error{OutOfMemory}!void {
        const leader = if (self.dedup) |dedup|
            dedup.acquireOrWaitWithTimeout(ns_dotted, rtype, 0, monotonic.nowNs() + ns_addr_dedup_timeout_ns) == .leader
        else
            false;
        defer if (leader) self.dedup.?.releaseLeader(ns_dotted, rtype, 0);

        if (self.resolveImpl(allocator, ns_dotted, rtype, depth + 1)) |r| {
            _ = self.appendAddressesFromRecords(r.message.answers, addrs, count);
        } else |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
        }
    }

    /// Resolve A + AAAA for a single NS name serially.
    fn resolveNsName(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_name: dns.Name,
        depth: usize,
        addrs: *[max_servers_per_level]na.Address,
        count: *usize,
    ) error{OutOfMemory}!bool {
        const ns_dotted = try nameToDotted(allocator, ns_name);
        const before = count.*;
        for (address_rtypes) |qtype| {
            try self.resolveNsNameOne(allocator, ns_dotted, qtype, depth, addrs, count);
        }
        return count.* > before;
    }

    fn resolveNsAddressesSerial(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_names: []const dns.Name,
        depth: usize,
        ns_fetch_limit: usize,
    ) !?NsAddrResult {
        var addrs: [max_servers_per_level]na.Address = undefined;
        var count: usize = 0;
        var resolved_ns_count: usize = 0;

        for (ns_names) |ns_name| {
            if (try self.resolveNsName(allocator, ns_name, depth, &addrs, &count)) {
                resolved_ns_count += 1;
                if (resolved_ns_count >= ns_fetch_limit) break;
            }
        }

        if (count == 0) return null;
        return .{ .addrs = addrs, .count = count };
    }

    /// Fan out NS-address resolution across one thread per (ns_name × rtype)
    /// task. Task 0 runs on the caller thread; spawn failures fall back to it
    /// after helpers join. Caps ATTEMPTS (not successes) at ns_fetch_limit;
    /// callers must serial-resolve the tail when this returns null.
    fn resolveNsAddressesFanout(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_names: []const dns.Name,
        depth: usize,
        ns_fetch_limit: usize,
    ) !?NsAddrResult {
        const rtypes_n = address_rtypes.len;
        const names_n = @min(ns_names.len, ns_fetch_limit);
        if (names_n == 0) return null;
        const task_n = names_n * rtypes_n;
        std.debug.assert(task_n <= max_ns_parallel_tasks);

        // Precompute dotted names once per NS name; the two rtype tasks for
        // each name share the string. Safe to share across helpers because
        // the caller-arena outlives the join.
        var dotted_names: [max_ns_fetch_limit][]const u8 = undefined;
        for (0..names_n) |ni| {
            dotted_names[ni] = try nameToDotted(allocator, ns_names[ni]);
        }

        // Each helper builds its OWN per-resolution cap in run() (gpa+mem_limit).
        // A shared cap split query_memory_limit across the concurrent helpers,
        // starving each to limit/task_n and SERVFAIL'ing ordinary signed domains.
        // Caps are transient — each freed at its thread's join.
        var task_ctxs: [max_ns_parallel_tasks]NsTaskCtx = undefined;
        var threads: [max_ns_parallel_tasks]?std.Thread = @splat(null);

        // Spawn helpers for tasks [1..task_n]. Task 0 runs on the caller.
        // `threads[i] == null` after this loop means spawn failed — the task
        // is handled synchronously in the fallback loop below.
        //
        // Raw `Thread.spawn` rather than `Io.Group.concurrent`: with miss-path
        // throughput in the 200k QPS range and up to 6 helpers per query, the
        // pool's default `async_limit = cpu_count − 1` saturates and forces
        // tasks inline, dropping miss/128 throughput by ~15%. The lifecycle
        // pattern here (spawn-then-join in the same function) doesn't need
        // structured shutdown — Group is the wrong primitive for this rate.
        for (1..task_n) |i| {
            const ni = i / rtypes_n;
            const ri = i % rtypes_n;
            task_ctxs[i] = .{
                .parent = self,
                .ns_dotted = dotted_names[ni],
                .rtype = address_rtypes[ri],
                .depth = depth,
                .gpa = self.gpa.?,
                .mem_limit = self.query_memory_limit,
            };
            threads[i] = std.Thread.spawn(.{ .stack_size = 1 << 20 }, NsTaskCtx.run, .{&task_ctxs[i]}) catch null;
        }
        // Guarantee helper join before task_ctxs go out of scope, including
        // error-return paths below.
        defer for (&threads) |*slot| {
            if (slot.*) |t| {
                t.join();
                slot.* = null;
            }
        };

        var addrs: [max_servers_per_level]na.Address = undefined;
        var count: usize = 0;

        // Task 0 = (NS[0], A) on caller thread.
        try self.resolveNsNameOne(allocator, dotted_names[0], address_rtypes[0], depth, &addrs, &count);

        // Thread-spawn fallbacks: run the task on the caller so we don't drop
        // it. Reserved for fork/resource-limit conditions.
        for (1..task_n) |i| {
            if (threads[i] != null) continue;
            const ni = i / rtypes_n;
            const ri = i % rtypes_n;
            try self.resolveNsNameOne(allocator, dotted_names[ni], address_rtypes[ri], depth, &addrs, &count);
        }

        // Join helpers and merge their addresses. Null each slot after the
        // join so the deferred cleanup loop at the top doesn't double-join.
        for (1..task_n) |i| {
            const t = threads[i] orelse continue;
            t.join();
            threads[i] = null;
            if (task_ctxs[i].oom) return error.OutOfMemory;
            const hc = task_ctxs[i].count;
            if (hc == 0) continue;
            const space = max_servers_per_level - count;
            const to_copy = @min(hc, space);
            @memcpy(addrs[count..][0..to_copy], task_ctxs[i].addrs[0..to_copy]);
            count += to_copy;
        }

        if (count == 0) return null;
        return .{ .addrs = addrs, .count = count };
    }

    /// Context for a helper thread resolving one (ns_dotted, rtype) pair.
    /// `ns_dotted` references the caller arena; safe because
    /// `resolveNsAddressesFanout` joins all helpers before returning. The
    /// parent pointer is read once at start to clone shared state (caches,
    /// selectors) into a thread-local resolver; config is stable after init.
    const NsTaskCtx = struct {
        parent: *RecursiveResolver,
        ns_dotted: []const u8,
        rtype: dns.RType,
        depth: usize,
        gpa: mem.Allocator,
        mem_limit: usize,
        addrs: [max_servers_per_level]na.Address = undefined,
        count: usize = 0,
        oom: bool = false,

        fn run(ctx: *NsTaskCtx) void {
            var udp_t = BlockingUdpTransport.init(.{}, ctx.parent.io);
            defer udp_t.deinit();
            var resolver = ctx.parent.cloneForThread(.{
                .udp = &udp_t,
                .tcp_enabled = ctx.parent.transports.?.tcp_enabled,
                .tls = ctx.parent.transports.?.tls,
            });

            var cap = CountingAllocator.init(ctx.gpa, ctx.mem_limit);
            var arena = std.heap.ArenaAllocator.init(cap.allocator());
            defer arena.deinit();

            resolver.resolveNsNameOne(
                arena.allocator(),
                ctx.ns_dotted,
                ctx.rtype,
                ctx.depth,
                &ctx.addrs,
                &ctx.count,
            ) catch {
                ctx.oom = true;
            };
        }
    };

    const NsAddrResult = struct { addrs: [max_servers_per_level]na.Address, count: usize };
    const DelegationResult = struct { addrs: [max_servers_per_level]na.Address, count: usize, zone: dns.Name };

    /// Check cache for A/AAAA records of NS names, avoiding network queries.
    /// Collects addresses from all cached NS names (cache lookups are free)
    /// for better server diversity.
    fn lookupCachedNsAddresses(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_names: []const dns.Name,
    ) !?NsAddrResult {
        const cache = self.cache orelse return null;

        var addrs: [max_servers_per_level]na.Address = undefined;
        var count: usize = 0;

        for (ns_names) |ns_name| {
            try self.collectCachedNsAddresses(allocator, cache, ns_name, &addrs, &count, 0);
        }

        if (count == 0) return null;
        return .{ .addrs = addrs, .count = count };
    }

    // Max alias hops we'll follow when collecting NS addresses from cache.
    // 1 covers the legitimate case (single CNAME); deeper chains are vanishingly
    // rare and would cost extra arena allocs inside cache.lookup per hop.
    const max_ns_cname_chain: u8 = 1;

    /// Follow one cached CNAME if no A/AAAA — repairs stale-glue when the
    /// alias chain is fresh (cf. `iter_cname_cache.rpl`). RFC 2181 §10.3
    /// forbids NS pointing to an alias, but tolerating on read costs nothing.
    fn collectCachedNsAddresses(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        cache: *RRsetCache,
        ns_name: dns.Name,
        addrs: *[max_servers_per_level]na.Address,
        count: *usize,
        depth: u8,
    ) error{OutOfMemory}!void {
        if (depth > max_ns_cname_chain) return;

        // cache.lookup re-copies the name into its own buffer; pass the
        // stack-formatted slice directly instead of duping into the arena.
        var name_buf: [dns.max_name_len + 1]u8 = undefined;
        const ns_dotted = ns_name.formatInto(&name_buf);

        const before = count.*;
        for (address_rtypes) |qtype| {
            if (cache.lookup(allocator, ns_dotted, qtype, .in)) |result| {
                switch (result) {
                    .hit => |h| _ = self.appendAddressesFromRecords(h.records, addrs, count),
                    .negative => {},
                }
            }
        }
        if (count.* > before) return;

        const cname_lookup = cache.lookup(allocator, ns_dotted, .cname, .in) orelse return;
        switch (cname_lookup) {
            .hit => |h| {
                for (h.records) |rr| {
                    if (rr.rtype == .cname) {
                        try self.collectCachedNsAddresses(allocator, cache, rr.rdata.cname, addrs, count, depth + 1);
                        return; // RFC 2181 §10.1: at most one CNAME per name
                    }
                }
            },
            .negative => {},
        }
    }

    /// Walk the domain name from TLD to find the closest cached delegation.
    /// E.g., for "www.example.com", check NS records for "com" then "example.com".
    pub fn findClosestCachedDelegation(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        target_name: []const u8,
    ) !?DelegationResult {
        const cache = self.cache orelse return null;

        // Split into labels
        var parts: [dns.max_label_count + 1][]const u8 = undefined;
        var part_count: usize = 0;
        var iter = mem.splitScalar(u8, target_name, '.');
        while (iter.next()) |part| {
            if (part.len == 0) continue;
            if (part_count >= dns.max_label_count + 1) break;
            parts[part_count] = part;
            part_count += 1;
        }
        if (part_count == 0) return null;

        // Walk from TLD toward full name, looking for cached NS + addresses.
        // Intermediate NS/glue clones live in a scratch arena that is reset
        // each iteration, so losing levels do not accumulate in the caller's
        // arena. A miss after a prior hit terminates the walk: referral
        // caching is populated top-down, so no deeper level can exist.
        var scratch_arena = std.heap.ArenaAllocator.init(allocator);
        defer scratch_arena.deinit();

        var best: ?DelegationResult = null;
        var had_ns_hit = false;

        var i: usize = part_count;
        while (i > 0) {
            i -= 1;
            // Build zone name string from parts[i..part_count]
            var zone_buf: [dns.max_name_len + 1]u8 = undefined;
            var pos: usize = 0;
            for (parts[i..part_count]) |p| {
                if (pos > 0) {
                    zone_buf[pos] = '.';
                    pos += 1;
                }
                if (pos + p.len > dns.max_name_len) break;
                @memcpy(zone_buf[pos..][0..p.len], p);
                pos += p.len;
            }
            const zone_str = zone_buf[0..pos];

            _ = scratch_arena.reset(.retain_capacity);
            const scratch = scratch_arena.allocator();

            const ns_lookup = cache.lookup(scratch, zone_str, .ns, .in) orelse {
                if (had_ns_hit) break;
                continue;
            };
            const hit = switch (ns_lookup) {
                .hit => |h| h,
                .negative => continue,
            };
            had_ns_hit = true;

            var ns_names: [max_servers_per_level]dns.Name = undefined;
            var ns_count: usize = 0;
            for (hit.records) |ns_rr| {
                if (ns_rr.rtype == .ns and ns_count < max_servers_per_level) {
                    ns_names[ns_count] = ns_rr.rdata.ns;
                    ns_count += 1;
                }
            }

            const res = (try self.lookupCachedNsAddresses(scratch, ns_names[0..ns_count])) orelse continue;

            // DNSSEC: only use this delegation if DS status is known.
            // If DS is a cache miss, another thread may not have cached
            // the insecure delegation yet. Try a targeted DS re-probe
            // using the parent delegation's servers (like Unbound's key
            // cache refresh) before falling back to referral re-walk.
            if (self.dnssec_enabled) {
                const ds_cache = self.keyCache() orelse break;
                if (!ds_cache.containsFresh(zone_str, .ds, .in)) {
                    const records = if (best) |parent_deleg|
                        self.reproveDelegationSecurity(
                            allocator,
                            zone_str,
                            parent_deleg.addrs[0..parent_deleg.count],
                        )
                    else
                        null;
                    // Records non-null = signed (may not be cached if TTL=0,
                    // but DS status is known). Null + cache hit (negative)
                    // = insecure. Null + cache miss = unknown, give up.
                    if (records == null and !ds_cache.containsFresh(zone_str, .ds, .in)) break;
                }
            }

            // Zone name must live on the caller's arena: `best` outlives
            // the scratch reset. Addresses are plain `na.Address` values.
            const zone_name = try dns.parseDottedName(allocator, zone_str);
            best = .{
                .addrs = res.addrs,
                .count = res.count,
                .zone = zone_name,
            };
        }

        return best;
    }
};

// ── Insecure delegation caching ───────────────────────────────────────

fn hasCachedInsecureDelegation(cache: ?*RRsetCache, allocator: mem.Allocator, zone: dns.Name) bool {
    const c = cache orelse return false;
    var zone_buf: [dns.max_name_len + 1]u8 = undefined;
    const ds_result = c.lookup(allocator, zone.formatInto(&zone_buf), .ds, .in) orelse return false;
    return switch (ds_result) {
        .negative => true,
        .hit => false,
    };
}

/// When classifyDelegation returns .insecure, cache a negative DS entry
/// so that findClosestCachedDelegation can determine DNSSEC security state
/// without re-walking the referral chain.
fn cacheInsecureDelegation(
    cache: ?*@import("cache.zig").RRsetCache,
    security_state: dnssec.SecurityStatus,
    zone_cut: dns.Name,
    authorities: []const dns.ResourceRecord,
    ttl_cap: u32,
) void {
    if (security_state != .insecure) return;
    const c = cache orelse return;

    // Use minimum authority section TTL (from NSEC/NSEC3 proving no DS),
    // bounded by the proof's signature validity.
    var neg_ttl: u32 = @min(3600, ttl_cap);
    for (authorities) |rr| {
        if (rr.ttl > 0 and rr.ttl < neg_ttl) neg_ttl = rr.ttl;
    }

    var zone_buf: [dns.max_name_len + 1]u8 = undefined;
    c.storeNegativeBare(zone_cut.formatInto(&zone_buf), .ds, .in, .no_error, neg_ttl, .insecure, .always);
}

/// Validate DNSKEY answers against cached DS records (RFC 4035 §5.2).
/// Extracts DS data from cache hit records and calls dnssec.validateDnskeyRrset.
fn validateDnskeyAgainstDs(
    dnskey_answers: []const dns.ResourceRecord,
    ds_records_rr: []const dns.ResourceRecord,
    zone_parsed: dns.Name,
    budget: *dnssec.ValidationBudget,
) !void {
    var ds_records: [16]dns.DsData = undefined;
    var ds_count: usize = 0;
    for (ds_records_rr) |rr| {
        if (rr.rtype == .ds and ds_count < ds_records.len) {
            ds_records[ds_count] = rr.rdata.ds;
            ds_count += 1;
        }
    }
    if (ds_count > 0) {
        // RFC 4035 §5.2: DNSKEY RRset MUST be self-signed.
        const now_u32 = epochNowU32();
        try dnssec.validateDnskeyRrset(
            dnskey_answers,
            ds_records[0..ds_count],
            zone_parsed,
            now_u32,
            budget,
        );
    }
}

/// Map dnssec validation status to the cache-tier subset (no .bogus).
fn cacheSecurityStatus(state: dnssec.SecurityStatus) cache_mod.SecurityStatus {
    return switch (state) {
        .secure => .secure,
        .insecure => .insecure,
        .unchecked, .bogus => .unchecked,
    };
}

// ── Helpers ────────────────────────────────────────────────────────────

/// RFC 8482 §6 example uses 3789s; matches BIND's default and signals to
/// debuggers that the answer is a synthetic HINFO and not a real RRset.
const ttl_any_hinfo: u32 = 3789;

/// RFC 8482: synthesize a minimal HINFO answer for a qtype=ANY query.
/// Wire-encodes RDATA as two character-strings: cpu="RFC8482", os="".
/// Uses the RType=13 / RData.unknown path so we don't have to teach the
/// rest of the parser/cache/printer about HINFO.
fn synthesizeAnyHinfo(allocator: mem.Allocator, name: []const u8) !dns.Message {
    // Lowercase the client-typed name before parsing so the synthetic
    // HINFO owner doesn't echo back mixed case (same scrub policy as the
    // upstream-reply path in `tryParseMessage`).
    var lower_buf: [dns.max_name_len + 1]u8 = undefined;
    if (name.len > lower_buf.len) return error.NameTooLong;
    const lower = dns.lowerNameIntoBuf(&lower_buf, name);
    const qname = try dns.parseDottedName(allocator, lower);
    // <len=7> R F C 8 4 8 2  <len=0>
    const rdata_bytes = try allocator.dupe(u8, &[_]u8{ 0x07, 'R', 'F', 'C', '8', '4', '8', '2', 0x00 });
    const arr = try allocator.alloc(dns.ResourceRecord, 1);
    arr[0] = .{
        .name = qname,
        .rtype = @fromBackingInt(@intCast(13)), // HINFO
        .rclass = .in,
        .ttl = ttl_any_hinfo,
        .rdata = .{ .unknown = rdata_bytes },
    };
    return synthesizedMessage(arr, &.{}, .no_error, false);
}

/// Parent zone name of `zone_name`. Returns "" (root) for TLDs and root.
fn parentZoneOf(zone_name: []const u8) []const u8 {
    const pos = mem.indexOfScalar(u8, zone_name, '.') orelse return "";
    if (pos + 1 >= zone_name.len) return "";
    return zone_name[pos + 1 ..];
}

/// Strip authority/additional sections from a message for targeted cache stores.
fn answersOnly(msg: dns.Message) dns.Message {
    var m = msg;
    m.authorities = &.{};
    m.additionals = &.{};
    m.header.ns_count = 0;
    m.header.ar_count = 0;
    return m;
}

/// Returns current epoch time as u32 for DNSSEC signature validation.
/// Uses wall clock (not monotonic) because RRSIG inception/expiration
/// are defined as epoch seconds (RFC 4034 §3.1.5). Truncation gives
/// correct serial number arithmetic wrapping behavior.
fn epochNowU32() u32 {
    return @truncate(@as(u64, @intCast(monotonic.wallclockSec())));
}

fn nameToDotted(allocator: mem.Allocator, name: dns.Name) ![]const u8 {
    var buf: [dns.max_name_len + 1]u8 = undefined;
    return allocator.dupe(u8, name.formatInto(&buf));
}

fn findCnameRecord(response: dns.Message, target: dns.Name) ?dns.ResourceRecord {
    for (response.answers) |rr| {
        if (rr.rtype == .cname and target.eql(rr.name)) {
            return rr;
        }
    }
    return null;
}

/// True when `next_target` matches the owner of any CNAME already in the
/// chain — a 2-name A→B→A cycle, or any longer revisit. Catches loops
/// before they burn through `max_cname_chain`. Chain owners are
/// lowercased at parse, so `Name.eql`'s case-insensitive compare is the
/// right granularity here.
fn cnameTargetRevisitsChain(chain: []const dns.ResourceRecord, next_target: dns.Name) bool {
    for (chain) |rr| {
        if (rr.name.eql(next_target)) return true;
    }
    return false;
}

/// Shared debug-log shape for the upstream-served and cache-served
/// CNAME loop-detection branches. Single format string keeps both
/// branches reading the same telemetry.
fn logCnameLoop(target: dns.Name, where: []const u8) void {
    var buf: [dns.max_name_len + 1]u8 = undefined;
    log.debug("cname loop detected ({s}): target {s} already in chain", .{ where, target.formatInto(&buf) });
}

/// Concatenate two RR slices. Returns the input slice unchanged when one
/// side is empty (zero-alloc fast path for the dominant non-DNSSEC case).
fn concatRRs(allocator: mem.Allocator, a: []const dns.ResourceRecord, b: []const dns.ResourceRecord) ![]const dns.ResourceRecord {
    if (b.len == 0) return a;
    if (a.len == 0) return b;
    const out = try allocator.alloc(dns.ResourceRecord, a.len + b.len);
    @memcpy(out[0..a.len], a);
    @memcpy(out[a.len..], b);
    return out;
}

/// Build the authority section for a cached negative response: SOA followed
/// by the cached NSEC/NSEC3 proofs (RFC 4035 §3.1.3.2 / §3.1.3.3). Returns
/// an empty slice when both inputs are empty so the wire shaper sees the
/// same `&.{}` it would receive from a sigless unsigned-zone negative.
fn buildNegativeAuthority(
    allocator: mem.Allocator,
    soa: ?dns.ResourceRecord,
    proofs: []const dns.ResourceRecord,
) ![]const dns.ResourceRecord {
    const have_soa: usize = if (soa != null) 1 else 0;
    const total = have_soa + proofs.len;
    if (total == 0) return &.{};
    const out = try allocator.alloc(dns.ResourceRecord, total);
    var i: usize = 0;
    if (soa) |s| {
        out[i] = s;
        i += 1;
    }
    @memcpy(out[i..], proofs);
    return out;
}

/// Stitch CNAME chain (prepends answers) and aggregated wildcard proofs
/// (prepends authority) into `response`. Mirrors Unbound's
/// `iter_add_prepend_auth`. Section trimming is the shaper's job.
fn withCnameChain(
    allocator: mem.Allocator,
    cc: *const CnameChain,
    response: dns.Message,
) !dns.Message {
    const chain = cc.records.items;
    const auth_aggregate = cc.wildcard_proofs.items;
    if (chain.len == 0 and auth_aggregate.len == 0) return response;
    var msg = response;
    // The tail's own verdict says nothing about the hops that led here.
    if (!cc.all_secure) msg.header.flags.ad = false;
    if (chain.len > 0) {
        const new_answers = try allocator.alloc(dns.ResourceRecord, chain.len + response.answers.len);
        @memcpy(new_answers[0..chain.len], chain);
        @memcpy(new_answers[chain.len..], response.answers);
        msg.answers = new_answers;
        msg.header.an_count = @intCast(new_answers.len);
    }
    if (auth_aggregate.len > 0) {
        const new_auths = try allocator.alloc(dns.ResourceRecord, auth_aggregate.len + response.authorities.len);
        @memcpy(new_auths[0..auth_aggregate.len], auth_aggregate);
        @memcpy(new_auths[auth_aggregate.len..], response.authorities);
        msg.authorities = new_auths;
        msg.header.ns_count = @intCast(new_auths.len);
    }
    return msg;
}

/// Cache-served sibling of `aggregateCnameWildcardProofs`: append the
/// pre-validated `nsec_proofs` from a CNAME cache entry to the running
/// chain aggregate. Trust-at-store applies — the cache only retains
/// `.secure` proofs for `.secure` entries, and `collectNsecProofs`
/// already filtered to `isNsecProofMaterial`, so no signature re-verify
/// is needed. Re-filtering on the way out is belt-and-suspenders against
/// a future store-path that loosens its filter; cheap on the empty-proof
/// common case.
fn aggregateCachedCnameWildcardProofs(
    allocator: mem.Allocator,
    cname_status: cache_mod.SecurityStatus,
    nsec_proofs: []const dns.ResourceRecord,
    cname_auth_aggregate: *std.ArrayListUnmanaged(dns.ResourceRecord),
) !void {
    if (cname_status != .secure or nsec_proofs.len == 0) return;
    for (nsec_proofs) |rr| {
        if (dns.isNsecProofMaterial(rr))
            try cname_auth_aggregate.append(allocator, rr);
    }
}

/// Assemble a `ResolveResult` for a negative response: SOA + NSEC
/// proofs in the authority section, empty answer section, threaded
/// through any active CNAME chain. Used by all cache-served negative
/// paths.
fn negativeResolveResult(
    allocator: mem.Allocator,
    soa: ?dns.ResourceRecord,
    proofs: []const dns.ResourceRecord,
    rcode: dns.RCode,
    ad: bool,
    prefetch_name: ?[]const u8,
    qtype: dns.RType,
    chain: *const CnameChain,
) !RecursiveResolver.ResolveResult {
    const authority = try buildNegativeAuthority(allocator, soa, proofs);
    return .{
        .message = try withCnameChain(allocator, chain, synthesizedMessage(&.{}, authority, rcode, ad)),
        .prefetch_name = prefetch_name,
        .prefetch_qtype = qtype,
    };
}

// ── Referral extraction ────────────────────────────────────────────────

const ReferralResult = union(enum) {
    referral: struct {
        addrs: [max_servers_per_level]na.Address,
        count: usize,
        zone_cut: dns.Name, // borrows from response (valid for caller's scope)
    },
    no_glue: struct {
        ns_names: [max_servers_per_level]dns.Name,
        ns_count: usize,
        zone_cut: dns.Name,
    },
};

/// Returns true if the response contains any RRSIG records (signed zone).
fn hasSignedRecords(response: dns.Message) bool {
    for (response.answers) |rr| if (rr.rtype == .rrsig) return true;
    for (response.authorities) |rr| if (rr.rtype == .rrsig) return true;
    return false;
}

/// Address-construction policy applied when materializing referral glue.
/// Defaults are production-safe; tests override to redirect at scripted
/// authorities on non-privileged ports in 127/8.
const ReferralAddrPolicy = struct {
    upstream_port: u16 = 53,
    allow_loopback: bool = false,
};

fn extractReferral(
    response: dns.Message,
    target: dns.Name,
    parent_zone: dns.Name,
    policy: ReferralAddrPolicy,
) ?ReferralResult {
    // Find the most specific zone cut: NS owner where target is a subdomain
    var zone_cut: ?dns.Name = null;
    var zone_cut_depth: usize = 0;
    for (response.authorities) |rr| {
        if (rr.rtype == .ns and target.isSubdomainOf(rr.name)) {
            if (zone_cut == null or rr.name.labels.len > zone_cut_depth) {
                zone_cut = rr.name;
                zone_cut_depth = rr.name.labels.len;
            }
        }
    }
    const zc = zone_cut orelse return null;

    // A valid referral always delegates to a child zone — the zone cut must
    // be strictly deeper than the current parent zone.  If the authority
    // section contains NS records for the same zone (or a parent), it is
    // not a referral (e.g. a server returning its own NS records alongside
    // a CNAME answer).  RFC 1034 §4.2.1, RFC 8499 §7.
    if (zc.labels.len <= parent_zone.labels.len) return null;

    // Collect NS names at the zone cut
    var ns_count: usize = 0;
    var ns_names: [max_servers_per_level]dns.Name = undefined;
    for (response.authorities) |rr| {
        if (rr.rtype == .ns and rr.name.eql(zc)) {
            if (ns_count < max_servers_per_level) {
                ns_names[ns_count] = rr.rdata.ns;
                ns_count += 1;
            }
        }
    }

    // Match glue A/AAAA records with bailiwick check
    var glue_addrs: [max_servers_per_level]na.Address = undefined;
    var glue_count: usize = 0;
    for (response.additionals) |rr| {
        const is_a = rr.rtype == .a;
        const is_aaaa = rr.rtype == .aaaa;
        if (!is_a and !is_aaaa) continue;
        // Bailiwick: glue name must be within the parent zone (the zone
        // the referring server is authoritative for). `isSubdomainOf`
        // already returns true when parent is root, so all glue is
        // accepted under root referrals.
        if (!rr.name.isSubdomainOf(parent_zone)) continue;

        for (ns_names[0..ns_count]) |ns_name| {
            if (ns_name.eql(rr.name)) {
                if (glue_count < max_servers_per_level) {
                    const addr = if (is_a)
                        na.initIp4(rr.rdata.a, policy.upstream_port)
                    else
                        na.initIp6(rr.rdata.aaaa, policy.upstream_port, 0, 0);
                    if (!policy.allow_loopback and na.isNonRoutableNs(addr)) break;
                    glue_addrs[glue_count] = addr;
                    glue_count += 1;
                }
                break;
            }
        }
    }
    if (glue_count == 0) return .{ .no_glue = .{
        .ns_names = ns_names,
        .ns_count = ns_count,
        .zone_cut = zc,
    } };

    return .{ .referral = .{
        .addrs = glue_addrs,
        .count = glue_count,
        .zone_cut = zc,
    } };
}

// ── Negative proof validation ──────────────────────────────────────────

/// `proceed` carries the *proof's* verdict, not the zone's, so AD and the cached
/// rank come from one source. Deriving both from `security_state` left an
/// Opt-Out proof — valid, but §9.2 forbids AD — with nowhere to land but
/// `skip_cache`, and a correct denial went uncached at 100 ms per repeat.
/// Unbound, BIND and Knot all cache these under an explicit insecure rank.
const NegativeValidation = union(enum) {
    /// Serve, and cache under this status. AD only when `.secure`.
    proceed: cache_mod.SecurityStatus,
    /// Serve, cache nothing: authority signatures did not verify at all, so
    /// there is no verdict worth persisting.
    skip_cache,
    bogus,
};

fn validateNegativeResponse(
    security_state: dnssec.SecurityStatus,
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    qtype: dns.RType,
    is_nxdomain: bool,
    zone: dns.Name,
    budget: *dnssec.ValidationBudget,
) NegativeValidation {
    if (security_state != .secure) return .{ .proceed = cacheSecurityStatus(security_state) };
    // RFC 4035 §5.4 + §5.5: inside a known-secure zone every negative response
    // must carry a complete proof; an incomplete one (.unchecked) fails closed.
    // `.insecure` — Opt-Out (§9.2) or unevaluable (RFC 6840 §5.11) — is served
    // and cached without AD.
    return switch (dnssec.validateNegativeProof(authorities, qname, qtype, is_nxdomain, zone, budget)) {
        .secure => .{ .proceed = .secure },
        .insecure => .{ .proceed = .insecure },
        .bogus => .bogus,
        .unchecked => {
            @branchHint(.cold);
            // Diagnostic for the fail-closed path: a real-world broken auth
            // (or a middlebox stripping NSEC) shows up here as SERVFAIL
            // where other resolvers may serve unauthenticated.
            var name_buf: [dns.max_name_len + 1]u8 = undefined;
            var qtype_buf: [24]u8 = undefined;
            log.warn(
                "incomplete NSEC/NSEC3 proof for {s} {s} (nx={}); SERVFAIL per RFC 4035 §5.4",
                .{ qname.formatInto(&name_buf), dns.safeTagName(dns.RType, qtype, &qtype_buf), is_nxdomain },
            );
            return .bogus;
        },
    };
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

// ── Test helpers ──────────────────────────────────────────────────────

fn makeHeader(ns_count: u16, ar_count: u16, an_count: u16) dns.Header {
    return .{
        .id = 0x1234,
        .flags = .{
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = false,
            .ra = false,
            .z = 0,
            .ad = false,
            .cd = false,
            .rcode = .no_error,
        },
        .qd_count = 0,
        .an_count = an_count,
        .ns_count = ns_count,
        .ar_count = ar_count,
    };
}

fn makeName(alloc: mem.Allocator, comptime labels: []const []const u8) !dns.Name {
    const l = try alloc.alloc([]const u8, labels.len);
    for (labels, 0..) |label, i| l[i] = try alloc.dupe(u8, label);
    return dns.Name{ .labels = l };
}

fn makeNsRr(zone: dns.Name, ns_name: dns.Name) dns.ResourceRecord {
    return .{ .name = zone, .rtype = .ns, .rclass = .in, .ttl = 172800, .rdata = .{ .ns = ns_name } };
}

fn makeGlueA(name: dns.Name, addr: [4]u8) dns.ResourceRecord {
    return .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 172800, .rdata = .{ .a = addr } };
}

fn makeGlueAaaa(name: dns.Name, addr: [16]u8) dns.ResourceRecord {
    return .{ .name = name, .rtype = .aaaa, .rclass = .in, .ttl = 172800, .rdata = .{ .aaaa = addr } };
}

fn makeResponse(alloc: mem.Allocator, authorities: []const dns.ResourceRecord, additionals: []const dns.ResourceRecord) !dns.Message {
    const auths = try alloc.alloc(dns.ResourceRecord, authorities.len);
    @memcpy(auths, authorities);
    const adds = try alloc.alloc(dns.ResourceRecord, additionals.len);
    @memcpy(adds, additionals);
    return .{
        .header = makeHeader(@intCast(authorities.len), @intCast(additionals.len), 0),
        .questions = &.{},
        .authorities = auths,
        .additionals = adds,
    };
}

// ── 0x20 echo tests ───────────────────────────────────────────────────

test "caseMangledEcho: only a same-name case mismatch marks mangling" {
    const query_name = dns.Name{ .labels = &.{ "eXaMpLe", "cOm" } };
    const question = struct {
        // comptime name so the questions array lands in static memory —
        // a runtime param would leave it dangling on this frame's stack.
        fn make(comptime name: dns.Name) dns.Message {
            return .{
                .header = makeHeader(0, 0, 0),
                .questions = &.{.{ .name = name, .qtype = .a, .qclass = .in }},
            };
        }
    }.make;

    // Same name, different byte case: genuine mangle.
    try std.testing.expect(RecursiveResolver.caseMangledEcho(
        query_name,
        question(.{ .labels = &.{ "example", "com" } }),
    ));
    // Exact echo: clean.
    try std.testing.expect(!RecursiveResolver.caseMangledEcho(query_name, question(query_name)));
    // Unrelated question (error rcodes are exempt from question-match,
    // RFC 9619): must NOT mark the server case-broken.
    try std.testing.expect(!RecursiveResolver.caseMangledEcho(
        query_name,
        question(.{ .labels = &.{ "other", "net" } }),
    ));
    // Question-less error reply: must not index questions[0].
    try std.testing.expect(!RecursiveResolver.caseMangledEcho(query_name, .{
        .header = makeHeader(0, 0, 0),
        .questions = &.{},
    }));
}

// ── extractReferral tests ─────────────────────────────────────────────

test "extractReferral with NS and glue A records" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 1, 2, 3, 4 })});
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const result = extractReferral(response, target, dns.Name{ .labels = &.{} }, .{}) orelse return error.TestUnexpectedResult;
    switch (result) {
        .referral => |ref| {
            try testing.expectEqual(@as(usize, 1), ref.count);
            const expected = na.initIp4(.{ 1, 2, 3, 4 }, 53);
            try testing.expectEqual(expected.ip4.bytes, ref.addrs[0].ip4.bytes);
            try testing.expectEqual(@as(u16, 53), ref.addrs[0].getPort());
            try testing.expect(ref.zone_cut.eql(zone_name));
        },
        .no_glue => return error.TestUnexpectedResult,
    }
}

test "extractReferral with no NS records returns null" {
    const response = dns.Message{
        .header = makeHeader(0, 0, 0),
        .questions = &.{},
    };
    try testing.expect(extractReferral(response, dns.Name{ .labels = &.{ "example", "com" } }, dns.Name{ .labels = &.{} }, .{}) == null);
}

test "extractReferral with NS but no glue returns no_glue" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }, .{}) orelse return error.TestUnexpectedResult;
    switch (result) {
        .no_glue => |ng| {
            try testing.expectEqual(@as(usize, 1), ng.ns_count);
            try testing.expect(ng.zone_cut.eql(zone_name));
            const ns_dotted = try nameToDotted(alloc, ng.ns_names[0]);
            defer alloc.free(ns_dotted);
            try testing.expectEqualStrings("ns1.example.com", ns_dotted);
        },
        .referral => return error.TestUnexpectedResult,
    }
}

test "extractReferral case-insensitive glue matching" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "NS1", "EXAMPLE", "COM" });
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 1, 2, 3, 4 })});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }, .{}) orelse return error.TestUnexpectedResult;
    try testing.expect(result == .referral);
    try testing.expectEqual(@as(usize, 1), result.referral.count);
}

test "extractReferral rejects private IP glue (DNS rebinding defense)" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    // Glue pointing to loopback — must be rejected
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 127, 0, 0, 1 })});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }, .{}) orelse return error.TestUnexpectedResult;
    // Private glue is dropped, so we should get no_glue (triggers glueless resolution)
    try testing.expect(result == .no_glue);
}

test "extractReferral accepts loopback glue when policy.allow_loopback = true" {
    // Locks in the test-only opt-in branch: with allow_loopback=true,
    // loopback glue is *not* rejected. Without this test, inverting the
    // boolean default would silently pass every other test.
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 127, 0, 0, 1 })});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(
        response,
        dns.Name{ .labels = &.{ "www", "example", "com" } },
        dns.Name{ .labels = &.{} },
        .{ .allow_loopback = true, .upstream_port = 5353 },
    ) orelse return error.TestUnexpectedResult;
    try testing.expect(result == .referral);
    try testing.expectEqual(@as(usize, 1), result.referral.count);
    // Confirm the policy-supplied port is what gets stamped onto the address.
    try testing.expectEqual(@as(u16, 5353), result.referral.addrs[0].getPort());
}

test "extractReferral rejects out-of-zone glue" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "evil", "org" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "evil", "org" });
    // Glue for ns1.evil.org — out of bailiwick for parent zone "com"
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 6, 6, 6, 6 })});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{"com"} }, .{}) orelse return error.TestUnexpectedResult;
    try testing.expect(result == .no_glue);
}

test "extractReferral no_glue carries multiple NS names" {
    const alloc = testing.allocator;
    const ns1 = try makeName(alloc, &.{ "ns1", "other", "net" });
    const ns2 = try makeName(alloc, &.{ "ns2", "other", "net" });
    const zone1 = try makeName(alloc, &.{ "example", "com" });
    const zone2 = try makeName(alloc, &.{ "example", "com" });
    const response = try makeResponse(alloc, &.{ makeNsRr(zone1, ns1), makeNsRr(zone2, ns2) }, &.{});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }, .{}) orelse return error.TestUnexpectedResult;
    switch (result) {
        .no_glue => |ng| {
            try testing.expectEqual(@as(usize, 2), ng.ns_count);
            try testing.expect(ng.zone_cut.eql(zone1));
        },
        .referral => return error.TestUnexpectedResult,
    }
}

test "extractReferral accepts in-zone glue" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{"com"});
    const glue_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 1, 2, 3, 4 })});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }, .{}) orelse return error.TestUnexpectedResult;
    try testing.expect(result == .referral);
    try testing.expectEqual(@as(usize, 1), result.referral.count);
}

test "extractReferral with AAAA glue returns IPv6 address" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const ipv6 = [_]u8{ 0x26, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueAaaa(glue_name, ipv6)});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }, .{}) orelse return error.TestUnexpectedResult;
    switch (result) {
        .referral => |ref| {
            try testing.expectEqual(@as(usize, 1), ref.count);
            try testing.expectEqual(@as(u16, 53), ref.addrs[0].getPort());
            const expected = na.initIp6(ipv6, 53, 0, 0);
            try testing.expectEqual(expected.ip6.bytes, ref.addrs[0].ip6.bytes);
        },
        .no_glue => return error.TestUnexpectedResult,
    }
}

test "extractReferral rejects same-zone NS as non-referral" {
    // A server returning NS records for its own zone (e.g. alongside a CNAME
    // answer) is not a referral — the zone cut must be strictly deeper than
    // the parent zone.  RFC 1034 §4.2.1, RFC 8499 §7.
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 192, 0, 2, 1 })});
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "api", "example", "com" } };
    // parent_zone == zone_cut → same zone, must return null
    const parent_zone = dns.Name{ .labels = &.{ "example", "com" } };
    try testing.expect(extractReferral(response, target, parent_zone, .{}) == null);
}

// ── findCnameRecord / nameToDotted tests ──────────────────────────────

test "nameToDotted round-trips correctly" {
    const alloc = testing.allocator;
    const name = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const dotted = try nameToDotted(alloc, name);
    defer alloc.free(dotted);
    try testing.expectEqualStrings("www.example.com", dotted);
}

test "findCnameRecord finds CNAME matching target" {
    const alloc = testing.allocator;
    const owner = try makeName(alloc, &.{ "www", "example", "com" });
    const cname_target = try makeName(alloc, &.{ "example", "com" });

    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = owner, .rtype = .cname, .rclass = .in, .ttl = 300, .rdata = .{ .cname = cname_target } };
    const response = dns.Message{ .header = makeHeader(0, 0, 1), .questions = &.{}, .answers = answers };
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const result = findCnameRecord(response, target);
    try testing.expect(result != null);
    try testing.expectEqual(dns.RType.cname, result.?.rtype);
    try testing.expect(target.eql(result.?.name));
}

test "cnameTargetRevisitsChain detects 2-name A→B→A cycle in ≤2 hops" {
    const alloc = testing.allocator;
    const a_name = try makeName(alloc, &.{ "a", "example", "com" });
    const b_name = try makeName(alloc, &.{ "b", "example", "com" });
    defer dns.freeName(alloc, a_name);
    defer dns.freeName(alloc, b_name);

    // Hop 1: A → B
    const cname_ab = dns.ResourceRecord{
        .name = a_name,
        .rtype = .cname,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .cname = b_name },
    };
    // Empty chain accepts anything.
    try testing.expect(!cnameTargetRevisitsChain(&.{}, b_name));

    // After hop 1, chain holds {A→B}. Hop 2 target = A revisits A.
    const chain_one = [_]dns.ResourceRecord{cname_ab};
    try testing.expect(cnameTargetRevisitsChain(&chain_one, a_name));
    // Sanity: a non-revisiting third name is fine.
    const c_name = try makeName(alloc, &.{ "c", "example", "com" });
    defer dns.freeName(alloc, c_name);
    try testing.expect(!cnameTargetRevisitsChain(&chain_one, c_name));
}

test "findCnameRecord returns null when no CNAME present" {
    const alloc = testing.allocator;
    const owner = try makeName(alloc, &.{ "example", "com" });

    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 93, 184, 216, 34 } } };
    const response = dns.Message{ .header = makeHeader(0, 0, 1), .questions = &.{}, .answers = answers };
    defer dns.freeMessage(alloc, response);

    try testing.expect(findCnameRecord(response, dns.Name{ .labels = &.{ "example", "com" } }) == null);
}

test "tryServeFromCache follow_cname: cached A→CNAME→target lets sibling AAAA short-circuit upstream" {
    const alloc = testing.allocator;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io });
    defer cache.deinit();

    // Pre-warm the cache: (alias.example.com CNAME → target.example.com)
    // and (target.example.com AAAA = ::1). Same shape a prior A query
    // would have laid down on its way through this resolver.
    {
        const cname_owner = try makeName(alloc, &.{ "alias", "example", "com" });
        const cname_target = try makeName(alloc, &.{ "target", "example", "com" });
        const cname_rrs = try alloc.alloc(dns.ResourceRecord, 1);
        cname_rrs[0] = .{ .name = cname_owner, .rtype = .cname, .rclass = .in, .ttl = 300, .rdata = .{ .cname = cname_target } };
        const cname_msg = dns.Message{
            .header = makeHeader(0, 0, 1),
            .questions = &.{},
            .answers = cname_rrs,
        };
        defer dns.freeMessage(alloc, cname_msg);
        cache.storeResponse(cname_msg, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
    }
    {
        const aaaa_owner = try makeName(alloc, &.{ "target", "example", "com" });
        const aaaa_rrs = try alloc.alloc(dns.ResourceRecord, 1);
        aaaa_rrs[0] = .{
            .name = aaaa_owner,
            .rtype = .aaaa,
            .rclass = .in,
            .ttl = 300,
            .rdata = .{ .aaaa = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
        };
        const aaaa_msg = dns.Message{
            .header = makeHeader(0, 0, 1),
            .questions = &.{},
            .answers = aaaa_rrs,
        };
        defer dns.freeMessage(alloc, aaaa_msg);
        cache.storeResponse(aaaa_msg, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
    }

    var resolver: RecursiveResolver = .{
        .transports = null,
        .io = testing.io,
        .cache = &cache,
        .cache_only = true, // any upstream attempt → error.CacheOnlyMiss
    };

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = try resolver.resolve(arena.allocator(), "alias.example.com", .aaaa);

    // Two answers: synthesized CNAME from the chain + target AAAA.
    try testing.expectEqual(@as(usize, 2), result.message.answers.len);
    try testing.expectEqual(dns.RType.cname, result.message.answers[0].rtype);
    try testing.expectEqual(dns.RType.aaaa, result.message.answers[1].rtype);
}

test "cousin prefetch: set on NOERROR A/AAAA, suppressed on NXDOMAIN" {
    const alloc = testing.allocator;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io });
    defer cache.deinit();
    {
        const owner = try makeName(alloc, &.{ "host", "example", "com" });
        const rrs = try alloc.alloc(dns.ResourceRecord, 1);
        rrs[0] = .{ .name = owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
        const msg = dns.Message{ .header = makeHeader(0, 0, 1), .questions = &.{}, .answers = rrs };
        defer dns.freeMessage(alloc, msg);
        cache.storeResponse(msg, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
    }

    var resolver: RecursiveResolver = .{
        .transports = null,
        .io = testing.io,
        .cache = &cache,
        .cache_only = true,
    };
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const hit = try resolver.resolve(arena.allocator(), "host.example.com", .a);
    try testing.expectEqual(@as(?dns.RType, .aaaa), hit.cousin_prefetch_qtype);

    // RFC 6761 special-use synthesis: NXDOMAIN with zero upstream work.
    const nx = try resolver.resolve(arena.allocator(), "host.invalid", .a);
    try testing.expectEqual(dns.RCode.name_error, nx.message.header.flags.rcode);
    try testing.expectEqual(@as(?dns.RType, null), nx.cousin_prefetch_qtype);
}

test "svcb cousin target: extraction, coverage skips, strict parse" {
    var buf: [dns.max_name_len + 1]u8 = undefined;
    const owner = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const mk = struct {
        fn rr(name: dns.Name, rtype: dns.RType, rdata: []const u8) dns.ResourceRecord {
            return .{ .name = name, .rtype = rtype, .rclass = .in, .ttl = 300, .rdata = .{ .unknown = rdata } };
        }
    }.rr;
    const target = RecursiveResolver.svcbCousinTarget;

    // ServiceMode with a real target: lowercased dotted text.
    const svc = mk(owner, .https, "\x00\x01\x03SVC\x03cdn\x07example\x00");
    try testing.expectEqualStrings("svc.cdn.example", target(&.{svc}, .https, "www.example.com", &buf).?);

    // AliasMode targets count too; foreign rtypes are skipped, first
    // eligible target wins.
    const alias = mk(owner, .https, "\x00\x00\x03svc\x03cdn\x07example\x00");
    const dot = mk(owner, .https, "\x00\x01\x00");
    const cname = mk(owner, .cname, "");
    try testing.expectEqualStrings("svc.cdn.example", target(&.{ cname, dot, alias }, .https, "www.example.com", &buf).?);

    // Targets the client's parallel queries already cover: ".",
    // qname-equal, owner-equal (case-insensitive).
    try testing.expect(target(&.{dot}, .https, "www.example.com", &buf) == null);
    const qname_eq = mk(owner, .https, "\x00\x01\x03www\x07example\x03com\x00");
    try testing.expect(target(&.{qname_eq}, .https, "WWW.example.COM", &buf) == null);
    try testing.expect(target(&.{qname_eq}, .https, "alias.example.com", &buf) == null); // owner-equal

    // Strict parse: compression pointer, truncation, non-LDH byte.
    try testing.expect(target(&.{mk(owner, .https, "\x00\x01\xc0\x0c")}, .https, "www.example.com", &buf) == null);
    try testing.expect(target(&.{mk(owner, .https, "\x00\x01\x03svc")}, .https, "www.example.com", &buf) == null);
    try testing.expect(target(&.{mk(owner, .https, "\x00\x01\x03s?c\x00")}, .https, "www.example.com", &buf) == null);
}

test "cousin prefetch: https answer carries target name through resolve" {
    const alloc = testing.allocator;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io });
    defer cache.deinit();
    {
        const owner = try makeName(alloc, &.{ "www", "example", "com" });
        const rrs = try alloc.alloc(dns.ResourceRecord, 1);
        rrs[0] = .{ .name = owner, .rtype = .https, .rclass = .in, .ttl = 300, .rdata = .{ .unknown = try alloc.dupe(u8, "\x00\x01\x03svc\x03cdn\x07example\x00") } };
        const msg = dns.Message{ .header = makeHeader(0, 0, 1), .questions = &.{}, .answers = rrs };
        defer dns.freeMessage(alloc, msg);
        cache.storeResponse(msg, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
    }

    var resolver: RecursiveResolver = .{
        .transports = null,
        .io = testing.io,
        .cache = &cache,
        .cache_only = true,
    };
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const hit = try resolver.resolve(arena.allocator(), "www.example.com", .https);
    try testing.expectEqual(@as(?dns.RType, null), hit.cousin_prefetch_qtype);
    try testing.expectEqualStrings("svc.cdn.example", hit.cousin_prefetch_name.?);
}

// Controllable clock for prefetch-window tests (mirrors cache.zig's).
var test_time: i64 = 0;
fn testNowSeconds() i64 {
    return test_time;
}

/// Seed (alias → target CNAME, target AAAA) with independent TTLs so either
/// chain member can be aged into its prefetch window.
fn seedCnameChain(alloc: mem.Allocator, cache: *RRsetCache, cname_ttl: u32, tail_ttl: u32) !void {
    {
        const cname_owner = try makeName(alloc, &.{ "alias", "example", "com" });
        const cname_target = try makeName(alloc, &.{ "target", "example", "com" });
        const cname_rrs = try alloc.alloc(dns.ResourceRecord, 1);
        cname_rrs[0] = .{ .name = cname_owner, .rtype = .cname, .rclass = .in, .ttl = cname_ttl, .rdata = .{ .cname = cname_target } };
        const cname_msg = dns.Message{ .header = makeHeader(0, 0, 1), .questions = &.{}, .answers = cname_rrs };
        defer dns.freeMessage(alloc, cname_msg);
        cache.storeResponse(cname_msg, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
    }
    {
        const aaaa_owner = try makeName(alloc, &.{ "target", "example", "com" });
        const aaaa_rrs = try alloc.alloc(dns.ResourceRecord, 1);
        aaaa_rrs[0] = .{
            .name = aaaa_owner,
            .rtype = .aaaa,
            .rclass = .in,
            .ttl = tail_ttl,
            .rdata = .{ .aaaa = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
        };
        const aaaa_msg = dns.Message{ .header = makeHeader(0, 0, 1), .questions = &.{}, .answers = aaaa_rrs };
        defer dns.freeMessage(alloc, aaaa_msg);
        cache.storeResponse(aaaa_msg, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
    }
}

test "chain tail in prefetch window flags head prefetch (mid-chain hit)" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io, .prefetch = true });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    // Long-lived redirect, short-lived tail — the CDN shape.
    try seedCnameChain(alloc, &cache, 3600, 300);

    // Tail: remaining 10 of 300 → in window. CNAME: remaining 3310 → not.
    test_time = 1290;

    var resolver: RecursiveResolver = .{
        .transports = null,
        .io = testing.io,
        .cache = &cache,
        .cache_only = true,
    };
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = try resolver.resolve(arena.allocator(), "alias.example.com", .aaaa);

    try testing.expectEqual(@as(usize, 2), result.message.answers.len);
    try testing.expect(result.from_cache);
    // The aging tail must surface as a prefetch of (head, qtype) — a bg
    // re-walk refreshes the whole chain.
    try testing.expect(result.prefetch_name != null);
    try testing.expectEqualStrings("alias.example.com", result.prefetch_name.?);
    try testing.expectEqual(dns.RType.aaaa, result.prefetch_qtype);
}

test "aging CNAME redirect on follow path flags head prefetch" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io, .prefetch = true });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    // Short-lived redirect, long-lived tail: the CNAME RRset itself ages
    // into the window and is served via the follow path (never a direct
    // (name, .cname) hit — stubs don't ask for CNAME).
    try seedCnameChain(alloc, &cache, 300, 3600);

    test_time = 1290;

    var resolver: RecursiveResolver = .{
        .transports = null,
        .io = testing.io,
        .cache = &cache,
        .cache_only = true,
    };
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = try resolver.resolve(arena.allocator(), "alias.example.com", .aaaa);

    try testing.expectEqual(@as(usize, 2), result.message.answers.len);
    try testing.expect(result.prefetch_name != null);
    try testing.expectEqualStrings("alias.example.com", result.prefetch_name.?);
    try testing.expectEqual(dns.RType.aaaa, result.prefetch_qtype);
}

test "fresh chain sets no prefetch and reports from_cache" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io, .prefetch = true });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    try seedCnameChain(alloc, &cache, 3600, 3600);
    test_time = 1010; // both members young

    var resolver: RecursiveResolver = .{
        .transports = null,
        .io = testing.io,
        .cache = &cache,
        .cache_only = true,
    };
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = try resolver.resolve(arena.allocator(), "alias.example.com", .aaaa);

    try testing.expect(result.from_cache);
    try testing.expect(result.prefetch_name == null);
}

test "tryServeFromCache follow_cname: cycle detection catches A→B→A in cache-served path" {
    const alloc = testing.allocator;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io });
    defer cache.deinit();

    // Build a deliberately cyclic pair of CNAMEs in the cache: an
    // attacker (or a really mangled zone) gives us a.example.com →
    // b.example.com and b.example.com → a.example.com. The upstream
    // path's loop check already catches this; the cache path must too.
    inline for ([_]struct { owner: []const []const u8, target: []const []const u8 }{
        .{ .owner = &.{ "a", "example", "com" }, .target = &.{ "b", "example", "com" } },
        .{ .owner = &.{ "b", "example", "com" }, .target = &.{ "a", "example", "com" } },
    }) |pair| {
        const owner = try makeName(alloc, pair.owner);
        const target = try makeName(alloc, pair.target);
        const rrs = try alloc.alloc(dns.ResourceRecord, 1);
        rrs[0] = .{ .name = owner, .rtype = .cname, .rclass = .in, .ttl = 300, .rdata = .{ .cname = target } };
        const msg = dns.Message{
            .header = makeHeader(0, 0, 1),
            .questions = &.{},
            .answers = rrs,
        };
        defer dns.freeMessage(alloc, msg);
        cache.storeResponse(msg, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
    }

    var resolver: RecursiveResolver = .{
        .transports = null,
        .io = testing.io,
        .cache = &cache,
        .cache_only = true,
    };

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = try resolver.resolve(arena.allocator(), "a.example.com", .a);

    // Cycle ⇒ SERVFAIL. Worth pinning: the upstream-blocked variant
    // would otherwise pop CacheOnlyMiss instead.
    try testing.expectEqual(dns.RCode.server_failure, result.message.header.flags.rcode);
}

test "aggregateCachedCnameWildcardProofs appends only when status is .secure" {
    const alloc = testing.allocator;

    const owner = try makeName(alloc, &.{ "x", "example", "com" });
    const next = try makeName(alloc, &.{ "z", "example", "com" });
    defer dns.freeName(alloc, owner);
    defer dns.freeName(alloc, next);

    const nsec_rr = dns.ResourceRecord{
        .name = owner,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .nsec = .{ .next_domain_name = next, .type_bit_maps = &.{} } },
    };

    // .unchecked → no-op (an unauthenticated cached entry must never
    // contribute AD-bearing material).
    {
        var agg: std.ArrayListUnmanaged(dns.ResourceRecord) = .empty;
        defer agg.deinit(alloc);
        try aggregateCachedCnameWildcardProofs(alloc, .unchecked, &.{nsec_rr}, &agg);
        try testing.expectEqual(@as(usize, 0), agg.items.len);
    }
    // .insecure → no-op.
    {
        var agg: std.ArrayListUnmanaged(dns.ResourceRecord) = .empty;
        defer agg.deinit(alloc);
        try aggregateCachedCnameWildcardProofs(alloc, .insecure, &.{nsec_rr}, &agg);
        try testing.expectEqual(@as(usize, 0), agg.items.len);
    }
    // .secure → proof material flows through.
    {
        var agg: std.ArrayListUnmanaged(dns.ResourceRecord) = .empty;
        defer agg.deinit(alloc);
        try aggregateCachedCnameWildcardProofs(alloc, .secure, &.{nsec_rr}, &agg);
        try testing.expectEqual(@as(usize, 1), agg.items.len);
        try testing.expectEqual(dns.RType.nsec, agg.items[0].rtype);
    }
}

// ── QNAME minimization tests ──────────────────────────────────────────

test "probe name construction from label sub-slice" {
    const full_labels: []const []const u8 = &.{ "www", "sub", "example", "com" };
    var buf: [dns.max_name_len + 1]u8 = undefined;

    try testing.expectEqualStrings("com", (dns.Name{ .labels = full_labels[3..] }).formatInto(&buf));
    try testing.expectEqualStrings("example.com", (dns.Name{ .labels = full_labels[2..] }).formatInto(&buf));
    try testing.expectEqualStrings("sub.example.com", (dns.Name{ .labels = full_labels[1..] }).formatInto(&buf));
    try testing.expectEqualStrings("www.sub.example.com", (dns.Name{ .labels = full_labels[0..] }).formatInto(&buf));
}

test "minimization stepping — probes advance one label at a time" {
    // Simulate: target = "www.sub.example.com", parent_zone = "com" (1 label)
    // Expected probes: label_count 2 → "example.com", 3 → "sub.example.com", 4 → final "www.sub.example.com"
    const target_labels: []const []const u8 = &.{ "www", "sub", "example", "com" };
    const parent_zone_labels: usize = 1; // "com"

    var label_count: usize = parent_zone_labels + 1; // start at 2
    var buf: [dns.max_name_len + 1]u8 = undefined;

    try testing.expectEqual(@as(usize, 2), label_count);
    try testing.expectEqualStrings("example.com", (dns.Name{ .labels = target_labels[target_labels.len - label_count ..] }).formatInto(&buf));
    label_count += 1;

    try testing.expectEqual(@as(usize, 3), label_count);
    try testing.expectEqualStrings("sub.example.com", (dns.Name{ .labels = target_labels[target_labels.len - label_count ..] }).formatInto(&buf));
    label_count += 1;

    // Now label_count == target_labels.len → is_final
    try testing.expectEqual(@as(usize, 4), label_count);
    try testing.expect(label_count >= target_labels.len);
}

// ── validateNegativeResponse tests ─────────────────────────────────────

test "validateNegativeResponse returns proceed when security_state is not secure" {
    const name = dns.Name{ .labels = &.{ "example", "com" } };
    var b: dnssec.ValidationBudget = .{};
    // unchecked/insecure → proceed regardless of authorities
    try testing.expectEqual(NegativeValidation{ .proceed = .unchecked }, validateNegativeResponse(.unchecked, &.{}, name, .a, true, test_root, &b));
    try testing.expectEqual(NegativeValidation{ .proceed = .insecure }, validateNegativeResponse(.insecure, &.{}, name, .a, false, test_root, &b));
}

test "validateNegativeResponse caches an .insecure proof instead of discarding it" {
    // `.insecure` in a secure zone is a valid denial that may not carry AD.
    // Mapping it to `.skip_cache` conflated it with "signatures did not verify"
    // and threw the answer away. The Opt-Out verdict is covered in dnssec.zig;
    // this pins the mapping, via the cheapest `.insecure` producer.
    const qname = dns.Name{ .labels = &.{ "victim", "com" } };
    var salt_buf: [4]u8 = @splat(0xAB);
    const high_iteration_nsec3 = [_]dns.ResourceRecord{.{
        .name = dns.Name{ .labels = &.{ "hash", "com" } },
        .rtype = .nsec3,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{
            .nsec3 = .{
                .hash_algorithm = .sha1,
                .flags = 0,
                .iterations = 200, // > max_nsec3_iterations → RFC 9276 §3.2
                .salt = &salt_buf,
                .next_hashed_owner = &@as([20]u8, @splat(0x43)),
                .type_bit_maps = &.{},
            },
        },
    }};
    var b: dnssec.ValidationBudget = .{};
    try testing.expectEqual(
        NegativeValidation{ .proceed = .insecure },
        validateNegativeResponse(.secure, &high_iteration_nsec3, qname, .a, true, test_root, &b),
    );
}

const test_root = dns.Name{ .labels = &.{} };

test "validateNegativeResponse binds a proof to the zone that signed it" {
    // The live counterexample: one publicly-fetchable wrap NSEC out of
    // example.net proves NXDOMAIN *and* NODATA for victim.com on geometry
    // alone (com < net, so the wrap range covers it, the closest encloser
    // clamps to root, and the same record covers the wildcard). Every
    // signature involved is real — only the zone binding stops it.
    testing.log_level = .err; // silence the fail-closed diagnostic warn
    const net_zone = dns.Name{ .labels = &.{ "example", "net" } };
    const authorities = [_]dns.ResourceRecord{
        .{
            .name = dns.Name{ .labels = &.{ "zzz", "example", "net" } },
            .rtype = .nsec,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .nsec = .{ .next_domain_name = net_zone, .type_bit_maps = &.{} } },
        },
    };
    const victim = dns.Name{ .labels = &.{ "victim", "com" } };
    var b: dnssec.ValidationBudget = .{};

    // Unbound (root zone): the proof is "complete" — that is the whole problem.
    try testing.expectEqual(
        dnssec.SecurityStatus.secure,
        dnssec.validateNegativeProof(&authorities, victim, .a, true, test_root, &b),
    );

    // Bound to the zone that actually signed it: victim.com is not under it,
    // and neither is the NSEC owner a member of any chain covering victim.com.
    try testing.expectEqual(
        NegativeValidation.bogus,
        validateNegativeResponse(.secure, &authorities, victim, .a, true, net_zone, &b),
    );

    // Positive control: the same zone denying one of its own names. The wrap
    // covers zzzz.example.net, and the apex NSEC covers *.example.net, so the
    // §5.4 pair is complete and the binding lets it through.
    const in_zone_auth = authorities ++ [_]dns.ResourceRecord{.{
        .name = net_zone,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{
            .nsec = .{
                .next_domain_name = dns.Name{ .labels = &.{ "a", "example", "net" } },
                .type_bit_maps = &.{ 0x00, 0x01, 0x62 }, // A NS SOA: a real apex
            },
        },
    }};
    const in_zone = dns.Name{ .labels = &.{ "zzzz", "example", "net" } };
    try testing.expectEqual(
        NegativeValidation{ .proceed = .secure },
        validateNegativeResponse(.secure, &in_zone_auth, in_zone, .a, true, net_zone, &b),
    );
}

test "validateNegativeResponse returns bogus for mixed NSEC/NSEC3 authorities" {
    testing.log_level = .err; // silence the fail-closed diagnostic warn
    const name = dns.Name{ .labels = &.{ "example", "com" } };
    // Build authorities with both NSEC and NSEC3 records
    const authorities = [_]dns.ResourceRecord{
        .{
            .name = dns.Name{ .labels = &.{ "example", "com" } },
            .rtype = .nsec,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{
                .nsec = .{
                    .next_domain_name = dns.Name{ .labels = &.{ "z", "example", "com" } },
                    .type_bit_maps = &.{ 0, 1, 0x40 }, // window 0, len 1, A bit
                },
            },
        },
        .{
            .name = dns.Name{ .labels = &.{ "example", "com" } },
            .rtype = .nsec3,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .nsec3 = .{
                .hash_algorithm = .sha1,
                .flags = 0,
                .iterations = 0,
                .salt = &.{},
                .next_hashed_owner = &@as([20]u8, @splat(0)),
                .type_bit_maps = &.{},
            } },
        },
    };
    var b: dnssec.ValidationBudget = .{};
    try testing.expectEqual(NegativeValidation.bogus, validateNegativeResponse(.secure, &authorities, name, .a, true, test_root, &b));
}

test "validateNegativeResponse returns proceed for valid NSEC NODATA proof" {
    const name = dns.Name{ .labels = &.{ "example", "com" } };
    // NSEC owner matches qname, type bitmap does NOT include A.
    // Bitmap with only SOA (type 6): window 0, len 1, byte 0 = 0x02 (bit 6)
    const authorities = [_]dns.ResourceRecord{
        .{
            .name = dns.Name{ .labels = &.{ "example", "com" } },
            .rtype = .nsec,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{
                .nsec = .{
                    .next_domain_name = dns.Name{ .labels = &.{ "z", "example", "com" } },
                    .type_bit_maps = &.{ 0, 1, 0x02 }, // window 0, len 1, only SOA
                },
            },
        },
    };
    var b: dnssec.ValidationBudget = .{};
    try testing.expectEqual(NegativeValidation{ .proceed = .secure }, validateNegativeResponse(.secure, &authorities, name, .a, false, test_root, &b));
}

test "validateNegativeResponse returns bogus when no proof found in secure zone" {
    testing.log_level = .err; // silence the fail-closed diagnostic warn
    const name = dns.Name{ .labels = &.{ "nonexistent", "example", "com" } };
    // Empty authorities in a known-secure zone is a downgrade attempt:
    // RFC 4035 §3.2.1 requires NSEC/NSEC3 with every negative response for
    // signed zones. Fail closed rather than serving the unauthenticated
    // NXDOMAIN/NODATA.
    var b: dnssec.ValidationBudget = .{};
    try testing.expectEqual(NegativeValidation.bogus, validateNegativeResponse(.secure, &.{}, name, .a, true, test_root, &b));
    try testing.expectEqual(NegativeValidation.bogus, validateNegativeResponse(.secure, &.{}, name, .a, false, test_root, &b));
}

test "validateNegativeResponse returns bogus on incomplete NSEC NXDOMAIN proof" {
    testing.log_level = .err; // silence the fail-closed diagnostic warn
    // NSEC covers qname but the wildcard-denial NSEC is missing — RFC 4035
    // §5.4 requires both. validateNegativeProof returns .unchecked; the
    // recursive wrapper must escalate that to .bogus inside a secure zone,
    // not serve the response unauthenticated.
    const aaa = dns.Name{ .labels = &.{ "aaa", "example", "com" } };
    const ccc = dns.Name{ .labels = &.{ "ccc", "example", "com" } };
    const beta = dns.Name{ .labels = &.{ "beta", "example", "com" } };
    const authorities = [_]dns.ResourceRecord{
        .{ .name = aaa, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{
            .next_domain_name = ccc,
            .type_bit_maps = &.{},
        } } },
        // No NSEC for *.example.com — proof is incomplete.
    };
    var b: dnssec.ValidationBudget = .{};
    try testing.expectEqual(
        NegativeValidation.bogus,
        validateNegativeResponse(.secure, &authorities, beta, .a, true, test_root, &b),
    );
}

test "dns.isNsecProofMaterial classifies the chain-aggregate keep set" {
    const sample_name = dns.Name{ .labels = &.{ "x", "example", "com" } };
    const sample_next = dns.Name{ .labels = &.{ "y", "example", "com" } };

    const nsec_rr = dns.ResourceRecord{
        .name = sample_name,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .nsec = .{ .next_domain_name = sample_next, .type_bit_maps = &.{} } },
    };
    const nsec3_rr = dns.ResourceRecord{
        .name = sample_name,
        .rtype = .nsec3,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .nsec3 = .{
            .hash_algorithm = .sha1,
            .flags = 0,
            .iterations = 0,
            .salt = &.{},
            .next_hashed_owner = &.{},
            .type_bit_maps = &.{},
        } },
    };
    const mkrrsig = struct {
        fn f(covered: dns.RType) dns.ResourceRecord {
            return .{
                .name = dns.Name{ .labels = &.{ "x", "example", "com" } },
                .rtype = .rrsig,
                .rclass = .in,
                .ttl = 3600,
                .rdata = .{ .rrsig = .{
                    .type_covered = covered,
                    .algorithm = .ecdsap256sha256,
                    .labels = 3,
                    .original_ttl = 3600,
                    .sig_expiration = 0,
                    .sig_inception = 0,
                    .key_tag = 0,
                    .signer_name = dns.Name{ .labels = &.{ "example", "com" } },
                    .signature = &.{},
                } },
            };
        }
    }.f;
    const ns_rr = dns.ResourceRecord{
        .name = sample_name,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .ns = sample_next },
    };

    try testing.expect(dns.isNsecProofMaterial(nsec_rr));
    try testing.expect(dns.isNsecProofMaterial(nsec3_rr));
    try testing.expect(dns.isNsecProofMaterial(mkrrsig(.nsec)));
    try testing.expect(dns.isNsecProofMaterial(mkrrsig(.nsec3)));
    try testing.expect(!dns.isNsecProofMaterial(mkrrsig(.ns)));
    try testing.expect(!dns.isNsecProofMaterial(mkrrsig(.a)));
    try testing.expect(!dns.isNsecProofMaterial(ns_rr));
}

test "withCnameChain prepends auth_aggregate to authorities (chain wildcard-proof case)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const owner = dns.Name{ .labels = &.{ "example", "com" } };
    const next = dns.Name{ .labels = &.{ "z", "example", "com" } };
    const cname_target = dns.Name{ .labels = &.{ "tgt", "example", "com" } };

    const cname_rr = dns.ResourceRecord{
        .name = owner,
        .rtype = .cname,
        .rclass = .in,
        .ttl = 60,
        .rdata = .{ .cname = cname_target },
    };
    const a_rr = dns.ResourceRecord{
        .name = cname_target,
        .rtype = .a,
        .rclass = .in,
        .ttl = 60,
        .rdata = .{ .a = .{ 192, 0, 2, 1 } },
    };
    const nsec_rr = dns.ResourceRecord{
        .name = owner,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .nsec = .{ .next_domain_name = next, .type_bit_maps = &.{} } },
    };

    const terminal_response = dns.Message{
        .header = .{
            .id = 0,
            .flags = .{
                .qr = true,
                .opcode = .query,
                .aa = false,
                .tc = false,
                .rd = false,
                .ra = true,
                .z = 0,
                .ad = false,
                .cd = false,
                .rcode = .no_error,
            },
            .qd_count = 0,
            .an_count = 1,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = &.{a_rr},
    };

    var cc: CnameChain = .{};
    defer cc.deinit(a);
    try cc.records.append(a, cname_rr);
    try cc.wildcard_proofs.append(a, nsec_rr);
    const stitched = try withCnameChain(a, &cc, terminal_response);

    try testing.expectEqual(@as(usize, 2), stitched.answers.len); // CNAME + A
    try testing.expectEqual(dns.RType.cname, stitched.answers[0].rtype);
    try testing.expectEqual(dns.RType.a, stitched.answers[1].rtype);
    try testing.expectEqual(@as(usize, 1), stitched.authorities.len); // NSEC aggregated
    try testing.expectEqual(dns.RType.nsec, stitched.authorities[0].rtype);
}

test "withCnameChain clears AD when any hop was not proven secure" {
    // The live shape: an unsigned zone CNAMEs into a signed CDN. The tail
    // validates, so the terminal response carries AD — but the redirect that
    // chose that tail was never authenticated, so the answer as a whole is
    // not. Both AD-setting sites are upstream of this funnel: validateAnswer
    // for a freshly-resolved target, and the cache-served synthesizedMessage
    // for a repeat of the same (qname, qtype), which files the answer under
    // the CNAME target and so flips AD 0→1 on the second identical query.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const owner = dns.Name{ .labels = &.{ "unsigned", "example" } };
    const cname_target = dns.Name{ .labels = &.{ "tgt", "signed", "example" } };
    const cname_rr = dns.ResourceRecord{ .name = owner, .rtype = .cname, .rclass = .in, .ttl = 60, .rdata = .{ .cname = cname_target } };
    const a_rr = dns.ResourceRecord{ .name = cname_target, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 192, 0, 2, 1 } } };

    const validated_tail = synthesizedMessage(&.{a_rr}, &.{}, .no_error, true);
    try testing.expect(validated_tail.header.flags.ad);

    var insecure_hop: CnameChain = .{};
    defer insecure_hop.deinit(a);
    try insecure_hop.hop(a, cname_rr, .unchecked);
    try testing.expectEqual(false, (try withCnameChain(a, &insecure_hop, validated_tail)).header.flags.ad);

    // A fully-proven chain keeps it.
    var secure_hop: CnameChain = .{};
    defer secure_hop.deinit(a);
    try secure_hop.hop(a, cname_rr, .secure);
    try testing.expectEqual(true, (try withCnameChain(a, &secure_hop, validated_tail)).header.flags.ad);

    // One bad hop anywhere in the chain poisons the whole answer.
    try secure_hop.hop(a, cname_rr, .insecure);
    try secure_hop.hop(a, cname_rr, .secure);
    try testing.expectEqual(false, (try withCnameChain(a, &secure_hop, validated_tail)).header.flags.ad);
}

// ── cache_only guard tests ────────────────────────────────────────────
// Pin the recv-thread fast-path invariant: every upstream-reaching entry
// must short-circuit before any `transports.?` access. Two guards cover
// the surface: `queryAuthoritativeServers` (the main recursion entry) and
// `fetchRRset` (reached via `findClosestCachedDelegation` →
// `reproveDelegationSecurity`). A real crash motivated the second guard.

test "fetchRRset returns CacheOnlyMiss when cache_only=true" {
    var resolver: RecursiveResolver = .{
        .transports = null,
        .io = testing.io,
        .cache_only = true,
    };
    const servers: []const na.Address = &.{na.initIp4(.{ 192, 0, 2, 1 }, 53)};
    const result = resolver.fetchRRset(testing.allocator, "example.com", .a, servers, 1, false, false);
    try testing.expectError(error.CacheOnlyMiss, result);
}

test "queryAuthoritativeServers returns CacheOnlyMiss when cache_only=true" {
    var resolver: RecursiveResolver = .{
        .transports = null,
        .io = testing.io,
        .cache_only = true,
    };
    var servers: [max_servers_per_level]na.Address = undefined;
    servers[0] = na.initIp4(.{ 192, 0, 2, 1 }, 53);
    const parent_zone = dns.Name{ .labels = &.{} };
    const result = resolver.queryAuthoritativeServers(testing.allocator, "example.com", .a, &servers, 1, parent_zone);
    try testing.expectError(error.CacheOnlyMiss, result);
}

// ── QueryBudget: tree-wide NXNS guard ─────────────────────────────────

test "QueryBudget.consume permits exactly max draws then refuses" {
    var budget: QueryBudget = .{ .max = 5 };
    for (0..5) |_| try budget.consume();
    try testing.expectError(error.GlobalQueryBudgetExhausted, budget.consume());
    // Stays refused once exhausted — the counter never resets mid-resolution
    // (the property that makes it NXNS-proof; cf. BIND #4741). The shared-by-
    // pointer-across-cloneForThread invariant is guarded end-to-end by
    // test/harness/test_nxns_amplification.py, not here — a unit test can only
    // restate Zig's value-copy semantics, which is not the thing that breaks.
    try testing.expectError(error.GlobalQueryBudgetExhausted, budget.consume());
}

test "validation budget stays tree-wide across cloneForThread under concurrent fan-out" {
    // Real helper threads each clone the parent (production cloneForThread) and
    // charge the shared budget until refused. Shared-by-pointer ⇒ exactly `ceiling`
    // draws succeed across ALL clones, not per-clone — the reset-on-clone guard a
    // struct test can't give. Teeth: re-add a per-clone reset to cloneForThread and
    // the total jumps to K*ceiling, turning this RED.
    const K = 6;
    const ceiling: u32 = 40;
    var shared: dnssec.ValidationBudget = .{ .max_sig_verify = ceiling };
    var parent: RecursiveResolver = .{
        .transports = null,
        .io = testing.io,
        .validation_budget = &shared,
    };

    const Worker = struct {
        parent: *RecursiveResolver,
        granted: u32 = 0,
        fn run(w: *@This()) void {
            var udp_t = BlockingUdpTransport.init(.{}, w.parent.io);
            defer udp_t.deinit();
            var clone = w.parent.cloneForThread(.{ .udp = &udp_t, .tcp_enabled = false, .tls = null });
            const vb = clone.validationBudget();
            while (true) {
                vb.consumeVerify() catch break;
                w.granted += 1;
            }
        }
    };

    var workers: [K]Worker = undefined;
    for (&workers) |*w| w.* = .{ .parent = &parent };
    var threads: [K]std.Thread = undefined;
    for (&threads, &workers) |*t, *w| t.* = try std.Thread.spawn(.{}, Worker.run, .{w});
    for (&threads) |t| t.join();

    var total: u32 = 0;
    for (workers) |w| total += w.granted;
    try testing.expectEqual(ceiling, total);
}

fn concatRRsOomProbe(allocator: mem.Allocator, _: void) !void {
    // Two non-empty inputs force `concatRRs` onto its allocating branch
    // (both empty / one empty paths return the input unchanged). The
    // function's only heap allocation is the combined output slice — a
    // single failure point — so this exercises that lone alloc.
    const blank: dns.ResourceRecord = .{
        .name = .{ .labels = &.{} },
        .rtype = .a,
        .rclass = .in,
        .ttl = 0,
        .rdata = .{ .a = .{ 0, 0, 0, 0 } },
    };
    const a = [_]dns.ResourceRecord{ blank, blank };
    const b = [_]dns.ResourceRecord{ blank, blank, blank };
    const out = try concatRRs(allocator, &a, &b);
    // concatRRs returns the alloc'd buffer on the allocating branch and
    // an input alias on the fast path. Free only when it allocated.
    if (out.ptr != @as([*]const dns.ResourceRecord, &a) and out.ptr != @as([*]const dns.ResourceRecord, &b)) {
        allocator.free(out);
    }
}

test "concatRRs handles OOM without leaking" {
    try testing.checkAllAllocationFailures(testing.allocator, concatRRsOomProbe, .{{}});
}

// ── tryParseMessage 0x20-case scrub tests ──────────────────────────────
//
// These cover the bug where 0x20-randomized case in upstream replies
// leaked into client responses via answer/authority/additional owner
// names — visible as `PING x.cOm` for a `ping x.com` query. The scrub
// in `tryParseMessage` lowercases every RR owner name; the question
// section keeps its upstream-echoed case so the resolver's eqlExact
// 0x20-echo verification still works.

fn buildMixedCaseAnswerPacket(buf: *[64]u8) []const u8 {
    var pos = writeMixedCaseQuestion(buf, .a);
    pos = writeAnswerHeader(buf, pos, .a, 4);
    buf[pos] = 192;
    buf[pos + 1] = 0;
    buf[pos + 2] = 2;
    buf[pos + 3] = 1;
    return buf[0 .. pos + 4];
}

test "tryParseMessage lowercases answer owner names but preserves question case" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [64]u8 = undefined;
    const wire = buildMixedCaseAnswerPacket(&buf);

    const server = na.initIp4(.{ 127, 0, 0, 1 }, 53);
    const msg = (try tryParseMessage(arena.allocator(), wire, server)) orelse return error.TestUnexpectedResult;

    // Question must keep its upstream-echoed bytes — eqlExact compares
    // it byte-for-byte against the outgoing randomized query name.
    try testing.expectEqual(@as(usize, 1), msg.questions.len);
    try testing.expectEqual(@as(usize, 2), msg.questions[0].name.labels.len);
    try testing.expectEqualStrings("X", msg.questions[0].name.labels[0]);
    try testing.expectEqualStrings("coM", msg.questions[0].name.labels[1]);

    // Answer owner must be lowercase — this is the client-visible name
    // that was leaking 0x20 randomization before the fix.
    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    try testing.expectEqual(@as(usize, 2), msg.answers[0].name.labels.len);
    try testing.expectEqualStrings("x", msg.answers[0].name.labels[0]);
    try testing.expectEqualStrings("com", msg.answers[0].name.labels[1]);
}

test "tryParseMessage clears an upstream-set AD bit" {
    // Route 53 sets AD on every DO=1 reply, including for zones with no DS.
    // Carried through, that bit reaches the client as "DNSSEC-authenticated"
    // for data hark never validated.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [64]u8 = undefined;
    const wire = buildMixedCaseAnswerPacket(&buf);
    mem.writeInt(u16, buf[2..4], 0x81A0, .big); // qr rd ra + AD

    const server = na.initIp4(.{ 127, 0, 0, 1 }, 53);
    const msg = (try tryParseMessage(arena.allocator(), wire, server)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(false, msg.header.flags.ad);
}

test "tryWildcardSynth lowercases owner and clears wire blob on rewrite" {
    // The user-visible bug surface: cached wildcard RRset has owner
    // `*.example.com` (lowercased on store), client queries
    // `WhAtEvEr.example.com`. Pre-fix, `tryWildcardSynth` rewrote
    // `rr.name = target_name` (mixed case) but left `rr.wire` set to
    // the cached blob carrying `*.example.com`. `writeResourceRecord`'s
    // fast path then memcpyd the blob and the client saw `*.example.com`
    // in the answer (or, if target_name had been lowercased only, the
    // wildcard literal). Assert both fixes: owner is lowercase AND
    // wire is null so serialization picks up the rewritten name.
    const alloc = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const aa = arena.allocator();

    // Store a wildcard A RRset under `*.example.com`.
    const star_labels = try aa.alloc([]const u8, 3);
    star_labels[0] = try aa.dupe(u8, "*");
    star_labels[1] = try aa.dupe(u8, "example");
    star_labels[2] = try aa.dupe(u8, "com");
    const wildcard_name = dns.Name{ .labels = star_labels };

    const rrs = try aa.alloc(dns.ResourceRecord, 1);
    rrs[0] = .{
        .name = wildcard_name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .a = .{ 192, 0, 2, 99 } },
    };
    const store_msg = dns.Message{
        .header = .{
            .id = 0,
            .flags = .{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = false, .ra = true, .z = 0, .ad = false, .cd = false, .rcode = .no_error },
            .qd_count = 0,
            .an_count = 1,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = rrs,
    };

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io });
    defer cache.deinit();
    cache.storeResponse(store_msg, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

    // Build a target name with mixed case: `WhAtEvEr.example.com`.
    const tgt_labels = try aa.alloc([]const u8, 3);
    tgt_labels[0] = try aa.dupe(u8, "WhAtEvEr");
    tgt_labels[1] = try aa.dupe(u8, "example");
    tgt_labels[2] = try aa.dupe(u8, "com");
    const target_name = dns.Name{ .labels = tgt_labels };

    // Minimal SOA placeholder (synthesis returns it in authority section;
    // not under test here, but tryWildcardSynth signature requires it).
    const soa_mname = dns.Name{ .labels = &.{ "example", "com" } };
    const soa_rname = dns.Name{ .labels = &.{ "hostmaster", "example", "com" } };
    const soa_rr = dns.ResourceRecord{
        .name = dns.Name{ .labels = &.{ "example", "com" } },
        .rtype = .soa,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .soa = .{ .mname = soa_mname, .rname = soa_rname, .serial = 1, .refresh = 3600, .retry = 600, .expire = 86400, .minimum = 3600 } },
    };

    var resolver: RecursiveResolver = .{
        .transports = null,
        .io = testing.io,
        .cache = &cache,
    };

    const empty_chain: CnameChain = .{};
    const synth = (try resolver.tryWildcardSynth(aa, 2, soa_rr, &.{}, target_name, .a, &empty_chain)) orelse return error.TestExpectedSynth;

    try testing.expect(synth.answers.len >= 1);
    const ans = synth.answers[0];
    // Owner is lowercase — client-visible name, was `WhAtEvEr.example.com` pre-fix.
    try testing.expectEqual(@as(usize, 3), ans.name.labels.len);
    try testing.expectEqualStrings("whatever", ans.name.labels[0]);
    try testing.expectEqualStrings("example", ans.name.labels[1]);
    try testing.expectEqualStrings("com", ans.name.labels[2]);
    // Wire blob was cleared so writeResourceRecord falls into the slow
    // path and re-serializes from the rewritten name. Pre-fix the blob
    // held `*.example.com`.
    try testing.expect(ans.wire == null);
    try testing.expectEqual(@as(u16, 0), ans.wire_ttl_offset);
}

// ── tryParseMessage 0x20 RDATA-name scrub tests ────────────────────────
//
// Worst case: a compression pointer in RDATA aliasing back to the
// mixed-case question name, so the parser hands us label slices that
// point straight at the upstream-chosen bytes.

/// Header + mixed-case question name `X.coM` + qtype/qclass. Returns
/// the offset where the answer RR starts.
fn writeMixedCaseQuestion(buf: []u8, qtype: dns.RType) usize {
    mem.writeInt(u16, buf[0..2], 0x1234, .big);
    mem.writeInt(u16, buf[2..4], 0x8180, .big);
    mem.writeInt(u16, buf[4..6], 1, .big); // qd
    mem.writeInt(u16, buf[6..8], 1, .big); // an
    mem.writeInt(u16, buf[8..10], 0, .big); // ns
    mem.writeInt(u16, buf[10..12], 0, .big); // ar
    @memcpy(buf[12..19], "\x01X\x03coM\x00");
    mem.writeInt(u16, buf[19..21], @backingInt(qtype), .big);
    mem.writeInt(u16, buf[21..23], 1, .big); // class IN
    return 23;
}

/// Answer RR header: owner = pointer to qname at offset 12, then
/// type/class/ttl/rdlength. Returns the RDATA write offset.
fn writeAnswerHeader(buf: []u8, start: usize, rtype: dns.RType, rdlength: u16) usize {
    buf[start] = 0xC0;
    buf[start + 1] = 12;
    mem.writeInt(u16, buf[start + 2 ..][0..2], @backingInt(rtype), .big);
    mem.writeInt(u16, buf[start + 4 ..][0..2], 1, .big); // class IN
    mem.writeInt(u32, buf[start + 6 ..][0..4], 300, .big); // ttl
    mem.writeInt(u16, buf[start + 10 ..][0..2], rdlength, .big);
    return start + 12;
}

test "tryParseMessage lowercases CNAME RDATA name via compression pointer" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [64]u8 = undefined;
    var pos = writeMixedCaseQuestion(&buf, .cname);
    pos = writeAnswerHeader(&buf, pos, .cname, 2);
    buf[pos] = 0xC0;
    buf[pos + 1] = 12;
    pos += 2;

    const server = na.initIp4(.{ 127, 0, 0, 1 }, 53);
    const msg = (try tryParseMessage(arena.allocator(), buf[0..pos], server)) orelse return error.TestUnexpectedResult;

    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    const cname = msg.answers[0].rdata.cname;
    try testing.expectEqual(@as(usize, 2), cname.labels.len);
    try testing.expectEqualStrings("x", cname.labels[0]);
    try testing.expectEqualStrings("com", cname.labels[1]);
}

test "tryParseMessage lowercases SOA mname AND rname via compression pointers" {
    // Dual-name arm — catches a fix that scrubs mname but forgets rname.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [64]u8 = undefined;
    var pos = writeMixedCaseQuestion(&buf, .soa);
    pos = writeAnswerHeader(&buf, pos, .soa, 24);
    // mname = ptr to qname, rname = ptr to qname, then 5 u32s.
    buf[pos] = 0xC0;
    buf[pos + 1] = 12;
    buf[pos + 2] = 0xC0;
    buf[pos + 3] = 12;
    mem.writeInt(u32, buf[pos + 4 ..][0..4], 1, .big); // serial
    mem.writeInt(u32, buf[pos + 8 ..][0..4], 3600, .big); // refresh
    mem.writeInt(u32, buf[pos + 12 ..][0..4], 600, .big); // retry
    mem.writeInt(u32, buf[pos + 16 ..][0..4], 86400, .big); // expire
    mem.writeInt(u32, buf[pos + 20 ..][0..4], 3600, .big); // minimum
    pos += 24;

    const server = na.initIp4(.{ 127, 0, 0, 1 }, 53);
    const msg = (try tryParseMessage(arena.allocator(), buf[0..pos], server)) orelse return error.TestUnexpectedResult;

    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    const soa = msg.answers[0].rdata.soa;
    try testing.expectEqualStrings("x", soa.mname.labels[0]);
    try testing.expectEqualStrings("com", soa.mname.labels[1]);
    try testing.expectEqualStrings("x", soa.rname.labels[0]);
    try testing.expectEqualStrings("com", soa.rname.labels[1]);
}

test "tryParseMessage preserves NSEC next_domain_name case via compression pointer" {
    // RFC 6840 §5.1: NSEC RDATA names are NOT case-folded when canonicalizing.
    // This test used to assert the opposite, on the theory that
    // upstream-chosen case leaking to DO=1 clients was the hazard. It is the
    // other way round: those bytes are what the signature covers, so folding
    // them breaks verification here *and* for any client validating the
    // answer we forward. NSEC RDATA rides out of aggressive
    // negative-synthesis answers verbatim via `nsecEntryToRecord`.
    //
    // The compression-pointer shape is the interesting one: the name is not
    // written inline, so preserving case must not degrade into preserving the
    // *pointer* into a wire buffer the message does not own.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [64]u8 = undefined;
    var pos = writeMixedCaseQuestion(&buf, .nsec);
    // rdlength = 2 (next_domain ptr) + 3 (bitmap: window=0, len=1, A-bit)
    pos = writeAnswerHeader(&buf, pos, .nsec, 5);
    buf[pos] = 0xC0;
    buf[pos + 1] = 12;
    buf[pos + 2] = 0; // window 0
    buf[pos + 3] = 1; // bitmap length
    buf[pos + 4] = 0x40; // A (rtype 1) bit
    pos += 5;

    const server = na.initIp4(.{ 127, 0, 0, 1 }, 53);
    const msg = (try tryParseMessage(arena.allocator(), buf[0..pos], server)) orelse return error.TestUnexpectedResult;

    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    const nsec = msg.answers[0].rdata.nsec;
    try testing.expectEqual(@as(usize, 2), nsec.next_domain_name.labels.len);
    // Wire question is `\x01X\x03coM` — both labels keep their case.
    try testing.expectEqualStrings("X", nsec.next_domain_name.labels[0]);
    try testing.expectEqualStrings("coM", nsec.next_domain_name.labels[1]);

    // Owner names ARE folded — only the NSEC RDATA name is exempt. Keeping
    // both assertions in one test is what stops a future "just stop folding"
    // from looking equivalent.
    try testing.expectEqualStrings("x", msg.answers[0].name.labels[0]);

    // And the preserved bytes are the message's own, not a window into `buf`.
    for (nsec.next_domain_name.labels) |label| {
        const inside = @intFromPtr(label.ptr) >= @intFromPtr(&buf) and
            @intFromPtr(label.ptr) < @intFromPtr(&buf) + buf.len;
        try testing.expect(!inside);
    }
}

test "storeWildcardRRsets abandons a wildcard RRset that overflows its collect buffer" {
    // storeWildcardRRsets writes `.secure`, and tryWildcardSynth serves that
    // entry as an AD=1 answer with no TC=1 for the whole TTL. A truncated
    // collect here is therefore the wrong-and-cached shape the store path
    // refuses everywhere else. `dominated` counts RRSIGs too, so a dual-algo
    // A RRset reaches the 16-record buffer at ~14 addresses.
    const alloc = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const aa = arena.allocator();

    const expanded = dns.Name{ .labels = &.{ "host", "example", "com" } };
    const signer = dns.Name{ .labels = &.{ "example", "com" } };

    // n = A records; the covering RRSIG is dominated too, so dominated = n+1.
    for ([_]usize{ 16, 15 }) |n| {
        var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io });
        defer cache.deinit();
        var resolver: RecursiveResolver = .{ .transports = null, .io = testing.io, .cache = &cache };

        const answers = try aa.alloc(dns.ResourceRecord, n + 1);
        for (answers[0..n], 0..) |*r, i| r.* = .{
            .name = expanded,
            .rtype = .a,
            .rclass = .in,
            .ttl = 300,
            .rdata = .{ .a = .{ 192, 0, 2, @intCast(i + 1) } },
        };
        // labels=2 (`*.example.com`) against a 3-label owner marks the answer
        // wildcard-expanded, which is what arms this path at all.
        answers[n] = .{
            .name = expanded,
            .rtype = .rrsig,
            .rclass = .in,
            .ttl = 300,
            .rdata = .{
                .rrsig = .{
                    .type_covered = .a,
                    .algorithm = .ecdsap256sha256,
                    .labels = 2,
                    .original_ttl = 300,
                    .sig_inception = 0,
                    // Live against the real wall clock, which this cache uses:
                    // 0xFFFFFFFF would not do — RFC 1982 serial arithmetic puts
                    // anything more than 2^31 s ahead of now in the *past*.
                    .sig_expiration = epochNowU32() +% 3600,
                    .key_tag = 1,
                    .signer_name = signer,
                    .signature = &.{},
                },
            },
        };

        resolver.storeWildcardRRsets(answers, .a, std.math.maxInt(u32));

        var look = std.heap.ArenaAllocator.init(alloc);
        defer look.deinit();
        const got = cache.lookup(look.allocator(), "*.example.com", .a, .in);
        if (n + 1 > 16) {
            try testing.expect(got == null);
        } else {
            // 16 dominated exactly fills the buffer: a complete collect, and
            // the boundary is off-by-one sensitive.
            try testing.expect(got != null);
        }
    }
}

test "storeWildcardRRsets bounds the synthesized entry by the validator's ttl cap" {
    // The wildcard entry is `.secure` proof-derived material; caching it past
    // the signatures that verified the expansion would let aggressive
    // synthesis serve AD=1 answers from a dead proof.
    const alloc = testing.allocator;
    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io });
    defer cache.deinit();
    var resolver: RecursiveResolver = .{ .transports = null, .io = testing.io, .cache = &cache };

    const expanded = dns.Name{ .labels = &.{ "host", "example", "com" } };
    const signer = dns.Name{ .labels = &.{ "example", "com" } };
    const answers = [_]dns.ResourceRecord{
        .{ .name = expanded, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 192, 0, 2, 1 } } },
        .{ .name = expanded, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = .{
            .type_covered = .a,
            .algorithm = .ecdsap256sha256,
            .labels = 2,
            .original_ttl = 300,
            .sig_inception = 0,
            .sig_expiration = epochNowU32() +% 3600,
            .key_tag = 1,
            .signer_name = signer,
            .signature = &.{},
        } } },
    };

    resolver.storeWildcardRRsets(&answers, .a, 7);

    var look = std.heap.ArenaAllocator.init(alloc);
    defer look.deinit();
    const got = cache.lookup(look.allocator(), "*.example.com", .a, .in) orelse return error.TestExpectedHit;
    try testing.expect(got.hit.remaining_ttl <= 7);
}

test "cacheInsecureDelegation bounds the negative DS by the proof's ttl cap" {
    // An insecure-delegation verdict rests on a verified proof (no-DS NSEC or
    // a parent-signed unsupported-algorithm DS RRset); it must not outlive it.
    const alloc = testing.allocator;
    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io });
    defer cache.deinit();

    const zone = dns.Name{ .labels = &.{ "example", "com" } };
    const authorities = [_]dns.ResourceRecord{
        .{ .name = zone, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{
            .next_domain_name = dns.Name{ .labels = &.{ "z", "example", "com" } },
            .type_bit_maps = &.{},
        } } },
    };

    cacheInsecureDelegation(&cache, .insecure, zone, &authorities, 7);

    var look = std.heap.ArenaAllocator.init(alloc);
    defer look.deinit();
    var zone_buf: [dns.max_name_len + 1]u8 = undefined;
    const got = cache.lookup(look.allocator(), zone.formatInto(&zone_buf), .ds, .in) orelse return error.TestExpectedHit;
    try testing.expect(got.negative.remaining_ttl <= 7);
}
