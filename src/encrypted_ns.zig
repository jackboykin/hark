const std = @import("std");
const monotonic = @import("monotonic.zig");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const na = @import("net_address.zig");
const AddressKey = na.AddressKey;
const BumpGatedGroup = @import("bg_group.zig");

/// How long a hard-failed probe is damped (1 hour). Hard failures are
/// definitive signals the server does not speak DoT — TLS handshake
/// rejection or ALPN mismatch.
const damping_sec: i64 = 3600;

/// How long a soft-failed probe is damped (60 s). Soft failures are
/// transient: TCP connect timeout, network unreachable, RST mid-stream.
/// RFC 9539 §4.3 contemplates this distinction so a flaky network blip
/// does not evict a known-capable server from the encrypted path for
/// an hour.
const soft_damping_sec: i64 = 60;

/// How long a .capable result persists before re-probing (3 days, per RFC 9539).
const persistence_sec: i64 = 3 * 24 * 3600;

/// How long a .probing entry is valid before expiring to .unknown (RFC 9539 §4.2).
const probe_timeout_sec: i64 = 30;

const max_entries: usize = 256;

/// Maximum concurrent background probe threads.
pub const max_probes: u32 = 8;

// ── Per-IP Encrypted NS State ────────────────────────────────────────

pub const ServerStatus = enum {
    /// Never probed.
    unknown,
    /// Probe in progress (dedup guard).
    probing,
    /// TLS probe succeeded — server supports encrypted transport.
    capable,
    /// TLS probe failed (hard) — damped for `damping_sec`.
    failed,
    /// TLS probe failed (soft / transient) — damped for `soft_damping_sec`.
    soft_failed,
};

/// `.discover` = first-contact probe (logs capability); `.rewarm` =
/// re-dial for a known-capable server's cold pool (quiet, and a failed
/// claim reverts to .capable, not .unknown).
pub const ProbeKind = enum { discover, rewarm };

const NsEntry = struct {
    status: ServerStatus = .unknown,
    last_probe: i64 = 0,
};

// ── Encrypted NS Cache ────────────────────────────────────────────────

pub const EncryptedNsCache = struct {
    entries: std.AutoHashMap(AddressKey, NsEntry),
    mutex: std.Io.Mutex = std.Io.Mutex.init,
    io: std.Io,
    /// Caps + joins in-flight probes; see `BumpGatedGroup`.
    probes: BumpGatedGroup = .init(max_probes),
    now_fn: *const fn () i64 = &monotonic.nowSec,
    /// Upstream answers by transport (RFC 9539 §8 asks deployments to report
    /// encrypted-egress share). Once per upstream answer — no line worth it.
    dot_answers: std.atomic.Value(u64) = .init(0),
    do53_answers: std.atomic.Value(u64) = .init(0),

    pub fn init(allocator: Allocator, io: std.Io) EncryptedNsCache {
        return .{
            .entries = std.AutoHashMap(AddressKey, NsEntry).init(allocator),
            .io = io,
        };
    }

    pub fn deinit(self: *EncryptedNsCache) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.entries.deinit();
    }

    /// Status for `entry` at `now`, decayed to `.unknown` once the damping
    /// period elapses.
    fn effectiveStatus(entry: NsEntry, now: i64) ServerStatus {
        const damping: i64 = switch (entry.status) {
            .capable => persistence_sec,
            .probing => probe_timeout_sec,
            .failed => damping_sec,
            .soft_failed => soft_damping_sec,
            .unknown => return .unknown,
        };
        if (now - entry.last_probe >= damping) return .unknown;
        return entry.status;
    }

    pub fn getStatus(self: *EncryptedNsCache, key: AddressKey) ServerStatus {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const entry = self.entries.get(key) orelse return .unknown;
        return effectiveStatus(entry, self.now_fn());
    }

    /// Claim the probe slot (status -> .probing; dedups dials and parks
    /// the server out of the encrypted-first scan). `.discover` requires
    /// effective .unknown, `.rewarm` requires .capable. True = caller
    /// fires the dial.
    pub fn claim(self: *EncryptedNsCache, key: AddressKey, kind: ProbeKind) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const now = self.now_fn();

        const existing = self.entries.get(key);
        const current: ServerStatus = if (existing) |entry|
            effectiveStatus(entry, now)
        else
            .unknown;
        const required: ServerStatus = switch (kind) {
            .discover => .unknown,
            .rewarm => .capable,
        };
        if (current != required) return false;

        // Evict only on a genuinely new key: overwrites don't grow the map.
        if (existing == null and self.entries.count() >= max_entries) {
            self.evictOldest(now);
        }
        self.entries.put(key, .{
            .status = .probing,
            .last_probe = now,
        }) catch return false;

        return true;
    }

    /// Record a probe outcome for `key`. Caller selects the damping band
    /// (.capable persists 3 days; .failed 1 hour; .soft_failed 60 s).
    /// `.probing` is reserved for `claim`'s atomic gate; `.unknown` is
    /// implied by absence — callers should not write either.
    pub fn setStatus(self: *EncryptedNsCache, key: AddressKey, status: ServerStatus) void {
        std.debug.assert(status != .unknown and status != .probing);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.entries.put(key, .{
            .status = status,
            .last_probe = self.now_fn(),
        }) catch {};
    }

    /// Roll back a claim whose dial never ran (spawn pressure):
    /// `.discover` forgets the entry, `.rewarm` restores .capable. Known
    /// slack: the restore keeps claim()'s fresh last_probe stamp, renewing
    /// the persistence window without a dial — bounded, a stale .capable
    /// costs one pooled miss.
    pub fn revertClaim(self: *EncryptedNsCache, key: AddressKey, kind: ProbeKind) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const entry = self.entries.getPtr(key) orelse return;
        if (entry.status != .probing) return;
        switch (kind) {
            .discover => _ = self.entries.remove(key),
            .rewarm => entry.status = .capable,
        }
    }

    pub const Stats = struct { dot_answers: u64, do53_answers: u64, capable: u32 };

    /// Snapshot for the stats log: answer counts plus how many servers are
    /// currently effective-.capable.
    pub fn getStats(self: *EncryptedNsCache) Stats {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const now = self.now_fn();
        var capable: u32 = 0;
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (effectiveStatus(kv.value_ptr.*, now) == .capable) capable += 1;
        }
        return .{
            .dot_answers = self.dot_answers.load(.monotonic),
            .do53_answers = self.do53_answers.load(.monotonic),
            .capable = capable,
        };
    }

    pub fn awaitProbes(self: *EncryptedNsCache) void {
        self.probes.awaitAll(self.io);
    }

    /// Evict the oldest non-capable entry when at capacity; only an
    /// all-capable map sacrifices a capable one. Capable entries are the
    /// map's payload — damping junk churns fast under discovery (every
    /// Do53-only candidate claims a slot), and age-only eviction let that
    /// churn erase stable capable servers, forcing a re-discovery dial
    /// each time. Caller must hold mutex.
    fn evictOldest(self: *EncryptedNsCache, now: i64) void {
        var victim: ?AddressKey = null;
        var victim_time: i64 = std.math.maxInt(i64);
        var victim_capable = true;

        var iter = self.entries.iterator();
        while (iter.next()) |kv| {
            const capable = effectiveStatus(kv.value_ptr.*, now) == .capable;
            const prefer = (!capable and victim_capable) or
                (capable == victim_capable and kv.value_ptr.last_probe < victim_time);
            if (prefer) {
                victim_time = kv.value_ptr.last_probe;
                victim = kv.key_ptr.*;
                victim_capable = capable;
            }
        }

        if (victim) |k| {
            _ = self.entries.fetchRemove(k);
        }
    }
};

// ── Tests ─────────────────────────────────────────────────────────────

fn makeKey(ip: [4]u8) AddressKey {
    return AddressKey.fromAddress(na.initIp4(ip, 853));
}

test "EncryptedNsCache setStatus capable, getStatus" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 1, 1, 1, 1 });
    cache.setStatus(key, .capable);
    try testing.expectEqual(ServerStatus.capable, cache.getStatus(key));
}

// Injectable test clock; each test resets it at entry (cf. cache.zig testNowSeconds).
var en_test_now: i64 = 100_000;
fn enTestNow() i64 {
    return en_test_now;
}

test "EncryptedNsCache failed with damping" {
    en_test_now = 100_000;

    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    cache.now_fn = &enTestNow;
    defer cache.deinit();

    const key = makeKey(.{ 8, 8, 8, 8 });
    cache.setStatus(key, .failed);

    // Within damping window — should be failed
    en_test_now = 100_000 + damping_sec - 1;
    try testing.expectEqual(ServerStatus.failed, cache.getStatus(key));

    // Past damping window — should revert to unknown
    en_test_now = 100_000 + damping_sec;
    try testing.expectEqual(ServerStatus.unknown, cache.getStatus(key));
}

test "EncryptedNsCache soft_failed uses shorter damping" {
    en_test_now = 100_000;

    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    cache.now_fn = &enTestNow;
    defer cache.deinit();

    const key = makeKey(.{ 8, 8, 4, 4 });
    cache.setStatus(key, .soft_failed);

    // Within soft-damping window — should report soft_failed.
    en_test_now = 100_000 + soft_damping_sec - 1;
    try testing.expectEqual(ServerStatus.soft_failed, cache.getStatus(key));

    // Past soft-damping window — reverts to unknown so a retry can fire.
    en_test_now = 100_000 + soft_damping_sec;
    try testing.expectEqual(ServerStatus.unknown, cache.getStatus(key));

    // Crucially, the soft window is much shorter than the hard one — a
    // soft-failed entry must not still be damped at the hard threshold.
    en_test_now = 100_000 + damping_sec - 1;
    try testing.expectEqual(ServerStatus.unknown, cache.getStatus(key));
}

test "EncryptedNsCache claim(.discover) dedup" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 9, 9, 9, 9 });

    try testing.expect(cache.claim(key, .discover));
    try testing.expectEqual(ServerStatus.probing, cache.getStatus(key));

    // Second claim for same key fails (dedup)
    try testing.expect(!cache.claim(key, .discover));
}

test "EncryptedNsCache claim(.discover) respects damping" {
    en_test_now = 100_000;

    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    cache.now_fn = &enTestNow;
    defer cache.deinit();

    const key = makeKey(.{ 1, 0, 0, 1 });
    cache.setStatus(key, .failed);

    // Within damping — claim should fail
    en_test_now = 100_000 + damping_sec - 1;
    try testing.expect(!cache.claim(key, .discover));

    // Past damping — claim should succeed
    en_test_now = 100_000 + damping_sec;
    try testing.expect(cache.claim(key, .discover));
}

test "EncryptedNsCache claim(.discover) skips capable" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 1, 1, 1, 1 });
    cache.setStatus(key, .capable);

    // Should not re-probe a capable server
    try testing.expect(!cache.claim(key, .discover));
}

test "EncryptedNsCache capable after failed" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 1, 0, 0, 1 });
    cache.setStatus(key, .failed);
    cache.setStatus(key, .capable);

    try testing.expectEqual(ServerStatus.capable, cache.getStatus(key));
}

test "EncryptedNsCache capable expires after persistence_sec" {
    en_test_now = 100_000;

    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    cache.now_fn = &enTestNow;
    defer cache.deinit();

    const key = makeKey(.{ 1, 1, 1, 1 });
    cache.setStatus(key, .capable);

    // Within persistence window — should be capable
    en_test_now = 100_000 + persistence_sec - 1;
    try testing.expectEqual(ServerStatus.capable, cache.getStatus(key));

    // Should not re-probe within window
    try testing.expect(!cache.claim(key, .discover));

    // Past persistence window — should revert to unknown
    en_test_now = 100_000 + persistence_sec;
    try testing.expectEqual(ServerStatus.unknown, cache.getStatus(key));

    try testing.expect(cache.claim(key, .discover));
}

test "EncryptedNsCache revertClaim(.discover) clears probing entry" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 4, 4, 4, 4 });
    try testing.expect(cache.claim(key, .discover));
    try testing.expectEqual(ServerStatus.probing, cache.getStatus(key));

    cache.revertClaim(key, .discover);
    try testing.expectEqual(ServerStatus.unknown, cache.getStatus(key));
}

test "EncryptedNsCache getStats counts capable and answers" {
    en_test_now = 100_000;
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    cache.now_fn = &enTestNow;

    cache.setStatus(makeKey(.{ 9, 0, 0, 1 }), .capable);
    cache.setStatus(makeKey(.{ 9, 0, 0, 2 }), .capable);
    cache.setStatus(makeKey(.{ 9, 0, 0, 3 }), .failed);
    _ = cache.dot_answers.fetchAdd(3, .monotonic);
    _ = cache.do53_answers.fetchAdd(7, .monotonic);

    var s = cache.getStats();
    try testing.expectEqual(@as(u32, 2), s.capable);
    try testing.expectEqual(@as(u64, 3), s.dot_answers);
    try testing.expectEqual(@as(u64, 7), s.do53_answers);

    // Expired .capable marks drop out of the gauge.
    en_test_now += persistence_sec;
    s = cache.getStats();
    try testing.expectEqual(@as(u32, 0), s.capable);
}

test "EncryptedNsCache claim(.rewarm): capable -> probing, no stampede" {
    en_test_now = 100_000;
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    cache.now_fn = &enTestNow;

    const key = makeKey(.{ 6, 6, 6, 6 });
    // Unknown server: nothing to rewarm.
    try testing.expect(!cache.claim(key, .rewarm));

    cache.setStatus(key, .capable);
    try testing.expect(cache.claim(key, .rewarm));
    try testing.expectEqual(ServerStatus.probing, cache.getStatus(key));
    // Concurrent misses must not fire duplicate dials.
    try testing.expect(!cache.claim(key, .rewarm));

    // Damped statuses are not rewarm-eligible.
    cache.setStatus(key, .soft_failed);
    try testing.expect(!cache.claim(key, .rewarm));

    // A .capable mark past its persistence window is stale — no rewarm.
    cache.setStatus(key, .capable);
    en_test_now += persistence_sec;
    try testing.expect(!cache.claim(key, .rewarm));
}

test "EncryptedNsCache claim on a present key never evicts" {
    en_test_now = 100_000;
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    cache.now_fn = &enTestNow;

    var i: usize = 0;
    while (i < max_entries) : (i += 1) {
        en_test_now += 1;
        cache.setStatus(makeKey(.{ 1, 1, @intCast(i >> 8), @intCast(i & 0xff) }), .capable);
    }
    try testing.expectEqual(max_entries, @as(usize, cache.entries.count()));

    // .rewarm on a present key at capacity: overwrite in place — the
    // oldest (stablest) entry must survive.
    const oldest = makeKey(.{ 1, 1, 0, 0 });
    en_test_now += 1;
    try testing.expect(cache.claim(makeKey(.{ 1, 1, 0, 42 }), .rewarm));
    try testing.expectEqual(max_entries, @as(usize, cache.entries.count()));
    try testing.expectEqual(ServerStatus.capable, cache.getStatus(oldest));

    // .discover on a NEW key at capacity still evicts (bound holds).
    try testing.expect(cache.claim(makeKey(.{ 2, 2, 2, 2 }), .discover));
    try testing.expectEqual(max_entries, @as(usize, cache.entries.count()));
}

test "EncryptedNsCache eviction spares capable entries" {
    en_test_now = 100_000;
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    cache.now_fn = &enTestNow;

    // Capacity − 1 capable entries, oldest stamp first…
    var i: usize = 0;
    while (i < max_entries - 1) : (i += 1) {
        en_test_now += 1;
        cache.setStatus(makeKey(.{ 1, 1, @intCast(i >> 8), @intCast(i & 0xff) }), .capable);
    }
    // …then damping junk carrying the freshest stamp of all.
    en_test_now += 1;
    const junk = makeKey(.{ 2, 2, 2, 2 });
    cache.setStatus(junk, .soft_failed);

    // A new claim at capacity must evict the junk, not the oldest capable.
    en_test_now += 1;
    try testing.expect(cache.claim(makeKey(.{ 3, 3, 3, 3 }), .discover));
    try testing.expectEqual(max_entries, @as(usize, cache.entries.count()));
    try testing.expect(cache.entries.get(junk) == null);
    try testing.expectEqual(ServerStatus.capable, cache.getStatus(makeKey(.{ 1, 1, 0, 0 })));
}

test "EncryptedNsCache revertClaim is no-op for non-probing" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 5, 5, 5, 5 });
    cache.setStatus(key, .capable);

    cache.revertClaim(key, .discover);
    try testing.expectEqual(ServerStatus.capable, cache.getStatus(key));
}
