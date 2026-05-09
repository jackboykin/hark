const std = @import("std");
const monotonic = @import("monotonic.zig");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const na = @import("net_address.zig");
const posix = std.posix;
const AddressKey = na.AddressKey;

/// How long a hard-failed probe is damped (1 hour). Hard failures are
/// definitive signals the server does not speak DoT — TLS handshake
/// rejection, ALPN mismatch, cert validation in strict mode.
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

/// Maximum number of cached entries.
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

const NsEntry = struct {
    status: ServerStatus = .unknown,
    last_probe: i64 = 0,
};

// ── Encrypted NS Cache ────────────────────────────────────────────────

pub const EncryptedNsCache = struct {
    entries: std.AutoHashMap(AddressKey, NsEntry),
    mutex: std.Io.Mutex = std.Io.Mutex.init,
    io: std.Io,
    active_probes: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    shutting_down: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    now_fn: *const fn () i64 = &monotonic.nowSec,

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

    /// Damping period a non-.unknown entry is "live" for.
    fn dampingPeriod(status: ServerStatus) i64 {
        return switch (status) {
            .capable => persistence_sec,
            .probing => probe_timeout_sec,
            .failed => damping_sec,
            .soft_failed => soft_damping_sec,
            .unknown => 0,
        };
    }

    /// Status for `entry` at `now`, decayed to `.unknown` once the damping
    /// period elapses.
    fn effectiveStatus(entry: NsEntry, now: i64) ServerStatus {
        if (entry.status == .unknown) return .unknown;
        if (now - entry.last_probe >= dampingPeriod(entry.status)) return .unknown;
        return entry.status;
    }

    /// Return the current status for a nameserver.
    pub fn getStatus(self: *EncryptedNsCache, key: AddressKey) ServerStatus {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const entry = self.entries.get(key) orelse return .unknown;
        return effectiveStatus(entry, self.now_fn());
    }

    /// Atomically claim a probe slot for `key`. Returns true if this caller
    /// should fire the probe (sets status to .probing). Returns false if
    /// already probing, already capable, or in damping window.
    pub fn claimProbe(self: *EncryptedNsCache, key: AddressKey) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const now = self.now_fn();

        if (self.entries.get(key)) |entry| {
            if (effectiveStatus(entry, now) != .unknown) return false;
        }

        if (self.entries.count() >= max_entries) {
            self.evictOldest();
        }
        self.entries.put(key, .{
            .status = .probing,
            .last_probe = now,
        }) catch return false;

        return true;
    }

    /// Record a probe outcome for `key`. Caller selects the damping band
    /// (.capable persists 3 days; .failed 1 hour; .soft_failed 60 s).
    /// `.probing` is reserved for `claimProbe`'s atomic gate; `.unknown` is
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

    /// Revert a .probing entry to .unknown (probe was never attempted).
    pub fn revertProbing(self: *EncryptedNsCache, key: AddressKey) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.entries.get(key)) |entry| {
            if (entry.status == .probing) {
                _ = self.entries.fetchRemove(key);
            }
        }
    }

    /// Block until all background probes have completed (for shutdown).
    pub fn awaitProbes(self: *EncryptedNsCache) void {
        self.shutting_down.store(true, .seq_cst);
        while (self.active_probes.load(.seq_cst) > 0) {
            const ts = std.os.linux.timespec{ .sec = 0, .nsec = 1_000_000 };
            _ = std.os.linux.nanosleep(&ts, null); // 1ms
        }
    }

    /// Evict the oldest entry when at capacity. Caller must hold mutex.
    fn evictOldest(self: *EncryptedNsCache) void {
        var oldest_key: ?AddressKey = null;
        var oldest_time: i64 = std.math.maxInt(i64);

        var iter = self.entries.iterator();
        while (iter.next()) |kv| {
            if (kv.value_ptr.last_probe < oldest_time) {
                oldest_time = kv.value_ptr.last_probe;
                oldest_key = kv.key_ptr.*;
            }
        }

        if (oldest_key) |k| {
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

test "EncryptedNsCache failed with damping" {
    var fake_time: i64 = 100_000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    cache.now_fn = &now_fn.now;
    defer cache.deinit();

    const key = makeKey(.{ 8, 8, 8, 8 });
    cache.setStatus(key, .failed);

    // Within damping window — should be failed
    fake_time = 100_000 + damping_sec - 1;
    try testing.expectEqual(ServerStatus.failed, cache.getStatus(key));

    // Past damping window — should revert to unknown
    fake_time = 100_000 + damping_sec;
    try testing.expectEqual(ServerStatus.unknown, cache.getStatus(key));
}

test "EncryptedNsCache soft_failed uses shorter damping" {
    var fake_time: i64 = 100_000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    cache.now_fn = &now_fn.now;
    defer cache.deinit();

    const key = makeKey(.{ 8, 8, 4, 4 });
    cache.setStatus(key, .soft_failed);

    // Within soft-damping window — should report soft_failed.
    fake_time = 100_000 + soft_damping_sec - 1;
    try testing.expectEqual(ServerStatus.soft_failed, cache.getStatus(key));

    // Past soft-damping window — reverts to unknown so a retry can fire.
    fake_time = 100_000 + soft_damping_sec;
    try testing.expectEqual(ServerStatus.unknown, cache.getStatus(key));

    // Crucially, the soft window is much shorter than the hard one — a
    // soft-failed entry must not still be damped at the hard threshold.
    fake_time = 100_000 + damping_sec - 1;
    try testing.expectEqual(ServerStatus.unknown, cache.getStatus(key));
}

test "EncryptedNsCache claimProbe dedup" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 9, 9, 9, 9 });

    // First claim succeeds
    try testing.expect(cache.claimProbe(key));
    try testing.expectEqual(ServerStatus.probing, cache.getStatus(key));

    // Second claim for same key fails (dedup)
    try testing.expect(!cache.claimProbe(key));
}

test "EncryptedNsCache claimProbe respects damping" {
    var fake_time: i64 = 100_000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    cache.now_fn = &now_fn.now;
    defer cache.deinit();

    const key = makeKey(.{ 1, 0, 0, 1 });
    cache.setStatus(key, .failed);

    // Within damping — claim should fail
    fake_time = 100_000 + damping_sec - 1;
    try testing.expect(!cache.claimProbe(key));

    // Past damping — claim should succeed
    fake_time = 100_000 + damping_sec;
    try testing.expect(cache.claimProbe(key));
}

test "EncryptedNsCache claimProbe skips capable" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 1, 1, 1, 1 });
    cache.setStatus(key, .capable);

    // Should not re-probe a capable server
    try testing.expect(!cache.claimProbe(key));
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
    var fake_time: i64 = 100_000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    cache.now_fn = &now_fn.now;
    defer cache.deinit();

    const key = makeKey(.{ 1, 1, 1, 1 });
    cache.setStatus(key, .capable);

    // Within persistence window — should be capable
    fake_time = 100_000 + persistence_sec - 1;
    try testing.expectEqual(ServerStatus.capable, cache.getStatus(key));

    // Should not re-probe within window
    try testing.expect(!cache.claimProbe(key));

    // Past persistence window — should revert to unknown
    fake_time = 100_000 + persistence_sec;
    try testing.expectEqual(ServerStatus.unknown, cache.getStatus(key));

    // Should allow re-probing
    try testing.expect(cache.claimProbe(key));
}

test "EncryptedNsCache revertProbing clears probing entry" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 4, 4, 4, 4 });
    try testing.expect(cache.claimProbe(key));
    try testing.expectEqual(ServerStatus.probing, cache.getStatus(key));

    cache.revertProbing(key);
    try testing.expectEqual(ServerStatus.unknown, cache.getStatus(key));
}

test "EncryptedNsCache revertProbing is no-op for capable" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 5, 5, 5, 5 });
    cache.setStatus(key, .capable);

    cache.revertProbing(key);
    try testing.expectEqual(ServerStatus.capable, cache.getStatus(key));
}
