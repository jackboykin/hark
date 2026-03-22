const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const na = @import("net_address.zig");
const posix = std.posix;
const AddressKey = @import("connection_pool.zig").AddressKey;

/// How long a failed probe is damped before re-probing (1 hour).
const damping_sec: i64 = 3600;

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
    /// TLS probe failed — damped for `damping_sec`.
    failed,
};

const NsEntry = struct {
    status: ServerStatus = .unknown,
    last_probe: i64 = 0,
    failure_count: u8 = 0,
};

// ── Encrypted NS Cache ────────────────────────────────────────────────

pub const EncryptedNsCache = struct {
    entries: std.AutoHashMap(AddressKey, NsEntry),
    mutex: std.Io.Mutex = std.Io.Mutex.init,
    io: std.Io,
    active_probes: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    shutting_down: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    now_fn: *const fn () i64 = &defaultNow,

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

    /// Return the current status for a nameserver.
    pub fn getStatus(self: *EncryptedNsCache, key: AddressKey) ServerStatus {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const entry = self.entries.get(key) orelse return .unknown;
        return switch (entry.status) {
            .capable => if (self.now_fn() - entry.last_probe >= persistence_sec) .unknown else .capable,
            .probing => if (self.now_fn() - entry.last_probe >= probe_timeout_sec) .unknown else .probing,
            .failed => if (self.now_fn() - entry.last_probe >= damping_sec) .unknown else .failed,
            .unknown => .unknown,
        };
    }

    /// Atomically claim a probe slot for `key`. Returns true if this caller
    /// should fire the probe (sets status to .probing). Returns false if
    /// already probing, already capable, or in damping window.
    pub fn claimProbe(self: *EncryptedNsCache, key: AddressKey) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const now = self.now_fn();

        if (self.entries.get(key)) |entry| {
            switch (entry.status) {
                .capable => if (now - entry.last_probe < persistence_sec) return false,
                .probing => if (now - entry.last_probe < probe_timeout_sec) return false,
                .failed => if (now - entry.last_probe < damping_sec) return false,
                .unknown => {},
            }
        }

        if (self.entries.count() >= max_entries) {
            self.evictOldest();
        }
        self.entries.put(key, .{
            .status = .probing,
            .last_probe = now,
            .failure_count = 0,
        }) catch return false;

        return true;
    }

    /// Mark a server as TLS-capable (probe succeeded).
    pub fn markCapable(self: *EncryptedNsCache, key: AddressKey) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.entries.put(key, .{
            .status = .capable,
            .last_probe = self.now_fn(),
            .failure_count = 0,
        }) catch {};
    }

    /// Mark a server as failed (probe failed). Increments failure_count.
    pub fn markFailed(self: *EncryptedNsCache, key: AddressKey) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const existing = self.entries.get(key);
        const count = if (existing) |e| e.failure_count else 0;
        self.entries.put(key, .{
            .status = .failed,
            .last_probe = self.now_fn(),
            .failure_count = if (count < 255) count + 1 else 255,
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

    fn defaultNow() i64 {
        return @import("monotonic.zig").nowSec();
    }
};

// ── Tests ─────────────────────────────────────────────────────────────

fn makeKey(ip: [4]u8) AddressKey {
    return AddressKey.fromAddress(na.initIp4(ip, 853));
}

test "EncryptedNsCache unknown address returns unknown" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    try testing.expectEqual(ServerStatus.unknown, cache.getStatus(makeKey(.{ 1, 1, 1, 1 })));
}

test "EncryptedNsCache markCapable and getStatus" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 1, 1, 1, 1 });
    cache.markCapable(key);
    try testing.expectEqual(ServerStatus.capable, cache.getStatus(key));
}

test "EncryptedNsCache markFailed with damping" {
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
    cache.markFailed(key);

    // Within damping window — should be failed
    fake_time = 100_000 + damping_sec - 1;
    try testing.expectEqual(ServerStatus.failed, cache.getStatus(key));

    // Past damping window — should revert to unknown
    fake_time = 100_000 + damping_sec;
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
    cache.markFailed(key);

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
    cache.markCapable(key);

    // Should not re-probe a capable server
    try testing.expect(!cache.claimProbe(key));
}

test "EncryptedNsCache failure count increments" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 10, 0, 0, 1 });
    cache.markFailed(key);
    cache.markFailed(key);
    cache.markFailed(key);

    const entry = cache.entries.get(key).?;
    try testing.expectEqual(@as(u8, 3), entry.failure_count);
}

test "EncryptedNsCache capable after failed" {
    var cache = EncryptedNsCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    const key = makeKey(.{ 1, 0, 0, 1 });
    cache.markFailed(key);
    cache.markCapable(key);

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
    cache.markCapable(key);

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
    cache.markCapable(key);

    cache.revertProbing(key);
    try testing.expectEqual(ServerStatus.capable, cache.getStatus(key));
}
