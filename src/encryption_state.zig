const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const AddressKey = @import("connection_pool.zig").AddressKey;

// ── RFC 9539 §4.3 Constants ─────────────────────────────────────────

/// How long a successful encryption probe remains valid.
const persistence_sec: i64 = 3 * 24 * 3600; // 3 days

/// After a failure, wait this long before re-probing.
const damping_sec: i64 = 1 * 24 * 3600; // 1 day

/// TCP+TLS connect timeout for opportunistic probes.
pub const opportunistic_timeout_ms: u32 = 4000; // 4 seconds

/// Short timeout for probing unknown servers (fast RST / connect fail).
pub const probe_timeout_ms: u32 = 500;

// ── Per-IP Encryption State ─────────────────────────────────────────

pub const EncryptionStatus = enum {
    /// Never probed — will attempt encrypted on next query.
    unknown,
    /// Last probe succeeded.
    success,
    /// Last probe failed (non-timeout).
    failed,
    /// Last probe timed out.
    timeout,
};

pub const EncryptionState = struct {
    status: EncryptionStatus = .unknown,
    last_success: i64 = 0,
    last_failure: i64 = 0,
};

// ── Encryption State Cache ──────────────────────────────────────────

pub const EncryptionStateCache = struct {
    entries: std.AutoHashMap(AddressKey, EncryptionState),
    now_fn: *const fn () i64 = &defaultNow,

    pub fn init(allocator: Allocator) EncryptionStateCache {
        return .{
            .entries = std.AutoHashMap(AddressKey, EncryptionState).init(allocator),
        };
    }

    pub fn deinit(self: *EncryptionStateCache) void {
        self.entries.deinit();
    }

    /// Return the current encryption status for a server without side effects.
    /// Used to select probe timeout: unknown → short probe, success → full timeout.
    pub fn getStatus(self: *EncryptionStateCache, key: AddressKey) EncryptionStatus {
        const state = self.entries.get(key) orelse return .unknown;
        const now = self.now_fn();
        return switch (state.status) {
            .success => if (now - state.last_success < persistence_sec) .success else .unknown,
            .failed, .timeout => if (now - state.last_failure < damping_sec) state.status else .unknown,
            .unknown => .unknown,
        };
    }

    /// RFC 9539 §4.6: Decide whether to attempt encrypted transport.
    pub fn shouldAttemptEncrypted(self: *EncryptionStateCache, key: AddressKey) bool {
        const state = self.entries.get(key) orelse return true; // unknown → probe
        const now = self.now_fn();

        return switch (state.status) {
            .unknown => true,
            .success => now - state.last_success < persistence_sec,
            .failed, .timeout => now - state.last_failure >= damping_sec,
        };
    }

    /// Record a successful encrypted connection to this address.
    pub fn recordSuccess(self: *EncryptionStateCache, key: AddressKey) void {
        const now = self.now_fn();
        self.entries.put(key, .{
            .status = .success,
            .last_success = now,
            .last_failure = 0,
        }) catch {};
    }

    /// Record a failed encrypted connection attempt.
    pub fn recordFailure(self: *EncryptionStateCache, key: AddressKey, was_timeout: bool) void {
        const now = self.now_fn();
        // Preserve last_success if we had one
        const existing = self.entries.get(key);
        self.entries.put(key, .{
            .status = if (was_timeout) .timeout else .failed,
            .last_success = if (existing) |e| e.last_success else 0,
            .last_failure = now,
        }) catch {};
    }

    fn defaultNow() i64 {
        return std.time.timestamp();
    }
};

// ── Tests ────────────────────────────────────────────────────────────

const net = std.net;
const posix = std.posix;

fn makeKey(ip: [4]u8) AddressKey {
    return AddressKey.fromAddress(net.Address.initIp4(ip, 853));
}

test "EncryptionStateCache unknown address returns true" {
    var cache = EncryptionStateCache.init(testing.allocator);
    defer cache.deinit();

    try testing.expect(cache.shouldAttemptEncrypted(makeKey(.{ 1, 1, 1, 1 })));
}

test "EncryptionStateCache success within persistence window" {
    var fake_time: i64 = 100_000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var cache = EncryptionStateCache.init(testing.allocator);
    cache.now_fn = &now_fn.now;
    defer cache.deinit();

    const key = makeKey(.{ 1, 1, 1, 1 });
    cache.recordSuccess(key);

    // Within persistence window (3 days) — should attempt
    fake_time = 100_000 + persistence_sec - 1;
    try testing.expect(cache.shouldAttemptEncrypted(key));

    // Past persistence window — should not attempt
    fake_time = 100_000 + persistence_sec + 1;
    try testing.expect(!cache.shouldAttemptEncrypted(key));
}

test "EncryptionStateCache failure with damping" {
    var fake_time: i64 = 100_000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var cache = EncryptionStateCache.init(testing.allocator);
    cache.now_fn = &now_fn.now;
    defer cache.deinit();

    const key = makeKey(.{ 8, 8, 8, 8 });
    cache.recordFailure(key, false);

    // Within damping window (1 day) — should NOT attempt
    fake_time = 100_000 + damping_sec - 1;
    try testing.expect(!cache.shouldAttemptEncrypted(key));

    // Past damping window — should attempt (re-probe)
    fake_time = 100_000 + damping_sec + 1;
    try testing.expect(cache.shouldAttemptEncrypted(key));
}

test "EncryptionStateCache timeout with damping" {
    var fake_time: i64 = 100_000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var cache = EncryptionStateCache.init(testing.allocator);
    cache.now_fn = &now_fn.now;
    defer cache.deinit();

    const key = makeKey(.{ 9, 9, 9, 9 });
    cache.recordFailure(key, true); // timeout

    // Within damping — no
    fake_time = 100_000 + damping_sec - 1;
    try testing.expect(!cache.shouldAttemptEncrypted(key));

    // Past damping — re-probe
    fake_time = 100_000 + damping_sec + 1;
    try testing.expect(cache.shouldAttemptEncrypted(key));
}

test "EncryptionStateCache success after failure preserves state" {
    var fake_time: i64 = 100_000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var cache = EncryptionStateCache.init(testing.allocator);
    cache.now_fn = &now_fn.now;
    defer cache.deinit();

    const key = makeKey(.{ 1, 0, 0, 1 });

    // Fail first
    cache.recordFailure(key, false);
    fake_time = 100_000 + 100;

    // Then succeed
    cache.recordSuccess(key);

    // Should be in success state
    fake_time = 100_000 + 200;
    try testing.expect(cache.shouldAttemptEncrypted(key));
}
