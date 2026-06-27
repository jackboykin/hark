//! Per-server tracking for QNAME 0x20 case-randomization (RFC draft
//! Vixie/Dagon). Some authoritatives lowercase or otherwise mangle the
//! QNAME they echo, so we mark them and skip 0x20 on retry. In-memory
//! only; restart re-probes everything.

const std = @import("std");
const monotonic = @import("monotonic.zig");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const na = @import("net_address.zig");
const AddressKey = na.AddressKey;

/// How long a non-conformance mark persists before re-probing 0x20.
const reprobe_sec: i64 = 3600;

/// Bound on entries — same magnitude as encrypted_ns and ns_selector.
const max_entries: usize = 4096;

pub const CaseState = struct {
    entries: std.AutoHashMap(AddressKey, i64),
    /// Lock-free fast path for the steady state (no servers ever marked).
    /// Set true on the first markBroken; never cleared.
    has_entries: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    mutex: std.Io.Mutex = std.Io.Mutex.init,
    io: std.Io,
    now_fn: *const fn () i64 = &monotonic.nowSec,

    pub fn init(allocator: Allocator, io: std.Io) CaseState {
        return .{
            .entries = std.AutoHashMap(AddressKey, i64).init(allocator),
            .io = io,
        };
    }

    pub fn deinit(self: *CaseState) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.entries.deinit();
    }

    /// Should we apply 0x20 to queries to this server? True unless we've
    /// recently observed it mangling case.
    pub fn shouldRandomize(self: *CaseState, key: AddressKey) bool {
        if (!self.has_entries.load(.acquire)) return true;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const last_marked = self.entries.get(key) orelse return true;
        return self.now_fn() - last_marked >= reprobe_sec;
    }

    /// Mark a server as case-mangling. Subsequent queries skip 0x20 for
    /// `reprobe_sec` then re-probe.
    pub fn markBroken(self: *CaseState, key: AddressKey) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.entries.count() >= max_entries and !self.entries.contains(key)) {
            self.evictOldest();
        }
        self.entries.put(key, self.now_fn()) catch {};
        self.has_entries.store(true, .release);
    }

    /// Caller must hold mutex.
    fn evictOldest(self: *CaseState) void {
        var oldest_key: ?AddressKey = null;
        var oldest_time: i64 = std.math.maxInt(i64);
        var iter = self.entries.iterator();
        while (iter.next()) |kv| {
            if (kv.value_ptr.* < oldest_time) {
                oldest_time = kv.value_ptr.*;
                oldest_key = kv.key_ptr.*;
            }
        }
        if (oldest_key) |k| _ = self.entries.fetchRemove(k);
    }
};

// ── Tests ─────────────────────────────────────────────────────────────

var test_now: i64 = 0;
fn frozenNow() i64 {
    return test_now;
}

fn makeKey(last: u8) AddressKey {
    return AddressKey.fromAddress(na.initIp4(.{ 192, 0, 2, last }, 53));
}

test "shouldRandomize defaults true" {
    var s = CaseState.init(testing.allocator, testing.io);
    defer s.deinit();
    try testing.expect(s.shouldRandomize(makeKey(1)));
}

test "markBroken disables until TTL" {
    var s = CaseState.init(testing.allocator, testing.io);
    defer s.deinit();
    s.now_fn = &frozenNow;

    test_now = 1000;
    const k = makeKey(2);
    try testing.expect(s.shouldRandomize(k));

    s.markBroken(k);
    try testing.expect(!s.shouldRandomize(k));

    test_now = 1000 + reprobe_sec - 1;
    try testing.expect(!s.shouldRandomize(k));

    test_now = 1000 + reprobe_sec;
    try testing.expect(s.shouldRandomize(k));
}

test "eviction at cap" {
    var s = CaseState.init(testing.allocator, testing.io);
    defer s.deinit();
    s.now_fn = &frozenNow;

    // Fill to capacity
    var i: usize = 0;
    while (i < max_entries) : (i += 1) {
        test_now = @intCast(i);
        const k = AddressKey.fromAddress(na.initIp4(.{
            10,
            @intCast((i >> 16) & 0xff),
            @intCast((i >> 8) & 0xff),
            @intCast(i & 0xff),
        }, 53));
        s.markBroken(k);
    }
    try testing.expectEqual(@as(u32, max_entries), s.entries.count());

    // One more triggers eviction
    test_now = @intCast(max_entries + 1);
    const new_key = AddressKey.fromAddress(na.initIp4(.{ 11, 0, 0, 0 }, 53));
    s.markBroken(new_key);
    try testing.expectEqual(@as(u32, max_entries), s.entries.count());
    try testing.expect(s.entries.contains(new_key));
}
