//! RFC 9539 §4.5 per-server state and the DoT session pool.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const na = @import("net_address.zig");
const AddressKey = na.AddressKey;
const monotonic = @import("monotonic.zig");
const tls_transport = @import("tls_transport.zig");
const BumpGatedGroup = @import("bg_group.zig");
const log = std.log.scoped(.encrypted_ns);

/// RFC 9539 §4.3 defaults.
const persistence_sec: i64 = 3 * 24 * 3600;
const damping_max_sec: i64 = 24 * 3600;
const dial_timeout_ns: i128 = 4 * std.time.ns_per_s;
const damping_base_sec: i64 = 60;
/// Outlives the dial timeout.
const probe_timeout_sec: i64 = 30;
const max_entries: usize = 8192;
pub const max_probes: u32 = 8;
const probe_width: usize = 3;

pub const Status = enum { unknown, capable, damped };

const Entry = struct {
    until: i64 = 0,
    capable: bool = false,
    damp_sec: i64 = 0,

    fn status(e: Entry, now: i64) Status {
        if (now >= e.until) return .unknown;
        return if (e.capable) .capable else .damped;
    }
};

pub const EncryptedNs = struct {
    entries: std.AutoHashMap(AddressKey, Entry),
    mutex: Io.Mutex = .init,
    pool: tls_transport.Pool,
    probes: BumpGatedGroup = .init(max_probes),
    now_fn: *const fn () i64 = &monotonic.nowSec,
    dot_answers: std.atomic.Value(u64) = .init(0),
    do53_answers: std.atomic.Value(u64) = .init(0),
    evictions: u64 = 0,

    pub fn init(allocator: Allocator, io: Io, idle_sec: i64) EncryptedNs {
        var pool = tls_transport.Pool.init(allocator, io);
        pool.max_idle_sec = idle_sec;
        return .{ .entries = .init(allocator), .pool = pool };
    }

    pub fn deinit(self: *EncryptedNs) void {
        self.probes.awaitAll(self.pool.io);
        self.pool.deinit();
        self.entries.deinit();
    }

    pub fn getStatus(self: *EncryptedNs, server: na.Address) Status {
        self.mutex.lockUncancelable(self.pool.io);
        defer self.mutex.unlock(self.pool.io);
        const e = self.entries.get(AddressKey.fromAddress(server)) orelse return .unknown;
        return e.status(self.now_fn());
    }

    /// Probe the first `probe_width` unknown servers in rank `order`; known
    /// ones spend no slot, so a winner pinned at rank 0 can't starve the rest.
    pub fn discover(self: *EncryptedNs, servers: []const na.Address, order: []const usize) void {
        var left: usize = probe_width;
        for (order) |idx| {
            if (left == 0) return;
            left -= @intFromBool(self.discoverOne(servers[idx]));
        }
    }

    fn discoverOne(self: *EncryptedNs, server: na.Address) bool {
        if (!self.probes.tryClaim()) return false;
        if (!self.claim(AddressKey.fromAddress(server))) {
            self.probes.release();
            return false;
        }
        // A failed spawn leaves the claim to expire.
        self.probes.spawn(self.pool.io, probe, .{ self, server }) catch self.probes.release();
        return true;
    }

    fn claim(self: *EncryptedNs, key: AddressKey) bool {
        self.mutex.lockUncancelable(self.pool.io);
        defer self.mutex.unlock(self.pool.io);
        const now = self.now_fn();
        const e = self.slot(key, now) orelse return false;
        if (e.status(now) != .unknown) return false;
        e.* = .{ .until = now + probe_timeout_sec, .damp_sec = e.damp_sec };
        return true;
    }

    pub const Outcome = enum { answered, handshake, failed };

    pub fn record(self: *EncryptedNs, server: na.Address, outcome: Outcome) void {
        self.mutex.lockUncancelable(self.pool.io);
        defer self.mutex.unlock(self.pool.io);
        const now = self.now_fn();
        const e = self.slot(AddressKey.fromAddress(server), now) orelse return;
        if (outcome == .failed) {
            const damp = @min(@max(e.damp_sec * 2, damping_base_sec), damping_max_sec);
            e.* = .{ .until = now + damp, .damp_sec = damp };
            return;
        }
        // Only an answer clears the backoff: a handshake can front a dead backend.
        const damp = if (outcome == .answered) 0 else e.damp_sec;
        e.* = .{ .until = now + persistence_sec, .capable = true, .damp_sec = damp };
    }

    fn slot(self: *EncryptedNs, key: AddressKey, now: i64) ?*Entry {
        if (self.entries.getPtr(key)) |e| return e;
        if (self.entries.count() >= max_entries) self.evictOne(now);
        const gop = self.entries.getOrPut(key) catch return null;
        gop.value_ptr.* = .{};
        return gop.value_ptr;
    }

    fn evictOne(self: *EncryptedNs, now: i64) void {
        var victim: ?AddressKey = null;
        var victim_capable = true;
        var victim_until: i64 = std.math.maxInt(i64);
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const capable = kv.value_ptr.status(now) == .capable;
            const until = kv.value_ptr.until;
            if (victim == null or (victim_capable and !capable) or (victim_capable == capable and until < victim_until)) {
                victim = kv.key_ptr.*;
                victim_capable = capable;
                victim_until = until;
            }
        }
        if (victim) |k| _ = self.entries.remove(k);
        self.evictions += 1;
    }

    pub const Stats = struct { dot_answers: u64, do53_answers: u64, capable: u32, evictions: u64 };

    pub fn getStats(self: *EncryptedNs) Stats {
        self.mutex.lockUncancelable(self.pool.io);
        defer self.mutex.unlock(self.pool.io);
        const now = self.now_fn();
        var capable: u32 = 0;
        var it = self.entries.valueIterator();
        while (it.next()) |e| capable += @intFromBool(e.status(now) == .capable);
        return .{
            .dot_answers = self.dot_answers.load(.monotonic),
            .do53_answers = self.do53_answers.load(.monotonic),
            .capable = capable,
            .evictions = self.evictions,
        };
    }

    fn probe(self: *EncryptedNs, server: na.Address) void {
        defer self.probes.release();
        const conn = tls_transport.dial(&self.pool, server, monotonic.nowNs() + dial_timeout_ns) catch
            return self.record(server, .failed);
        self.pool.release(AddressKey.fromAddress(server), conn, true);
        self.record(server, .handshake);
        var buf: [64]u8 = undefined;
        log.info("server {s} supports DoT (RFC 9539)", .{na.format(tls_transport.tlsAddress(server), &buf)});
    }
};

var en_test_now: i64 = 100_000;
fn enTestNow() i64 {
    return en_test_now;
}

fn testNs() EncryptedNs {
    en_test_now = 100_000;
    var ns = EncryptedNs.init(testing.allocator, testing.io, 30);
    ns.now_fn = &enTestNow;
    return ns;
}

const srv = na.initIp4(.{ 192, 0, 2, 1 }, 53);

test "capable persists then expires to unknown" {
    var ns = testNs();
    defer ns.deinit();
    try testing.expectEqual(Status.unknown, ns.getStatus(srv));
    ns.record(srv, .answered);
    try testing.expectEqual(Status.capable, ns.getStatus(srv));
    en_test_now += persistence_sec - 1;
    try testing.expectEqual(Status.capable, ns.getStatus(srv));
    en_test_now += 1;
    try testing.expectEqual(Status.unknown, ns.getStatus(srv));
}

test "failures damp with doubling backoff, capped; success resets" {
    var ns = testNs();
    defer ns.deinit();
    var expect = damping_base_sec;
    for (0..12) |_| {
        ns.record(srv, .failed);
        try testing.expectEqual(Status.damped, ns.getStatus(srv));
        en_test_now += @min(expect, damping_max_sec) - 1;
        try testing.expectEqual(Status.damped, ns.getStatus(srv));
        en_test_now += 1;
        try testing.expectEqual(Status.unknown, ns.getStatus(srv));
        expect *= 2;
    }
    ns.record(srv, .answered);
    ns.record(srv, .failed);
    en_test_now += damping_base_sec;
    try testing.expectEqual(Status.unknown, ns.getStatus(srv));
}

test "a handshake alone keeps the backoff" {
    var ns = testNs();
    defer ns.deinit();
    ns.record(srv, .failed);
    ns.record(srv, .handshake);
    try testing.expectEqual(Status.capable, ns.getStatus(srv));
    ns.record(srv, .failed);
    en_test_now += 2 * damping_base_sec - 1;
    try testing.expectEqual(Status.damped, ns.getStatus(srv));
}

test "claim gates on unknown, expires, and keeps the backoff" {
    var ns = testNs();
    defer ns.deinit();
    const key = AddressKey.fromAddress(srv);
    try testing.expect(ns.claim(key));
    try testing.expectEqual(Status.damped, ns.getStatus(srv));
    try testing.expect(!ns.claim(key));
    en_test_now += probe_timeout_sec;
    try testing.expectEqual(Status.unknown, ns.getStatus(srv));
    ns.record(srv, .failed);
    en_test_now += damping_base_sec;
    try testing.expect(ns.claim(key));
    ns.record(srv, .failed);
    en_test_now += 2 * damping_base_sec - 1;
    try testing.expectEqual(Status.damped, ns.getStatus(srv));
}

test "discover skips known servers down the rank order" {
    var ns = testNs();
    defer ns.deinit();
    // Nothing listens on loopback 853, so the probes fail fast.
    var servers: [5]na.Address = undefined;
    for (&servers, 1..) |*a, i| a.* = na.initIp4(.{ 127, 0, 0, @intCast(i) }, 53);
    ns.record(servers[0], .answered);
    ns.discover(&servers, &.{ 0, 4, 1, 3, 2 });
    for ([_]usize{ 4, 1, 3 }) |i| try testing.expect(ns.getStatus(servers[i]) != .unknown);
    try testing.expectEqual(Status.unknown, ns.getStatus(servers[2]));
}

test "eviction spares capable entries" {
    var ns = testNs();
    defer ns.deinit();
    for (0..max_entries) |i| {
        const s = na.initIp4(.{ 10, 0, @intCast(i >> 8), @intCast(i & 0xff) }, 53);
        ns.record(s, if (i % 2 == 0) .answered else .failed);
    }
    try testing.expectEqual(@as(u32, max_entries / 2), ns.getStats().capable);
    for (0..max_entries / 2) |i| {
        const s = na.initIp4(.{ 10, 1, @intCast(i >> 8), @intCast(i & 0xff) }, 53);
        ns.record(s, .failed);
    }
    try testing.expectEqual(@as(u32, max_entries / 2), ns.getStats().capable);
    try testing.expectEqual(max_entries, ns.entries.count());
}
