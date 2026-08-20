/// Capped fire-and-forget tasks on an `Io.Group`. `tryClaim` reserves a
/// slot before the spawn; `awaitAll` (test teardown only) polls the claim
/// counter to zero first because a claim precedes its `group.concurrent`,
/// so a bare `group.await` could return inside that window.
const std = @import("std");
const Io = std.Io;

const BumpGatedGroup = @This();

active: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
group: Io.Group = .init,
max: u32,

pub fn init(max: u32) BumpGatedGroup {
    return .{ .max = max };
}

/// On true, caller must eventually `release` (typically a `defer` inside
/// the spawned task body).
pub fn tryClaim(self: *BumpGatedGroup) bool {
    var cur = self.active.load(.monotonic);
    while (cur < self.max) {
        cur = self.active.cmpxchgWeak(cur, cur + 1, .monotonic, .monotonic) orelse return true;
    }
    return false;
}

pub fn release(self: *BumpGatedGroup) void {
    _ = self.active.fetchSub(1, .release);
}

pub fn inFlight(self: *const BumpGatedGroup) u32 {
    return self.active.load(.acquire);
}

/// On `ConcurrencyUnavailable` the caller owns the `release`.
pub fn spawn(
    self: *BumpGatedGroup,
    io: Io,
    comptime function: anytype,
    args: std.meta.ArgsTuple(@TypeOf(function)),
) Io.ConcurrentError!void {
    return self.group.concurrent(io, function, args);
}

/// Tasks `release` before the group's own bookkeeping, so the await after
/// the poll is not a no-op.
pub fn awaitAll(self: *BumpGatedGroup, io: Io) void {
    while (self.inFlight() > 0) {
        io.sleep(.fromMilliseconds(1), .awake) catch {};
    }
    self.group.await(io) catch {};
}

const testing = std.testing;

test "BumpGatedGroup: cap enforcement and release" {
    var bg = BumpGatedGroup.init(4);
    for (0..4) |_| try testing.expect(bg.tryClaim());
    try testing.expect(!bg.tryClaim());
    bg.release();
    try testing.expect(bg.tryClaim());
    for (0..4) |_| bg.release();
    try testing.expectEqual(@as(u32, 0), bg.inFlight());
}
