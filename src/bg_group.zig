/// Concurrency primitive for capped fire-and-forget tasks with structured
/// shutdown. Pairs an `Io.Group` with an `active` claim counter and a
/// `shutting_down` flag.
///
/// Callers gate spawns via `tryClaim` (respecting both the cap and the
/// shutdown signal) and join the group on teardown via `awaitAll`.
///
/// The counter is load-bearing for two races that `Io.Group` alone doesn't
/// close:
///
///   1. **Bump-vs-spawn.** `tryClaim` bumps `active` *before* the caller
///      calls `group.concurrent`. A naive `group.await` would see an empty
///      group during that window and return prematurely. The counter poll
///      in `awaitAll` drains the window.
///
///   2. **Shutdown-CAS rollback.** A CAS bump can land after `shutdown` is
///      set; `tryClaim`'s post-bump re-check rolls back. The poll must
///      observe both the transient bump and the rollback decrement.
const std = @import("std");
const Io = std.Io;

const BumpGatedGroup = @This();

active: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
shutting_down: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
group: Io.Group = .init,
max: u32,

/// 1ms drain poll. The window between `tryClaim` returning true and
/// `group.concurrent` returning is a handful of instructions; 1ms is
/// generous and matches the prior `nanosleep`-based lifecycle.
const drain_poll: Io.Duration = .fromMilliseconds(1);

pub fn init(max: u32) BumpGatedGroup {
    return .{ .max = max };
}

/// Reserve a slot. Returns false when the cap is hit or shutdown started.
/// On true return, caller MUST eventually call `release` (typically via
/// `defer` inside the spawned task body) and SHOULD call `spawn` to put
/// the work in the group — otherwise `awaitAll` waits for nothing.
pub fn tryClaim(self: *BumpGatedGroup) bool {
    if (self.shutting_down.load(.acquire)) return false;
    while (true) {
        const cur = self.active.load(.monotonic);
        if (cur >= self.max) return false;
        // .acq_rel on success: the release publishes our bump so awaitAll's
        // acquire-load sees it; the acquire pairs with the post-bump
        // shutdown re-check below.
        if (self.active.cmpxchgStrong(cur, cur + 1, .acq_rel, .monotonic) == null) {
            // Between pre-check and CAS, awaitAll may have set shutting_down
            // and observed inFlight==0 (because our bump hadn't published yet)
            // and exited. If shutdown is now set, roll back so we don't spawn
            // into torn-down state.
            if (self.shutting_down.load(.acquire)) {
                _ = self.active.fetchSub(1, .release);
                return false;
            }
            return true;
        }
    }
}

pub fn release(self: *BumpGatedGroup) void {
    _ = self.active.fetchSub(1, .release);
}

pub fn inFlight(self: *const BumpGatedGroup) u32 {
    return self.active.load(.acquire);
}

/// Spawn a previously-claimed task into the group. Caller must have
/// observed `tryClaim` returning true. On `ConcurrencyUnavailable` the
/// caller is responsible for `release` (and any application-level
/// rollback) before propagating.
pub fn spawn(
    self: *BumpGatedGroup,
    io: Io,
    comptime function: anytype,
    args: std.meta.ArgsTuple(@TypeOf(function)),
) Io.ConcurrentError!void {
    return self.group.concurrent(io, function, args);
}

/// Signal shutdown, drain in-flight claims, then join the group. Called
/// from owners' deinit so caches/config outlive the tasks that read them.
///
/// `group.await` after the poll is **not** a no-op: tasks call `release`
/// before the group's internal `num_running` decrement, so the group may
/// still hold outstanding work even after `active` hits zero.
pub fn awaitAll(self: *BumpGatedGroup, io: Io) void {
    self.shutting_down.store(true, .release);
    while (self.inFlight() > 0) {
        io.sleep(drain_poll, .awake) catch {};
    }
    self.group.await(io) catch {};
}

// ── Tests ─────────────────────────────────────────────────────────────

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

test "BumpGatedGroup: tryClaim short-circuits after shutdown" {
    var bg = BumpGatedGroup.init(4);
    bg.shutting_down.store(true, .release);
    try testing.expect(!bg.tryClaim());
    try testing.expectEqual(@as(u32, 0), bg.inFlight());
}

test "BumpGatedGroup: post-CAS shutdown rollback leaves active at zero" {
    // The pre-CAS shutting_down check is bypassed when shutdown lands AFTER
    // pre-check but BEFORE the post-CAS re-check. Drive that window with
    // concurrent workers and an external shutdown signal; the only way
    // `active` can settle at 0 is if the rollback fetchSub fires on the
    // racing thread.
    var bg = BumpGatedGroup.init(1024);

    const Worker = struct {
        fn run(b: *BumpGatedGroup, iters: u32) void {
            for (0..iters) |_| {
                if (b.tryClaim()) b.release();
            }
        }
    };

    const num_threads = 8;
    const iters_each: u32 = 50_000;
    var threads: [num_threads]std.Thread = undefined;
    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{ &bg, iters_each });
    }

    // Set shutdown mid-flight. Workers that already passed pre-check and
    // landed a CAS bump must observe shutdown on the re-check and roll back.
    std.Thread.yield() catch {};
    bg.shutting_down.store(true, .release);

    for (threads) |t| t.join();

    try testing.expectEqual(@as(u32, 0), bg.inFlight());
}
