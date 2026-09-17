/// Draws from the calling thread's ChaCha CSPRNG, so `thread` copies across
/// threads. Not `io.random`: its global mutex on threads Io.Threaded didn't
/// spawn cost ~6% CPU on misses.
const std = @import("std");
const linux = std.os.linux;

threadlocal var csprng: ?std.Random.DefaultCsprng = null;

pub const thread: std.Random = .{ .ptr = undefined, .fillFn = fill };

fn fill(_: *anyopaque, buf: []u8) void {
    if (csprng == null) {
        @branchHint(.unlikely);
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        // With signals blocked, only a missing entropy source reads short;
        // guessable TXIDs are worse than no resolver.
        if (linux.getrandom(&seed, seed.len, 0) != seed.len) @panic("getrandom failed");
        csprng = .init(seed);
    }
    csprng.?.fill(buf);
}

test "thread draws differ across threads" {
    const T = struct {
        fn draw(out: *u64) void {
            out.* = thread.int(u64);
        }
    };
    var a: u64 = 0;
    var b: u64 = 0;
    const t = try std.Thread.spawn(.{}, T.draw, .{&a});
    T.draw(&b);
    t.join();
    try std.testing.expect(a != b);
}
