//! A byte stream of DNS messages, each behind its two-byte length (RFC 1035
//! §4.2.2): what has arrived of the next one, and what is owed to a peer
//! that may not be reading.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Allocator = std.mem.Allocator;

pub const max_frame = 2 + @as(usize, std.math.maxInt(u16));

pub fn framed(bytes: []u8) ?[]u8 {
    if (bytes.len < 2) return null;
    const len = std.mem.readInt(u16, bytes[0..2], .big);
    return if (bytes.len < 2 + @as(usize, len)) null else bytes[2..][0..len];
}

const Read = union(enum) {
    bytes: []u8,
    ended,
    wait,
    failed: linux.E,
};

pub const Held = struct {
    bytes: []u8 = &.{},

    /// Reads into `buf` behind a copy of what was held and gives back both.
    /// What of them is left unread must be kept again.
    pub fn read(h: *Held, gpa: Allocator, fd: posix.fd_t, buf: []u8) Read {
        const held = h.bytes.len;
        const rc = linux.read(fd, buf[held..].ptr, buf.len - held);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc == 0) return .ended,
            .AGAIN, .INTR => return .wait,
            else => |err| return .{ .failed = err },
        }
        @memcpy(buf[0..held], h.bytes);
        h.deinit(gpa);
        return .{ .bytes = buf[0 .. held + rc] };
    }

    /// `rest` may lie in what is held.
    pub fn keep(h: *Held, gpa: Allocator, rest: []const u8) !void {
        const kept = try gpa.dupe(u8, rest);
        h.deinit(gpa);
        h.bytes = kept;
    }

    pub fn deinit(h: *Held, gpa: Allocator) void {
        gpa.free(h.bytes);
        h.bytes = &.{};
    }
};

const Put = union(enum) {
    /// Nothing new to wait for: all of it was written, or it waits behind
    /// bytes already waiting for room.
    done,
    /// The first bytes owed: wait for room.
    began,
    failed: linux.E,
};

const Flush = union(enum) { owing, drained, failed: linux.E };

pub const Unsent = struct {
    bytes: std.ArrayList(u8) = .empty,

    /// No put is larger than a frame, so a put is refused only once a whole
    /// frame already waits on a peer that is not reading.
    const cap = 2 * max_frame;

    pub fn owing(u: *const Unsent) bool {
        return u.bytes.items.len != 0;
    }

    /// error.Unread: the peer is owed past the cap. The stream's bytes are then
    /// no longer whole, as after any error, so the stream must end.
    pub fn put(u: *Unsent, gpa: Allocator, fd: posix.fd_t, bytes: []const u8) error{ OutOfMemory, Unread }!Put {
        std.debug.assert(bytes.len <= max_frame);
        const began = !u.owing();
        var rest = bytes;
        if (began) rest = rest[switch (write(fd, rest)) {
            .took => |n| n,
            .failed => |err| return .{ .failed = err },
        }..];
        if (rest.len == 0) return .done;
        if (u.bytes.items.len + rest.len > cap) return error.Unread;
        try u.bytes.appendSlice(gpa, rest);
        return if (began) .began else .done;
    }

    pub fn flush(u: *Unsent, gpa: Allocator, fd: posix.fd_t) Flush {
        switch (write(fd, u.bytes.items)) {
            .took => |n| u.bytes.replaceRangeAssumeCapacity(0, n, &.{}),
            .failed => |err| return .{ .failed = err },
        }
        if (u.owing()) return .owing;
        u.deinit(gpa);
        return .drained;
    }

    pub fn deinit(u: *Unsent, gpa: Allocator) void {
        u.bytes.clearAndFree(gpa);
    }
};

fn write(fd: posix.fd_t, bytes: []const u8) union(enum) { took: usize, failed: linux.E } {
    const rc = linux.write(fd, bytes.ptr, bytes.len);
    return switch (linux.errno(rc)) {
        .SUCCESS => .{ .took = rc },
        .AGAIN, .INTR => .{ .took = 0 },
        else => |err| .{ .failed = err },
    };
}

test "a peer that stops reading is owed no more than the cap" {
    var pair: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0, &pair)) != .SUCCESS) return error.SocketPairFailed;
    defer for (pair) |fd| {
        _ = linux.close(fd);
    };
    var u: Unsent = .{};
    defer u.deinit(std.testing.allocator);
    const frame: [max_frame]u8 = @splat(0);
    for (0..64) |_| {
        const put = u.put(std.testing.allocator, pair[0], &frame) catch |err| {
            try std.testing.expectEqual(error.Unread, err);
            break;
        };
        try std.testing.expect(put != .failed);
    } else return error.TestUnexpectedResult;
    try std.testing.expect(u.bytes.items.len <= Unsent.cap);
}
