//! A byte stream of DNS messages, each behind its two-byte length (RFC 1035
//! §4.2.2): what has arrived of the next one.

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
