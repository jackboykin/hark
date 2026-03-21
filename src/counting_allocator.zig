const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Wraps a backing allocator and tracks total bytes allocated.
/// Refuses allocations that would exceed a byte cap.
pub const CountingAllocator = struct {
    backing: Allocator,
    current_bytes: std.atomic.Value(usize),
    max_bytes: usize,

    pub fn init(backing: Allocator, max_bytes: usize) CountingAllocator {
        return .{ .backing = backing, .current_bytes = std.atomic.Value(usize).init(0), .max_bytes = max_bytes };
    }

    pub fn allocator(self: *CountingAllocator) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Allocator.VTable = .{
        .alloc = countingAlloc,
        .resize = countingResize,
        .free = countingFree,
        .remap = countingRemap,
    };

    fn reserveBytes(self: *CountingAllocator, len: usize) bool {
        while (true) {
            const current = self.current_bytes.load(.monotonic);
            const sum, const overflow = @addWithOverflow(current, len);
            if (overflow != 0 or sum > self.max_bytes) return false;
            if (self.current_bytes.cmpxchgWeak(current, sum, .monotonic, .monotonic) == null) return true;
        }
    }

    fn countingAlloc(ctx: *anyopaque, len: usize, alignment: mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (!self.reserveBytes(len)) return null;
        const ptr = self.backing.rawAlloc(len, alignment, ret_addr) orelse {
            _ = self.current_bytes.fetchSub(len, .monotonic);
            return null;
        };
        return ptr;
    }

    fn countingResize(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len) {
            if (!self.reserveBytes(new_len - buf.len)) return false;
            if (!self.backing.rawResize(buf, alignment, new_len, ret_addr)) {
                _ = self.current_bytes.fetchSub(new_len - buf.len, .monotonic);
                return false;
            }
        } else {
            if (!self.backing.rawResize(buf, alignment, new_len, ret_addr)) return false;
            _ = self.current_bytes.fetchSub(buf.len - new_len, .monotonic);
        }
        return true;
    }

    fn countingRemap(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len) {
            if (!self.reserveBytes(new_len - buf.len)) return null;
            const ptr = self.backing.rawRemap(buf, alignment, new_len, ret_addr) orelse {
                _ = self.current_bytes.fetchSub(new_len - buf.len, .monotonic);
                return null;
            };
            return ptr;
        } else {
            const ptr = self.backing.rawRemap(buf, alignment, new_len, ret_addr) orelse return null;
            _ = self.current_bytes.fetchSub(buf.len - new_len, .monotonic);
            return ptr;
        }
    }

    fn countingFree(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        _ = self.current_bytes.fetchSub(buf.len, .monotonic);
        self.backing.rawFree(buf, alignment, ret_addr);
    }
};
