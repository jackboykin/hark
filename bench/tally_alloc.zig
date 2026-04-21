//! Pass-through allocator that counts every alloc call and total bytes
//! requested. Unlike CountingAllocator (which tracks the underlying page
//! churn), TallyAllocator counts what the caller asked for — so it works
//! correctly even when the inner allocator is a retained arena that serves
//! requests from pre-allocated capacity.

const std = @import("std");

pub const TallyAllocator = struct {
    inner: std.mem.Allocator,
    bytes: u64 = 0,
    calls: u64 = 0,

    pub fn init(inner: std.mem.Allocator) TallyAllocator {
        return .{ .inner = inner };
    }

    pub fn reset(self: *TallyAllocator) void {
        self.bytes = 0;
        self.calls = 0;
    }

    pub fn allocator(self: *TallyAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *TallyAllocator = @ptrCast(@alignCast(ctx));
        const result = self.inner.rawAlloc(len, alignment, ret_addr);
        if (result != null) {
            self.bytes += len;
            self.calls += 1;
        }
        return result;
    }

    fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *TallyAllocator = @ptrCast(@alignCast(ctx));
        return self.inner.rawResize(buf, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *TallyAllocator = @ptrCast(@alignCast(ctx));
        return self.inner.rawRemap(buf, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *TallyAllocator = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(buf, alignment, ret_addr);
    }
};
