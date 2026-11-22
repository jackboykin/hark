//! A share of hark's memory: what is held of it, and the most that may be.
held: usize = 0,
limit: usize = std.math.maxInt(usize),

const std = @import("std");
const Share = @This();

pub fn crowded(s: *const Share, num: usize, den: usize) bool {
    return @as(u128, s.held) * den >= @as(u128, s.limit) * num;
}

pub fn atDoor(s: *const Share) bool {
    return s.crowded(7, 8);
}

pub fn room(s: *const Share, n: usize) bool {
    return s.held + n <= s.limit;
}
