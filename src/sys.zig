//! What hark asks of the OS: sockets, the clocks and entropy. Syscall
//! wrappers come from the per-OS file and are re-exported, so the list below
//! is what a new platform has to provide. Addresses convert to and from
//! sockaddr here.
const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const posix = std.posix;
const mem = std.mem;
const na = @import("net_address.zig");

const os = switch (builtin.os.tag) {
    .linux => @import("sys_linux.zig"),
    else => @compileError("no sys backend for " ++ @tagName(builtin.os.tag)),
};

pub const socket = os.socket;
pub const bind = os.bind;
pub const connect = os.connect;
pub const detach = os.detach;
pub const close = os.close;
pub const listen = os.listen;
pub const sendto = os.sendto;
pub const write = os.write;
pub const writeNoWait = os.writeNoWait;

pub const PosixAddress = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
};

pub fn toSockaddr(addr: *const na.Address, storage: *PosixAddress) posix.socklen_t {
    return switch (addr.*) {
        .ip4 => |ip4| {
            storage.in = .{
                .port = mem.nativeToBig(u16, ip4.port),
                .addr = @bitCast(ip4.bytes),
            };
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |ip6| {
            storage.in6 = .{
                .port = mem.nativeToBig(u16, ip6.port),
                .flowinfo = ip6.flow,
                .addr = ip6.bytes,
                .scope_id = ip6.interface.index,
            };
            return @sizeOf(posix.sockaddr.in6);
        },
    };
}

pub fn fromSockaddr(sa: *const PosixAddress) na.Address {
    return switch (sa.any.family) {
        posix.AF.INET => .{ .ip4 = .{
            .port = mem.bigToNative(u16, sa.in.port),
            .bytes = @bitCast(sa.in.addr),
        } },
        posix.AF.INET6 => .{ .ip6 = .{
            .port = mem.bigToNative(u16, sa.in6.port),
            .bytes = sa.in6.addr,
            .flow = sa.in6.flowinfo,
            .interface = .{ .index = sa.in6.scope_id },
        } },
        else => unreachable,
    };
}

pub fn afU32(addr: na.Address) u32 {
    return switch (addr) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
}

pub fn connectTo(fd: posix.fd_t, addr: *const na.Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try connect(fd, &storage.any, sa_len);
}

pub fn bindTo(fd: posix.fd_t, addr: *const na.Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try bind(fd, &storage.any, sa_len);
}

var test_offset_secs: i64 = 0;

inline fn testOffsetSec() i64 {
    return if (build_options.testing_enabled) test_offset_secs else 0;
}

pub fn advanceTestClock(secs: i64) void {
    if (build_options.testing_enabled) test_offset_secs += secs;
}

/// Boot time for ages and deadlines, wall time for signature windows (RFC
/// 4034 §3.1.5) and log stamps. Both run ahead under -Dtesting by an offset
/// the live harness advances.
pub fn nowNs() i64 {
    const ts = os.uptime();
    return (ts.sec + testOffsetSec()) * std.time.ns_per_s + ts.nsec;
}

pub fn wallclockSec() i64 {
    return os.wallclock().sec + testOffsetSec();
}

threadlocal var csprng: ?std.Random.DefaultCsprng = null;

/// Per-thread, not `io.random`: its global mutex costs ~6% CPU on misses.
pub const random: std.Random = .{ .ptr = undefined, .fillFn = fill };

fn fill(_: *anyopaque, buf: []u8) void {
    if (csprng == null) {
        @branchHint(.unlikely);
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        // No fallback seed: guessable TXIDs are worse than no resolver.
        os.entropy(&seed);
        csprng = .init(seed);
    }
    csprng.?.fill(buf);
}

test "random draws differ across threads" {
    const T = struct {
        fn draw(out: *u64) void {
            out.* = random.int(u64);
        }
    };
    var a: u64 = 0;
    var b: u64 = 0;
    const t = try std.Thread.spawn(.{}, T.draw, .{&a});
    T.draw(&b);
    t.join();
    try std.testing.expect(a != b);
}
