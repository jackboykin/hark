//! The socket surface hark asks of the OS. Syscall wrappers come from the
//! per-OS file and are re-exported, so the list below is what a new platform
//! has to provide.
const builtin = @import("builtin");

const os = switch (builtin.os.tag) {
    .linux => @import("sys_linux.zig"),
    else => @compileError("no sys backend for " ++ @tagName(builtin.os.tag)),
};

pub const socket = os.socket;
pub const bind = os.bind;
pub const connect = os.connect;
pub const close = os.close;
pub const listen = os.listen;
pub const sendto = os.sendto;
pub const getsockname = os.getsockname;
pub const write = os.write;
