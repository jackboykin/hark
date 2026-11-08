//! What carries a server's exchanges over an encrypted session: the one
//! interface `Sessions` drives, whichever transport is underneath.
const std = @import("std");
const na = @import("net_address.zig");
const Edge = @import("edge.zig");
const DotSocket = @import("dot_socket.zig");

pub const Kind = enum { dot };

pub const Carrier = union(Kind) {
    dot: DotSocket,

    pub fn open(kind: Kind, edge: *Edge, server: na.Address, port: u16, tag: u32) !Carrier {
        return switch (kind) {
            .dot => .{ .dot = try .open(edge, server, port, tag) },
        };
    }

    pub fn close(c: *Carrier) void {
        switch (c.*) {
            inline else => |*x| x.close(),
        }
    }

    pub fn token(c: *const Carrier) u32 {
        return switch (c.*) {
            inline else => |*x| x.token,
        };
    }

    pub fn established(c: *const Carrier) bool {
        return switch (c.*) {
            inline else => |*x| x.established(),
        };
    }

    pub fn rounds(c: *const Carrier) u32 {
        return switch (c.*) {
            inline else => |*x| x.rounds(),
        };
    }

    pub fn spent(c: *const Carrier) bool {
        return switch (c.*) {
            inline else => |*x| x.spent(),
        };
    }

    pub fn query(c: *Carrier, sh: *Shared, wire: []const u8) !?QueryId {
        return switch (c.*) {
            inline else => |*x, kind| if (try x.query(&@field(sh, @tagName(kind)), wire)) |id| id else null,
        };
    }

    /// False: gone.
    pub fn flush(c: *Carrier, sh: *Shared) !bool {
        return switch (c.*) {
            inline else => |*x, kind| try x.flush(&@field(sh, @tagName(kind))),
        };
    }

    pub fn unflush(c: *const Carrier, sh: *Shared) void {
        switch (c.*) {
            inline else => |_, kind| @field(sh, @tagName(kind)).out_len = 0,
        }
    }

    pub fn ready(c: *Carrier, sh: *Shared, events: u32) !News {
        return switch (c.*) {
            inline else => |*x, kind| try x.ready(&@field(sh, @tagName(kind)), events),
        };
    }

    pub fn next(c: *Carrier, sh: *Shared) !?Event {
        return switch (c.*) {
            inline else => |*x, kind| try x.next(&@field(sh, @tagName(kind))),
        };
    }

    pub fn stage(c: *const Carrier) []const u8 {
        return switch (c.*) {
            inline else => |*x| @tagName(x.state),
        };
    }

    pub fn fault(c: *const Carrier) []const u8 {
        return switch (c.*) {
            inline else => |*x| x.fault,
        };
    }
};

pub fn dialRounds(kind: Kind) u32 {
    return switch (kind) {
        .dot => DotSocket.dial_rounds,
    };
}

pub const Shared = struct {
    dot: DotSocket.Shared = .{},
};

/// How a query is told from its neighbours on a session.
pub const QueryId = u64;

pub const End = enum { failed, closed };

pub const News = union(enum) {
    nothing,
    /// `next` has events to take.
    read,
    ended: End,
};

pub const Event = union(enum) {
    /// Queries may go; those before the next flush leave with the handshake's last flight.
    established,
    reply: struct { id: QueryId, bytes: []u8 },
    ended: End,
};
