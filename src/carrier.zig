//! What carries a server's exchanges over an encrypted session: the one
//! interface `Sessions` drives, whichever transport is underneath.

const na = @import("net_address.zig");
const Edge = @import("edge.zig");
const DotSocket = @import("dot_socket.zig");
const DoqSocket = @import("doq_socket.zig");

pub const Kind = enum { dot, doq };

pub const Carrier = union(Kind) {
    dot: DotSocket,
    doq: DoqSocket,

    pub fn open(kind: Kind, edge: *Edge, sh: *Shared, server: na.Address, port: u16, tag: u32) !Carrier {
        return switch (kind) {
            inline else => |k| @unionInit(Carrier, @tagName(k), try .open(edge, &@field(sh, @tagName(k)), server, port, tag)),
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

    /// `wire` is borrowed and must outlive its query.
    pub fn query(c: *Carrier, sh: *Shared, wire: []const u8) !Taken {
        return switch (c.*) {
            inline else => |*x, kind| try x.query(&@field(sh, @tagName(kind)), wire),
        };
    }

    pub fn cancel(c: *Carrier, id: QueryId) void {
        switch (c.*) {
            inline else => |*x| x.cancel(id),
        }
    }

    pub fn flush(c: *Carrier, sh: *Shared) !bool {
        return switch (c.*) {
            inline else => |*x, kind| try x.flush(&@field(sh, @tagName(kind))),
        };
    }

    pub fn unflush(c: *const Carrier, sh: *Shared) void {
        switch (c.*) {
            inline else => |*x, kind| x.unflush(&@field(sh, @tagName(kind))),
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

    pub fn due(c: *const Carrier) ?i64 {
        return switch (c.*) {
            inline else => |*x| x.due(),
        };
    }

    pub fn fire(c: *Carrier, sh: *Shared) !News {
        return switch (c.*) {
            inline else => |*x, kind| try x.fire(&@field(sh, @tagName(kind))),
        };
    }

    pub fn heard(c: *const Carrier) bool {
        return switch (c.*) {
            inline else => |*x| x.heard(),
        };
    }

    pub fn stage(c: *const Carrier) []const u8 {
        return switch (c.*) {
            inline else => |*x| x.stage(),
        };
    }

    pub fn fault(c: *const Carrier) []const u8 {
        return switch (c.*) {
            inline else => |*x| x.fault(),
        };
    }
};

pub fn dialRounds(kind: Kind) u32 {
    return switch (kind) {
        .dot => DotSocket.dial_rounds,
        .doq => DoqSocket.dial_rounds,
    };
}

pub const Shared = struct {
    dot: DotSocket.Shared = .{},
    doq: DoqSocket.Shared = .{},
};

pub const QueryId = u64;

pub const Taken = union(enum) {
    sent: QueryId,
    later,
    gone,
};

pub const End = enum { failed, closed };

pub const News = union(enum) {
    nothing,
    read,
    ended: End,
};

pub const Event = union(enum) {
    established,
    reply: struct { id: QueryId, bytes: []u8 },
    refused: QueryId,
    room,
    ended: End,
};
