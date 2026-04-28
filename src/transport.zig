const BlockingUdpTransport = @import("blocking_transport.zig").BlockingUdpTransport;
const BlockingTcpTransport = @import("blocking_transport.zig").BlockingTcpTransport;
const TlsTransport = @import("tls_transport.zig").TlsTransport;

pub const Transport = union(enum) {
    blocking: Blocking,

    const Blocking = struct {
        udp: *BlockingUdpTransport,
        tcp: ?*BlockingTcpTransport,
    };

    pub fn asBlocking(self: Transport) Blocking {
        return switch (self) {
            .blocking => |b| b,
        };
    }
};

pub const Transports = struct {
    do53: Transport,
    tls: ?*TlsTransport = null,
};
