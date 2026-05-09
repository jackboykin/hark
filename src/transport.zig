const BlockingUdpTransport = @import("blocking_transport.zig").BlockingUdpTransport;
const BlockingTcpTransport = @import("blocking_transport.zig").BlockingTcpTransport;
const TlsTransport = @import("tls_transport.zig").TlsTransport;

pub const Transports = struct {
    udp: *BlockingUdpTransport,
    tcp: ?*BlockingTcpTransport,
    tls: ?*TlsTransport = null,
};
