const BlockingUdpTransport = @import("blocking_transport.zig").BlockingUdpTransport;
const TlsTransport = @import("tls_transport.zig").TlsTransport;

pub const Transports = struct {
    udp: *BlockingUdpTransport,
    tcp_enabled: bool,
    tls: ?*TlsTransport = null,
};
