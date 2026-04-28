const BlockingUdpTransport = @import("blocking_transport.zig").BlockingUdpTransport;
const BlockingTcpTransport = @import("blocking_transport.zig").BlockingTcpTransport;
const TlsTransport = @import("tls_transport.zig").TlsTransport;

/// Tagged union over Do53 transport implementations. Today only the blocking
/// (sockets-on-pool-threads) variant exists; an `evented` variant will be
/// added when stdlib `Io.Evented` networking becomes usable (PR #25592).
/// At that point, `.blocking()` is replaced by forwarding methods on
/// `Transport` that dispatch by variant.
pub const Transport = union(enum) {
    blocking: Blocking,

    pub const Blocking = struct {
        udp: *BlockingUdpTransport,
        tcp: ?*BlockingTcpTransport,
    };

    /// Transitional accessor — single-variant shortcut. Will be removed when
    /// a second variant is added; callers should switch to forwarding methods.
    pub fn asBlocking(self: Transport) Blocking {
        return switch (self) {
            .blocking => |b| b,
        };
    }
};

/// Bundle of transports a resolver uses: Do53 (UDP+TCP) and optional TLS.
/// TLS is a sibling field rather than a union arm because it's a different
/// protocol concern (DoT/DoH), not an alternative impl of Do53.
pub const Transports = struct {
    do53: Transport,
    tls: ?*TlsTransport = null,
};
