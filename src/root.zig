pub const dns = @import("dns.zig");
pub const event_loop = @import("event_loop.zig");
pub const transport = @import("transport.zig");
pub const tcp_transport = @import("tcp_transport.zig");
pub const resolver = @import("resolver.zig");
pub const recursive = @import("recursive.zig");
pub const cache = @import("cache.zig");
pub const dnssec = @import("dnssec.zig");
pub const tls_transport = @import("tls_transport.zig");
pub const connection_pool = @import("connection_pool.zig");
pub const tls_client = @import("tls_client.zig");
pub const encryption_state = @import("encryption_state.zig");

test {
    _ = dns;
    _ = event_loop;
    _ = transport;
    _ = tcp_transport;
    _ = resolver;
    _ = recursive;
    _ = cache;
    _ = dnssec;
    _ = tls_transport;
    _ = connection_pool;
    _ = tls_client;
    _ = encryption_state;
}
