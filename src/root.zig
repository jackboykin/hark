pub const dns = @import("dns.zig");
pub const event_loop = @import("event_loop.zig");
pub const transport = @import("transport.zig");
pub const tcp_transport = @import("tcp_transport.zig");
pub const resolver = @import("resolver.zig");
pub const recursive = @import("recursive.zig");
pub const cache = @import("cache.zig");
pub const dnssec = @import("dnssec.zig");

test {
    _ = dns;
    _ = event_loop;
    _ = transport;
    _ = tcp_transport;
    _ = resolver;
    _ = recursive;
    _ = cache;
    _ = dnssec;
}
