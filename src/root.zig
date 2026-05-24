pub const dns = @import("dns.zig");
pub const dns_print = @import("dns_print.zig");
pub const event_loop = @import("event_loop.zig");
pub const recursive = @import("recursive.zig");
pub const cache = @import("cache.zig");
pub const dnssec = @import("dnssec.zig");
pub const tls_transport = @import("tls_transport.zig");
pub const connection_pool = @import("connection_pool.zig");
pub const encrypted_ns = @import("encrypted_ns.zig");
pub const case_state = @import("case_state.zig");
pub const toml = @import("toml.zig");
pub const config = @import("config.zig");
pub const server = @import("server.zig");
pub const ns_rtt = @import("ns_rtt.zig");
pub const ns_selector = @import("ns_selector.zig");
pub const dedup = @import("dedup.zig");
pub const nsec_cache = @import("nsec_cache.zig");
pub const counting_allocator = @import("counting_allocator.zig");
pub const bg_group = @import("bg_group.zig");
pub const blocking_transport = @import("blocking_transport.zig");
pub const rand = @import("rand.zig");
pub const monotonic = @import("monotonic.zig");
pub const sys = @import("sys.zig");
pub const net_address = @import("net_address.zig");
pub const special_use = @import("special_use.zig");
pub const acl = @import("acl.zig");
pub const rebinding = @import("rebinding.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("response.zig"); // explicit: response.zig isn't re-exported, so don't rely on transitive imports keeping its tests in the run set
}
