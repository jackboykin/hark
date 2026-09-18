pub const dns = @import("dns.zig");
pub const event_loop = @import("event_loop.zig");
pub const recursive = @import("recursive.zig");
pub const delegation = @import("delegation.zig");
pub const cache = @import("cache.zig");
pub const dnssec = @import("dnssec.zig");
pub const tls_transport = @import("tls_transport.zig");
pub const connection_pool = @import("connection_pool.zig");
pub const encrypted_ns = @import("encrypted_ns.zig");
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
pub const sys = @import("sys_union.zig");
pub const net_address = @import("net_address.zig");
pub const special_use = @import("special_use.zig");
pub const acl = @import("acl.zig");
pub const rebinding = @import("rebinding.zig");
pub const dns64 = @import("dns64.zig");
pub const response = @import("response.zig");
pub const graph = struct {
    pub const rpl = @import("graph/rpl.zig");
    pub const sim = @import("graph/sim.zig");
    pub const graph = @import("graph/graph.zig");
    pub const run = @import("graph/run.zig");
    pub const sign = @import("graph/sign.zig");
};

/// This module's own optimize mode. The bench harness is pinned to ReleaseFast
/// so the instrument stays constant while `-Doptimize` varies the subject, which
/// means the harness's `builtin.mode` is the constant `fast` and says nothing
/// about which hark was measured. Read this instead.
pub const build_mode = @import("builtin").mode;

// Explicit per-file imports drive test discovery by reachability, so tests run
// regardless of pub-ness — unlike refAllDecls, which sees only pub decls (a
// dropped `pub` silently drops a file's tests) and is on its way out of std.
// Add a line here when you add a module file.
test {
    _ = @import("dns.zig");
    _ = @import("event_loop.zig");
    _ = @import("uring.zig");
    _ = @import("epoll.zig");
    _ = @import("recursive.zig");
    _ = @import("delegation.zig");
    _ = @import("cache.zig");
    _ = @import("dnssec.zig");
    _ = @import("tls_transport.zig");
    _ = @import("connection_pool.zig");
    _ = @import("encrypted_ns.zig");
    _ = @import("toml.zig");
    _ = @import("config.zig");
    _ = @import("server.zig");
    _ = @import("ns_rtt.zig");
    _ = @import("ns_selector.zig");
    _ = @import("dedup.zig");
    _ = @import("nsec_cache.zig");
    _ = @import("counting_allocator.zig");
    _ = @import("bg_group.zig");
    _ = @import("graph/rpl.zig");
    _ = @import("graph/sim.zig");
    _ = @import("graph/graph.zig");
    _ = @import("graph/run.zig");
    _ = @import("graph/sign.zig");
    _ = @import("blocking_transport.zig");
    _ = @import("rand.zig");
    _ = @import("monotonic.zig");
    _ = @import("sys_union.zig");
    _ = @import("sys_linux.zig");
    _ = @import("net_address.zig");
    _ = @import("special_use.zig");
    _ = @import("acl.zig");
    _ = @import("rebinding.zig");
    _ = @import("dns64.zig");
    _ = @import("response.zig");
    _ = @import("fuzz_wire.zig");
    _ = @import("fuzz_nsec.zig");
}
