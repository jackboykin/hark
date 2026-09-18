pub const dns = @import("dns.zig");
pub const delegation = @import("delegation.zig");
pub const dnssec = @import("dnssec.zig");
pub const toml = @import("toml.zig");
pub const config = @import("config.zig");
pub const ns_rtt = @import("ns_rtt.zig");
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
    pub const graph = @import("graph/graph.zig");
    pub const walk = @import("graph/walk.zig");
    pub const trust = @import("graph/trust.zig");
    pub const denial = @import("graph/denial.zig");
    pub const store = @import("graph/store.zig");
    pub const answer = @import("graph/answer.zig");
    pub const serve = @import("graph/serve.zig");
    pub const edge = @import("graph/edge.zig");
    pub const rpl = @import("graph/sim/rpl.zig");
    pub const sim = @import("graph/sim/sim.zig");
    pub const sign = @import("graph/sim/sign.zig");
    pub const replay = @import("graph/sim/replay.zig");
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
    _ = @import("delegation.zig");
    _ = @import("dnssec.zig");
    _ = @import("toml.zig");
    _ = @import("config.zig");
    _ = @import("ns_rtt.zig");
    _ = @import("graph/graph.zig");
    _ = @import("graph/walk.zig");
    _ = @import("graph/trust.zig");
    _ = @import("graph/denial.zig");
    _ = @import("graph/store.zig");
    _ = @import("graph/answer.zig");
    _ = @import("graph/serve.zig");
    _ = @import("graph/edge.zig");
    _ = @import("graph/sim/rpl.zig");
    _ = @import("graph/sim/sim.zig");
    _ = @import("graph/sim/sign.zig");
    _ = @import("graph/sim/replay.zig");
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
