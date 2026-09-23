pub const acl = @import("acl.zig");
pub const answer = @import("answer.zig");
pub const config = @import("config.zig");
pub const delegation = @import("delegation.zig");
pub const denial = @import("denial.zig");
pub const dns = @import("dns.zig");
pub const dns64 = @import("dns64.zig");
pub const dnssec = @import("dnssec.zig");
pub const edge = @import("edge.zig");
pub const graph = @import("graph.zig");
pub const monotonic = @import("monotonic.zig");
pub const net_address = @import("net_address.zig");
pub const ns_rtt = @import("ns_rtt.zig");
pub const proof = @import("proof.zig");
pub const rand = @import("rand.zig");
pub const rebinding = @import("rebinding.zig");
pub const response = @import("response.zig");
pub const rrsig = @import("rrsig.zig");
pub const serve = @import("serve.zig");
pub const special_use = @import("special_use.zig");
pub const store = @import("store.zig");
pub const sys = @import("sys_union.zig");
pub const toml = @import("toml.zig");
pub const trust = @import("trust.zig");
pub const walk = @import("walk.zig");
pub const sim = struct {
    pub const rpl = @import("sim/rpl.zig");
    pub const sign = @import("sim/sign.zig");
    pub const sim = @import("sim/sim.zig");
    pub const replay = @import("sim/replay.zig");
};

// Explicit per-file imports drive test discovery by reachability, so tests run
// regardless of pub-ness — unlike refAllDecls, which sees only pub decls (a
// dropped `pub` silently drops a file's tests) and is on its way out of std.
// Add a line here when you add a module file.
test {
    _ = @import("acl.zig");
    _ = @import("answer.zig");
    _ = @import("config.zig");
    _ = @import("delegation.zig");
    _ = @import("denial.zig");
    _ = @import("dns.zig");
    _ = @import("dns64.zig");
    _ = @import("dnssec.zig");
    _ = @import("edge.zig");
    _ = @import("fuzz_nsec.zig");
    _ = @import("fuzz_wire.zig");
    _ = @import("graph.zig");
    _ = @import("monotonic.zig");
    _ = @import("net_address.zig");
    _ = @import("ns_rtt.zig");
    _ = @import("proof.zig");
    _ = @import("rand.zig");
    _ = @import("rebinding.zig");
    _ = @import("response.zig");
    _ = @import("rrsig.zig");
    _ = @import("serve.zig");
    _ = @import("sim/replay.zig");
    _ = @import("sim/rpl.zig");
    _ = @import("sim/sign.zig");
    _ = @import("sim/sim.zig");
    _ = @import("special_use.zig");
    _ = @import("store.zig");
    _ = @import("sys_linux.zig");
    _ = @import("sys_union.zig");
    _ = @import("toml.zig");
    _ = @import("trust.zig");
    _ = @import("walk.zig");
}
