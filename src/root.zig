//! The hark module: every source file, for main, the fuzzers and the tests.

pub const config = @import("config.zig");
pub const monotonic = @import("monotonic.zig");
pub const serve = @import("serve.zig");
pub const slab = @import("slab.zig");

// Explicit per-file imports drive test discovery by reachability, so tests run
// regardless of pub-ness — unlike refAllDecls, which sees only pub decls (a
// dropped `pub` silently drops a file's tests) and is on its way out of std.
// Add a line here when you add a module file.
test {
    _ = @import("acl.zig");
    _ = @import("answer.zig");
    _ = @import("arena.zig");
    _ = @import("batch.zig");
    _ = @import("config.zig");
    _ = @import("delegation.zig");
    _ = @import("denial.zig");
    _ = @import("dns.zig");
    _ = @import("dot.zig");
    _ = @import("carrier.zig");
    _ = @import("dot_socket.zig");
    _ = @import("doq_socket.zig");
    _ = @import("quic.zig");
    _ = @import("dns64.zig");
    _ = @import("dnssec.zig");
    _ = @import("edge.zig");
    _ = @import("fuzz_nsec.zig");
    _ = @import("fuzz_wire.zig");
    _ = @import("graph.zig");
    _ = @import("slab.zig");
    _ = @import("monotonic.zig");
    _ = @import("net_address.zig");
    _ = @import("ns_rtt.zig");
    _ = @import("proof.zig");
    _ = @import("rand.zig");
    _ = @import("rebinding.zig");
    _ = @import("response.zig");
    _ = @import("rrsig.zig");
    _ = @import("serve.zig");
    _ = @import("sessions.zig");
    _ = @import("sim/replay.zig");
    _ = @import("sim/rpl.zig");
    _ = @import("sim/sign.zig");
    _ = @import("sim/sim.zig");
    _ = @import("special_use.zig");
    _ = @import("store.zig");
    _ = @import("stub.zig");
    _ = @import("sys_linux.zig");
    _ = @import("sys_union.zig");
    _ = @import("tls13.zig");
    _ = @import("toml.zig");
    _ = @import("trust.zig");
    _ = @import("walk.zig");
}
