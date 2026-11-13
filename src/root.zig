//! The hark module: every source file, for main, the fuzzers and the tests.

pub const config = @import("config.zig");
pub const log = @import("log.zig");
pub const monotonic = @import("monotonic.zig");
pub const serve = @import("serve.zig");
pub const slab = @import("slab.zig");

// Tests are found by reachability from here: a file not listed runs none.
test {
    _ = @import("acl.zig");
    _ = @import("answer.zig");
    _ = @import("arena.zig");
    _ = @import("batch.zig");
    _ = @import("carrier.zig");
    _ = @import("chaos.zig");
    _ = @import("config.zig");
    _ = @import("delegation.zig");
    _ = @import("denial.zig");
    _ = @import("dns.zig");
    _ = @import("dns64.zig");
    _ = @import("dnssec.zig");
    _ = @import("doq_socket.zig");
    _ = @import("dot.zig");
    _ = @import("dot_socket.zig");
    _ = @import("edge.zig");
    _ = @import("fuzz_nsec.zig");
    _ = @import("fuzz_wire.zig");
    _ = @import("graph.zig");
    _ = @import("log.zig");
    _ = @import("model.zig");
    _ = @import("monotonic.zig");
    _ = @import("net_address.zig");
    _ = @import("ns_rtt.zig");
    _ = @import("proof.zig");
    _ = @import("quic.zig");
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
    _ = @import("slab.zig");
    _ = @import("special_use.zig");
    _ = @import("store.zig");
    _ = @import("stub.zig");
    _ = @import("sys.zig");
    _ = @import("sys_linux.zig");
    _ = @import("tls13.zig");
    _ = @import("toml.zig");
    _ = @import("trust.zig");
    _ = @import("walk.zig");
}
