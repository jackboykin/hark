//! Serving a client from the graph.
const std = @import("std");
const Allocator = std.mem.Allocator;
const dns = @import("../dns.zig");
const graph = @import("graph.zig");

pub const Client = struct { rd: bool = true, cd: bool = false, do_bit: bool = false, ad: bool = false };

/// A reply, and whether it is a fact past this instant (TTL 0 is served
/// but never memoised).
pub const Served = struct { msg: dns.Message, cacheable: bool };

/// RFC 8482: ANY is answered with a synthetic HINFO, asking nobody.
pub fn hinfo(arena: Allocator, q: dns.Question, c: Client) !Served {
    const rr: dns.ResourceRecord = .{ .name = q.name, .rtype = @fromBackingInt(13), .rclass = .in, .ttl = 0, .rdata = .{ .unknown = "\x07RFC8482\x00" } };
    return .{ .cacheable = false, .msg = .{
        .header = .{ .id = 0, .flags = .{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = c.rd, .ra = true, .z = 0, .ad = false, .cd = c.cd, .rcode = .no_error } },
        .questions = try arena.dupe(dns.Question, &.{q}),
        .answers = try arena.dupe(dns.ResourceRecord, &.{rr}),
    } };
}

/// The settled answer cell `root`, its chain aged to now and shaped for
/// the client. A bogus chain is SERVFAIL unless CD; a verified hop's TTLs
/// are bounded by its proof's remaining validity; signatures only to a DO
/// client; AD claims the whole chain, set only when asked for (RFC 6840
/// §5.7).
pub fn answer(arena: Allocator, g: *graph.Graph, root: graph.CellId, q: dns.Question, c: Client, minimal: bool) !Served {
    const a = g.cell(root).value.answer;
    var chain: std.ArrayList(dns.ResourceRecord) = .empty;
    var last: graph.Reply = .{ .kind = .servfail, .rcode = .server_failure, .aa = false };
    var age: u32 = 0;
    var life: u32 = std.math.maxInt(u32);
    const served = !a.broken and (a.status != .bogus or c.cd);
    if (served) for (a.hops, 0..) |h, i| {
        last = g.cell(h).value.rrset;
        age = @intCast(@divTrunc(g.now() - last.stored_ns, std.time.ns_per_s));
        life = std.math.maxInt(u32);
        if (i < a.judged.len) {
            const proven = g.cell(a.judged[i]).value.secure.proven_until_ns;
            life = @intCast(@min(@max(@divTrunc(proven - g.now(), std.time.ns_per_s), 0), std.math.maxInt(u32)));
        }
        try appendAged(arena, &chain, last.answers, age, life, c.do_bit);
    };
    const positive = last.kind == .answer or last.kind == .alias;
    var authorities: std.ArrayList(dns.ResourceRecord) = .empty;
    var additionals: std.ArrayList(dns.ResourceRecord) = .empty;
    if (!(positive and minimal and q.qtype != .ns)) {
        try appendAged(arena, &authorities, last.authorities, age, life, c.do_bit);
        try appendAged(arena, &additionals, last.additionals, age, life, c.do_bit);
    }
    return .{ .cacheable = g.cell(root).expires_ns > g.now(), .msg = .{
        .header = .{ .id = 0, .flags = .{
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = c.rd,
            .ra = true,
            .z = 0,
            .ad = served and a.status == .secure and (c.do_bit or c.ad),
            .cd = c.cd,
            .rcode = if (last.kind == .servfail) last.rcode else if (last.kind == .nxdomain) .name_error else .no_error,
        } },
        .questions = try arena.dupe(dns.Question, &.{q}),
        .answers = chain.items,
        .authorities = authorities.items,
        .additionals = additionals.items,
    } };
}

/// TTLs less the time since the reply was taken, at most `life`;
/// signatures only when wanted.
fn appendAged(arena: Allocator, out: *std.ArrayList(dns.ResourceRecord), rrs: []const dns.ResourceRecord, age: u32, life: u32, sigs: bool) !void {
    for (rrs) |rr| {
        if (rr.rtype == .rrsig and !sigs) continue;
        var aged = rr;
        aged.ttl = @min(rr.ttl -| age, life);
        try out.append(arena, aged);
    }
}
