//! The simulator: network, clock and randomness from a seed; stands in for
//! the edge. Serves RANGE entries as test/harness/responder.py does, after
//! a seeded per-server latency, and logs every upstream query.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("../dns.zig");
const na = @import("../net_address.zig");
const rpl = @import("rpl.zig");
const sign = @import("sign.zig");
const graph = @import("graph.zig");

const Transport = graph.Transport;
const Exchange = graph.Exchange;
const Completion = graph.Completion;

pub const LogRow = struct {
    server: na.Address,
    qname: dns.Name,
    qtype: dns.RType,
    transport: Transport,
};

const Event = struct {
    at_ns: i64,
    seq: u32,
    id: u32,
    completion: Completion,

    fn before(_: void, a: Event, b: Event) std.math.Order {
        return switch (std.math.order(a.at_ns, b.at_ns)) {
            .eq => std.math.order(a.seq, b.seq),
            else => |o| o,
        };
    }
};

pub const Sim = struct {
    arena: Allocator,
    gpa: Allocator,
    scenario: *const rpl.Scenario,
    signer: sign.Signer,
    /// Signed.
    ranges: []const rpl.Range,
    prng: std.Random.DefaultPrng,
    /// Monotonic; starts well above zero so deadlines never wrap negative.
    now_ns: i64 = 1_000_000_000_000,
    /// Wall seconds, for RRSIG windows.
    wall_sec: i64 = 1_800_000_000,
    /// The scenario step in effect, for RANGE windows.
    step: u32 = 0,
    /// `STEP n TIMEOUT`: drop this many of the next upstream queries.
    pending_drops: u32 = 0,
    events: std.PriorityQueue(Event, void, Event.before) = .empty,
    seq: u32 = 0,
    log: std.ArrayList(LogRow) = .empty,
    reply_buf: [65535]u8 = undefined,

    pub fn init(arena: Allocator, gpa: Allocator, scenario: *const rpl.Scenario, seed: u64) !Sim {
        var s: Sim = .{
            .arena = arena,
            .scenario = scenario,
            .signer = undefined,
            .ranges = undefined,
            .prng = std.Random.DefaultPrng.init(seed),
            .gpa = gpa,
        };
        s.signer = try sign.Signer.init(arena, scenario, seed, s.wall_sec);
        s.ranges = try s.signer.bake(scenario.ranges);
        return s;
    }

    pub fn deinit(s: *Sim) void {
        s.events.deinit(s.gpa);
        s.log.deinit(s.gpa);
    }

    pub fn random(s: *Sim) std.Random {
        return s.prng.random();
    }

    pub fn edge(s: *Sim) graph.Edge {
        return .{ .ctx = s, .now_ns = &s.now_ns, .wall_sec = &s.wall_sec, .rng = s.random(), .sendFn = sendErased, .wakeFn = wakeErased };
    }

    fn sendErased(ctx: *anyopaque, ex: Exchange) anyerror!void {
        return @as(*Sim, @ptrCast(@alignCast(ctx))).send(ex);
    }

    fn wakeErased(ctx: *anyopaque, id: u32, at_ns: i64) anyerror!void {
        return @as(*Sim, @ptrCast(@alignCast(ctx))).wake(id, at_ns);
    }

    pub fn advance(s: *Sim, seconds: u32) void {
        s.now_ns += @as(i64, seconds) * std.time.ns_per_s;
        s.wall_sec += seconds;
    }

    /// One upstream query. Its reply or absence is scheduled now; nothing
    /// depends on later steps.
    pub fn send(s: *Sim, ex: Exchange) !void {
        const query = dns.parseMessage(s.arena, ex.wire) catch return s.schedule(ex.id, ex.deadline_ns, .timeout);
        if (query.questions.len == 0) return s.schedule(ex.id, ex.deadline_ns, .timeout);
        const q = query.questions[0];
        // RFC 8109 root priming is not logged, as in the Python responder.
        if (!(q.name.labels.len == 0 and q.qtype == .ns))
            try s.log.append(s.gpa, .{ .server = ex.server, .qname = q.name, .qtype = q.qtype, .transport = ex.transport });
        if (s.pending_drops > 0) {
            s.pending_drops -= 1;
            return s.schedule(ex.id, ex.deadline_ns, .timeout);
        }
        const delay = s.latency(ex.server, s.random());
        const entry = s.findEntry(ex.server, q, ex.transport) orelse {
            // No RANGE for this address: nothing listens there.
            if (!s.serves(ex.server)) return s.schedule(ex.id, ex.deadline_ns, .timeout);
            var msg = query;
            msg.header.flags = .{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = query.header.flags.rd, .ra = false, .z = 0, .ad = false, .cd = false, .rcode = .refused };
            msg.answers = &.{};
            // A signed zone's DNSKEY is answered where it signs; anything
            // else unmatched is REFUSED so a coverage gap surfaces instead
            // of looking like a blackhole.
            if (try s.signer.dnskeyAnswer(ex.server, q)) |rrs| {
                msg.header.flags.aa = true;
                msg.header.flags.rcode = .no_error;
                msg.answers = rrs;
            }
            msg.authorities = &.{};
            msg.additionals = &.{};
            msg.opt = null;
            return s.deliver(ex, query, msg, delay);
        };
        if (entry.drop) return s.schedule(ex.id, ex.deadline_ns, .timeout);

        var flags = entry.flags;
        flags.qr = true;
        flags.rd = query.header.flags.rd;
        var question = q;
        if (entry.force_lower_qname) question.name = try dns.cloneNameLower(s.arena, q.name);
        const questions = try s.arena.dupe(dns.Question, &.{question});
        const msg: dns.Message = .{
            .header = .{ .id = query.header.id, .flags = flags },
            .questions = questions,
            .answers = entry.answers,
            .authorities = entry.authorities,
            .additionals = entry.additionals,
        };
        return s.deliver(ex, query, msg, delay);
    }

    fn deliver(s: *Sim, ex: Exchange, query: dns.Message, msg: dns.Message, latency_ns: i64) !void {
        var wire = dns.serializeMessage(&s.reply_buf, msg) catch return s.schedule(ex.id, ex.deadline_ns, .timeout);
        // A UDP reply past the advertised payload arrives truncated.
        const payload: usize = if (query.opt) |o| o.udp_payload_size else 512;
        if (ex.transport == .udp and wire.len > payload) {
            var hdr = msg.header;
            hdr.flags.tc = true;
            wire = dns.serializeMessage(&s.reply_buf, .{ .header = hdr, .questions = msg.questions }) catch return s.schedule(ex.id, ex.deadline_ns, .timeout);
        }
        const at = s.now_ns + latency_ns;
        if (at > ex.deadline_ns) return s.schedule(ex.id, ex.deadline_ns, .timeout);
        return s.schedule(ex.id, at, .{ .reply = try s.arena.dupe(u8, wire) });
    }

    pub fn wake(s: *Sim, id: u32, at_ns: i64) !void {
        return s.schedule(id, at_ns, .wake);
    }

    fn schedule(s: *Sim, id: u32, at_ns: i64, completion: Completion) !void {
        s.seq += 1;
        try s.events.push(s.gpa, .{ .at_ns = at_ns, .seq = s.seq, .id = id, .completion = completion });
    }

    /// Advance to the next completion, or to `until_ns` if none lies
    /// before it.
    pub fn next(s: *Sim, until_ns: i64) ?struct { id: u32, completion: Completion } {
        const ev = s.events.peek() orelse {
            s.now_ns = @max(s.now_ns, until_ns);
            return null;
        };
        if (ev.at_ns > until_ns) {
            s.now_ns = @max(s.now_ns, until_ns);
            return null;
        }
        _ = s.events.pop();
        s.now_ns = @max(s.now_ns, ev.at_ns);
        return .{ .id = ev.id, .completion = ev.completion };
    }

    /// Per-server: 2–40 ms base, ±25% jitter, so seeds exercise different
    /// interleavings.
    fn latency(s: *Sim, server: na.Address, rng: std.Random) i64 {
        _ = s;
        // By field: the struct has padding and AddressKey's own hash
        // folds in a per-process seed.
        var h = std.hash.Wyhash.init(0);
        const key = na.AddressKey.fromAddress(server);
        h.update(&key.addr);
        h.update(mem.asBytes(&key.port));
        h.update(mem.asBytes(&key.family));
        const base_ms: i64 = 2 + @as(i64, @intCast(h.final() % 39));
        const quarter = @divTrunc(base_ms, 4);
        const jitter = rng.intRangeAtMost(i64, -quarter, quarter);
        return (base_ms + jitter) * std.time.ns_per_ms;
    }

    fn serves(s: *const Sim, server: na.Address) bool {
        for (s.ranges) |r| if (na.ipEqual(r.address, server)) return true;
        return false;
    }

    fn findEntry(s: *const Sim, server: na.Address, q: dns.Question, transport: Transport) ?*const rpl.Entry {
        for (s.ranges) |*r| {
            if (!na.ipEqual(r.address, server)) continue;
            if (s.step < r.start or s.step > r.end) continue;
            for (r.entries) |*e| if (entryMatches(e, q, transport)) return e;
        }
        return null;
    }

    /// responder.py `_entry_matches_query`: an empty MATCH means
    /// `question` (qname, qtype, qclass).
    fn entryMatches(e: *const rpl.Entry, q: dns.Question, transport: Transport) bool {
        if (e.questions.len == 0) return false;
        var m = e.match;
        if (m.isEmpty()) m.question = true;
        if (m.question) {
            m.qname = true;
            m.qtype = true;
            m.qclass = true;
        }
        const eq = e.questions[0];
        if (m.tcp and transport != .tcp) return false;
        if (m.udp and transport != .udp) return false;
        if (m.opcode and e.flags.opcode != .query) return false;
        if (m.qtype and eq.qtype != q.qtype) return false;
        if (m.qname and !eq.name.eql(q.name)) return false;
        if (m.subdomain and !q.name.isSubdomainOf(eq.name)) return false;
        return true;
    }
};
