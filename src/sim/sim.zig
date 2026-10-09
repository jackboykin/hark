//! The simulator: network, clock and randomness from a seed; stands in for
//! the edge. Serves RANGE entries after a seeded per-server latency and
//! logs every upstream query.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("../dns.zig");
const na = @import("../net_address.zig");
const rpl = @import("rpl.zig");
const sign = @import("sign.zig");
const graph = @import("../graph.zig");

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

const now0_ns: i64 = 1_000_000_000_000;
const wall0_sec: i64 = 1_800_000_000;

pub const Sim = struct {
    arena: Allocator,
    gpa: Allocator,
    scenario: *const rpl.Scenario,
    signer: sign.Signer,
    /// Signed.
    ranges: []const rpl.Range,
    prng: std.Random.DefaultPrng,
    seed: u64,
    sent: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    /// Monotonic; starts well above zero so deadlines never wrap negative.
    now_ns: i64 = now0_ns,
    /// Wall seconds, for RRSIG windows.
    wall_sec: i64 = wall0_sec,
    /// The scenario step in effect, for RANGE windows.
    step: u32 = 0,
    /// `STEP n TIMEOUT`: drop this many of the next upstream queries.
    pending_drops: u32 = 0,
    /// `STEP n UNSENT`: refuse this many of the next upstream queries at the host.
    pending_unsent: u32 = 0,
    events: std.PriorityQueue(Event, void, Event.before) = .empty,
    seq: u32 = 0,
    log: std.ArrayList(LogRow) = .empty,
    heard: Heard = .empty,
    /// A chaos run's reference: once this run hears what that one never
    /// did, or heard at another step, the two no longer share a world and
    /// their answers may differ.
    known: ?*const Heard = null,
    departed: bool = false,
    reply_buf: [65535]u8 = undefined,

    pub const Heard = std.AutoArrayHashMapUnmanaged(u64, void);

    pub fn init(arena: Allocator, gpa: Allocator, scenario: *const rpl.Scenario, mint: *sign.Mint, seed: u64) !Sim {
        var s: Sim = .{
            .arena = arena,
            .scenario = scenario,
            .signer = undefined,
            .ranges = undefined,
            .prng = std.Random.DefaultPrng.init(seed),
            .seed = seed,
            .gpa = gpa,
        };
        s.signer = try sign.Signer.init(arena, scenario, mint, s.wall_sec);
        s.ranges = try s.signer.bake(scenario.ranges);
        return s;
    }

    pub fn deinit(s: *Sim) void {
        s.events.deinit(s.gpa);
        s.log.deinit(s.gpa);
        s.sent.deinit(s.gpa);
        s.heard.deinit(s.gpa);
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

    fn wakeErased(ctx: *anyopaque, id: u32, gen: u32, at_ns: i64) anyerror!void {
        return @as(*Sim, @ptrCast(@alignCast(ctx))).schedule(id, at_ns, .{ .wake = gen });
    }

    /// One upstream query. Its reply or absence is scheduled now; nothing
    /// depends on later steps.
    pub fn send(s: *Sim, ex: Exchange) !void {
        const query = dns.parseMessage(s.arena, ex.wire) catch return s.schedule(ex.id, ex.deadline_ns, .timeout);
        if (query.questions.len == 0) return s.schedule(ex.id, ex.deadline_ns, .timeout);
        const q = query.questions[0];
        if (s.pending_unsent > 0) {
            s.pending_unsent -= 1;
            try s.hear(q, silence);
            return s.schedule(ex.id, s.now_ns, .unsent);
        }
        // RFC 8109 root priming is not logged.
        if (!(q.name.labels.len == 0 and q.qtype == .ns))
            try s.log.append(s.gpa, .{ .server = ex.server, .qname = try dns.cloneNameFlat(s.arena, q.name, false), .qtype = q.qtype, .transport = ex.transport });
        if (s.pending_drops > 0) {
            s.pending_drops -= 1;
            try s.hear(q, silence);
            return s.schedule(ex.id, ex.deadline_ns, .timeout);
        }
        const asked = try s.ask(ex.server, q, ex.transport);
        const delay = s.latency(ex.server, asked);
        const entry = s.findEntry(ex.server, q, ex.transport) orelse {
            // No RANGE for this address: nothing listens there.
            if (!s.serves(ex.server)) {
                try s.hear(q, silence);
                return s.schedule(ex.id, ex.deadline_ns, .timeout);
            }
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
        if (entry.drop) {
            try s.hear(q, silence);
            return s.schedule(ex.id, ex.deadline_ns, .timeout);
        }

        var flags = entry.flags;
        flags.qr = true;
        flags.rd = query.header.flags.rd;
        var question = q;
        switch (entry.echo) {
            .copy, .none => {},
            .lower => question.name = try dns.cloneNameLower(s.arena, q.name),
            .upper => {
                question.name = try dns.cloneNameFlat(s.arena, q.name, false);
                for (question.name.labels) |l| for (@constCast(l)) |*c| {
                    c.* = std.ascii.toUpper(c.*);
                };
            },
        }
        const questions: []const dns.Question = if (entry.echo == .none) &.{} else try s.arena.dupe(dns.Question, &.{question});
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
        var said = msg;
        said.header.id = 0;
        said.questions = &.{};
        const content = dns.serializeMessage(&s.reply_buf, said) catch return s.schedule(ex.id, ex.deadline_ns, .timeout);
        try s.hear(query.questions[0], std.hash.Wyhash.hash(0, content));
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

    const silence: u64 = 0;

    fn hear(s: *Sim, q: dns.Question, content: u64) !void {
        var nb: [dns.max_dotted_len + 1]u8 = undefined;
        var h = std.hash.Wyhash.init(content);
        h.update(q.name.formatLower(&nb));
        h.update(mem.asBytes(&q.qtype));
        h.update(mem.asBytes(&s.step));
        const k = h.final();
        try s.heard.put(s.gpa, k, {});
        if (s.known) |known| s.departed = s.departed or !known.contains(k);
    }

    fn schedule(s: *Sim, id: u32, at_ns: i64, completion: Completion) !void {
        s.seq += 1;
        try s.events.push(s.gpa, .{ .at_ns = at_ns, .seq = s.seq, .id = id, .completion = completion });
    }

    /// Names a query by what it asks and how many times it was asked.
    fn ask(s: *Sim, server: na.Address, q: dns.Question, transport: Transport) !std.hash.Wyhash {
        var h = std.hash.Wyhash.init(0);
        const key = na.AddressKey.fromAddress(server);
        h.update(&key.addr);
        h.update(mem.asBytes(&key.port));
        h.update(mem.asBytes(&key.family));
        var nb: [dns.max_dotted_len + 1]u8 = undefined;
        h.update(q.name.formatLower(&nb));
        h.update(mem.asBytes(&q.qtype));
        h.update(mem.asBytes(&transport));
        const nth = try s.sent.getOrPut(s.gpa, h.final());
        if (!nth.found_existing) nth.value_ptr.* = 0;
        nth.value_ptr.* += 1;
        h.update(mem.asBytes(nth.value_ptr));
        return h;
    }

    /// Advance to the next completion, or to `until_ns` if none lies
    /// before it.
    pub fn next(s: *Sim, until_ns: i64) ?struct { id: u32, completion: Completion } {
        const ev = s.events.peek() orelse {
            s.now_ns = @max(s.now_ns, until_ns);
            s.syncWall();
            return null;
        };
        if (ev.at_ns > until_ns) {
            s.now_ns = @max(s.now_ns, until_ns);
            s.syncWall();
            return null;
        }
        _ = s.events.pop();
        s.now_ns = @max(s.now_ns, ev.at_ns);
        s.syncWall();
        return .{ .id = ev.id, .completion = ev.completion };
    }

    /// A rule run mid-window judges signatures at its own time.
    fn syncWall(s: *Sim) void {
        s.wall_sec = wall0_sec + @divFloor(s.now_ns - now0_ns, std.time.ns_per_s);
    }

    /// Per-server: 2–40 ms base, ±25% jitter, so seeds exercise different
    /// interleavings. Keyed by the query rather than draw order, so a run
    /// that asks in another order meets the same network.
    fn latency(s: *Sim, server: na.Address, asked: std.hash.Wyhash) i64 {
        // By field: the struct has padding and AddressKey's own hash
        // folds in a per-process seed.
        var h = std.hash.Wyhash.init(0);
        const key = na.AddressKey.fromAddress(server);
        h.update(&key.addr);
        h.update(mem.asBytes(&key.port));
        h.update(mem.asBytes(&key.family));
        const base_ms: i64 = 2 + @as(i64, @intCast(h.final() % 39));
        const quarter = @divTrunc(base_ms, 4);
        const span: u64 = @intCast(2 * quarter + 1);
        var drawn = asked;
        drawn.update(mem.asBytes(&s.seed));
        const draw = drawn.final();
        const jitter = @as(i64, @intCast(std.math.mulWide(u64, draw, span) >> 64)) - quarter;
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

    /// An empty MATCH means `question` (qname, qtype, qclass).
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
