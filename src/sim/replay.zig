//! Replay a `.rpl` scenario against the graph in the simulator: the
//! graph's test suite.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;
const dns = @import("../dns.zig");
const na = @import("../net_address.zig");
const rpl = @import("rpl.zig");
const sim = @import("sim.zig");
const sign = @import("sign.zig");
const graph = @import("../graph.zig");
const answer = @import("../answer.zig");
const response = @import("../response.zig");
const rebinding = @import("../rebinding.zig");
const config = @import("../config.zig");
const ns_rtt = @import("../ns_rtt.zig");
const chaos = @import("../chaos.zig");

pub const Phase = enum { steps, warm };

/// How many decisions each chaos site took other than hark's own.
const Fired = std.EnumArray(chaos.Site, u32);

pub const Report = struct {
    /// The failing step and why.
    step: u32 = 0,
    msg: []const u8 = "",
    phase: Phase = .steps,
    /// The upstream query log, one `server <- qname qtype` per line,
    /// gpa-owned. Two runs of one seed must produce the same text.
    log: []const u8 = "",
    /// `Graph.schedule`: two runs of one seed must run one.
    schedule: u64 = 0,
    answers: std.ArrayList(Answered) = .empty,
    heard: sim.Sim.Heard = .empty,
    departed: u32 = 0,
    compared: u32 = 0,
    fired: Fired = .initFill(0),
    /// The chaos decisions that left hark's own, and under `tell`, named.
    left: chaos.Events = .empty,
    told: std.ArrayList([]const u8) = .empty,
    tally: graph.Tally = .{},
    cells: usize = 0,

    fn deinit(r: *Report, gpa: Allocator) void {
        gpa.free(r.log);
        for (r.answers.items) |a| gpa.free(a.wire);
        r.answers.deinit(gpa);
        r.heard.deinit(gpa);
        r.left.deinit(gpa);
        for (r.told.items) |t| gpa.free(t);
        r.told.deinit(gpa);
    }
};

pub const Answered = struct {
    phase: Phase,
    step: u32,
    wire: []const u8,
    limited: bool,
};

pub const Options = struct {
    seed: u64 = 1,
    trace: bool = false,
    chaos: u64 = 0,
    reference: []const Answered = &.{},
    known: ?*const sim.Sim.Heard = null,
    only: ?*const chaos.Events = null,
    tell: bool = false,
};

fn runScenario(gpa: Allocator, scenario: *const rpl.Scenario, mint: *sign.Mint, opts: Options, report: *Report) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var s = try sim.Sim.init(arena, gpa, scenario, mint, opts.seed);
    defer s.deinit();
    s.known = opts.known;
    defer mem.swap(sim.Sim.Heard, &report.heard, &s.heard);
    var ch: chaos.Chaos = .{ .gpa = gpa, .seed = opts.chaos, .only = opts.only, .told = if (opts.tell) .empty else null };
    defer ch.deinit();
    defer {
        report.fired = ch.fired;
        mem.swap(chaos.Events, &report.left, &ch.left);
        if (ch.told) |*t| mem.swap(std.ArrayList([]const u8), &report.told, t);
    }
    var edge = s.edge();
    if (opts.chaos != 0) {
        edge.chaos = &ch;
        s.chaos = &ch;
    }
    var g = try graph.Graph.init(gpa, .{
        .qmin = scenario.qmin orelse true,
        .root_hints = scenario.root_hints,
        .stub_zones = scenario.stub_zones,
        .addr_policy = .{ .allow_loopback = true },
        .stagger_ms = scenario.stagger_ms orelse 150,
        .max_queries = scenario.max_queries orelse 100,
        .trust_anchor = s.signer.anchor(),
        .prefetch = scenario.prefetch orelse false,
        .trace = opts.trace,
    }, edge);
    defer g.deinit();
    defer {
        report.tally = g.tally;
        report.schedule = g.schedule;
        report.cells = g.cells.items.len;
    }

    // Off unless the scenario turns it on, as the harness runs serve.
    const rb: rebinding.Config = .{
        .enabled = scenario.rebinding_enabled orelse false,
        .allow_zones = try config.parseZoneList(arena, scenario.rebinding_allow_zones),
        .extra_block = try config.parseCidrList(arena, scenario.rebinding_extra_block),
        .extra_allow = try config.parseCidrList(arena, scenario.rebinding_extra_allow),
        .nat64 = scenario.dns64_prefix,
    };
    var drops: u32 = 0;
    for (scenario.steps) |st| drops += @intFromBool(st.kind == .timeout);
    s.pending_drops = drops;

    defer report.log = formatLog(gpa, s.log.items) catch "";
    // CHECK_ANSWER reads the held roots' hops.
    var held: Held = .{ null, null };
    defer unholdAll(&g, &held);
    var desk: answer.Desk = .{
        .g = &g,
        .retention = .{ .min_ttl = scenario.min_ttl orelse 0, .serve_stale_ttl = scenario.serve_stale_ttl orelse 0 },
        .dns64 = scenario.dns64_prefix,
        .minimal = scenario.minimal_responses orelse true,
    };
    defer desk.deinit();
    var last: ?dns.Message = null;
    var cursor: usize = 0;
    for (scenario.steps) |st| {
        s.step = st.n;
        report.step = st.n;
        if (opts.chaos != 0) switch (st.kind) {
            .check_answer, .check_query_log, .check_out_query, .check_max_queries, .check_max_verifies, .check_max_runs => continue,
            else => {},
        };
        switch (st.kind) {
            .query => {
                const sent = try resolveClient(arena, &g, &s, scenario, st.entry.?, &held, &desk, &rb);
                try answered(gpa, report, opts, &s, .steps, st.n, sent);
                if (sent) |x| last = x.msg else if (opts.chaos == 0) {
                    report.msg = "client timed out";
                    return error.ScenarioFailed;
                }
            },
            .check_answer => {
                const actual = last orelse {
                    report.msg = "CHECK_ANSWER before any QUERY";
                    return error.ScenarioFailed;
                };
                if (answerMismatch(actual, st.entry.?, .cold)) |why| {
                    if (opts.trace) printSections(actual);
                    report.msg = why;
                    return error.ScenarioFailed;
                }
            },
            .check_query_log => if (queryLogMismatch(s.log.items, st.entry.?)) |why| {
                report.msg = why;
                return error.ScenarioFailed;
            },
            .check_out_query => {
                if (cursor >= s.log.items.len) {
                    report.msg = "CHECK_OUT_QUERY past the end of the log";
                    return error.ScenarioFailed;
                }
                if (outQueryMismatch(s.log.items[cursor], st.entry.?)) |why| {
                    report.msg = why;
                    return error.ScenarioFailed;
                }
                cursor += 1;
            },
            .check_max_queries => if (s.log.items.len > st.bound) {
                report.msg = "CHECK_MAX_QUERIES exceeded";
                return error.ScenarioFailed;
            },
            .check_max_verifies => if (g.verify_memo.misses > st.bound) {
                report.msg = "CHECK_MAX_VERIFIES exceeded";
                return error.ScenarioFailed;
            },
            .check_max_runs => if (g.tally.runs > st.bound) {
                report.msg = "CHECK_MAX_RUNS exceeded";
                return error.ScenarioFailed;
            },
            .timeout => cursor += 1,
            .unsent => s.pending_unsent += 1,
            // What was due arrives on the way.
            .time_passes => {
                const until = s.now_ns + @as(i64, st.seconds) * std.time.ns_per_s;
                while (s.next(until)) |ev| try g.complete(ev.id, ev.completion);
            },
        }
    }
    report.phase = .warm;
    try requery(gpa, arena, &g, &s, scenario, opts, report, &held, &desk, &rb);
    // Quiescence: nothing outlives its demand.
    unholdAll(&g, &held);
    while (s.next(s.now_ns + 60 * std.time.ns_per_s)) |ev| try g.complete(ev.id, ev.completion);
    if (g.live != 0 or g.budgets != 0 or g.flights != 0 or g.work.bytes != 0) {
        report.msg = "cells, budgets, flights or work bytes outlived the scenario";
        return error.ScenarioFailed;
    }
}

/// Every checked question, re-asked against the settled graph, must answer
/// the same and from memory alone unless the answer was never a fact (TTL
/// 0). A cell that expired as it settled, or a memoised head that lost its
/// chain, shows up as an upstream query or a different answer. The last
/// check of a question is in force; TTLs have aged and are not compared,
/// and a failure still held answers Cached Error (RFC 8914 §4.14).
fn requery(gpa: Allocator, arena: Allocator, g: *graph.Graph, s: *sim.Sim, scenario: *const rpl.Scenario, opts: Options, report: *Report, held: *Held, desk: *answer.Desk, rb: *const rebinding.Config) !void {
    const steps = scenario.steps;
    for (steps[0..steps.len -| 1], steps[1..], 0..) |query, check, i| {
        if (query.kind != .query or check.kind != .check_answer) continue;
        const q = query.entry.?.questions[0];
        var superseded = false;
        for (steps[i + 2 ..]) |st| if (st.kind == .query) {
            const lq = st.entry.?.questions[0];
            superseded = superseded or (lq.name.eql(q.name) and lq.qtype == q.qtype);
        };
        if (superseded) continue;
        report.step = query.n;
        const before = s.log.items.len;
        const sent = try resolveClient(arena, g, s, scenario, query.entry.?, held, desk, rb);
        try answered(gpa, report, opts, s, .warm, query.n, sent);
        const actual = sent orelse {
            if (opts.chaos != 0) continue;
            report.msg = "client timed out";
            return error.ScenarioFailed;
        };
        if (opts.chaos == 0) if (answerMismatch(actual.msg, check.entry.?, .warm)) |why| {
            report.msg = why;
            return error.ScenarioFailed;
        };
        if (opts.chaos == 0 and s.log.items.len != before and actual.cacheable) {
            report.msg = "went upstream";
            return error.ScenarioFailed;
        }
    }
}

const Held = [2]?graph.CellId;

fn unholdAll(g: *graph.Graph, held: *Held) void {
    for (held) |*h| if (h.*) |id| {
        g.unhold(id);
        h.* = null;
    };
}

/// What the client was sent, read back off the wire serve builds.
const Sent = struct { msg: dns.Message, wire: []const u8, cacheable: bool, limited: bool };

fn answered(gpa: Allocator, report: *Report, opts: Options, s: *const sim.Sim, phase: Phase, step: u32, sent: ?Sent) !void {
    const limited = if (sent) |x| x.limited else true;
    const wire = try gpa.dupe(u8, if (sent) |x| x.wire else "");
    {
        errdefer gpa.free(wire);
        try report.answers.append(gpa, .{ .phase = phase, .step = step, .wire = wire, .limited = limited });
    }
    if (opts.chaos == 0) return;
    const ref = find(opts.reference, phase, step) orelse {
        report.msg = "chaos asked what the reference did not";
        return error.ScenarioFailed;
    };
    // A limit may only make its own answer fail.
    if (limited or ref.limited) return;
    if (s.departed) {
        report.departed += 1;
        return;
    }
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const want = try dns.parseMessage(arena_state.allocator(), ref.wire);
    const actual = sent.?.msg;
    // What chaos forgot may fail any later answer of its own.
    if (s.chaos.?.forgot and actual.header.flags.rcode == .server_failure) return;
    report.compared += 1;
    if (messageMismatch(actual, want)) |why| {
        std.debug.print("  chaos's answer, then the reference's:\n", .{});
        printSections(actual);
        printSections(want);
        report.msg = why;
        return error.ScenarioFailed;
    }
}

fn synthesized(m: dns.Message) bool {
    const opt = m.opt orelse return false;
    for (opt.options) |o| if (o.code == dns.edns_opt_ede and o.data.len >= 2 and
        mem.readInt(u16, o.data[0..2], .big) == @backingInt(dns.Ede.Code.synthesized)) return true;
    return false;
}

fn find(answers: []const Answered, phase: Phase, step: u32) ?Answered {
    for (answers) |a| if (a.phase == phase and a.step == step) return a;
    return null;
}

/// TTLs age from when each run fetched, so they are not compared. An
/// answer's EDNS options say how hark answered (synthesized, say), which is
/// its state's to say; a failure's say why, which is the answer. A denial
/// synthesized from what hark holds proves the same answer with other
/// proofs than the server sent, so its authority is not compared.
fn messageMismatch(actual: dns.Message, want: dns.Message) ?[]const u8 {
    const af = actual.header.flags;
    const wf = want.header.flags;
    if (af.rcode != wf.rcode) return "chaos moved the rcode";
    if (af.aa != wf.aa or af.tc != wf.tc or af.ad != wf.ad or af.ra != wf.ra) return "chaos moved the flags";
    if (!sectionEql(actual.answers, want.answers, false)) return "chaos moved the ANSWER";
    const relayed = !synthesized(actual) and !synthesized(want);
    if (relayed and !sectionEql(actual.authorities, want.authorities, false)) return "chaos moved the AUTHORITY";
    if (!sectionEql(actual.additionals, want.additionals, false)) return "chaos moved the ADDITIONAL";
    if (af.rcode != .server_failure) return null;
    const a_opts: []const dns.EdnsOption = if (actual.opt) |o| o.options else &.{};
    const w_opts: []const dns.EdnsOption = if (want.opt) |o| o.options else &.{};
    if (a_opts.len != w_opts.len) return "chaos moved the EDNS options";
    for (a_opts, w_opts) |x, y| if (x.code != y.code or !mem.eql(u8, x.data, y.data)) return "chaos moved the EDNS options";
    return null;
}

/// Null when the client's timer fires first. The roots stay in `held`,
/// since the answer reads their hops, until the next question.
fn resolveClient(arena: Allocator, g: *graph.Graph, s: *sim.Sim, scenario: *const rpl.Scenario, entry: rpl.Entry, held: *Held, desk: *answer.Desk, rb: *const rebinding.Config) !?Sent {
    const q = entry.questions[0];
    const client: answer.Client = .{ .rd = entry.flags.rd, .cd = entry.flags.cd, .do_bit = entry.do_bit, .ad = entry.flags.ad };
    var limited = false;
    const served = switch (try desk.early(arena, q, client)) {
        .synthesized, .replayed, .floored => |served| served,
        .held => |served| blk: {
            limited = true;
            break :blk served;
        },
        .recalled => |served| blk: {
            errdefer served.release(&g.store);
            try agrees(arena, g, s, scenario, q, client, held, desk, rb, served);
            break :blk served;
        },
        .graph => blk: {
            const built = try shapeClient(arena, g, s, scenario, q, client, held, desk) orelse return null;
            for (held) |h| if (h) |id| if (answer.failureOf(g, id, client.cd)) |why| {
                limited = limited or why.cause == .asker or why.remembered;
            };
            break :blk try desk.derived(q, client, built);
        },
    };
    defer served.release(&g.store);
    const wire = try wireOf(arena, q, client, entry.do_bit or entry.edns, rb, served);
    return .{ .msg = try dns.parseMessage(arena, wire), .wire = wire, .cacheable = served.cacheable, .limited = limited };
}

/// The bytes serve would send `client` for `served`, bar the query id.
fn wireOf(arena: Allocator, q: dns.Question, client: answer.Client, edns: bool, rb: *const rebinding.Config, served: answer.Served) ![]const u8 {
    const ctx: response.ResponseContext = .{
        .query_id = 0,
        .opcode = .query,
        .rd = client.rd,
        .cd = client.cd,
        .questions = try arena.dupe(dns.Question, &.{q}),
        .client_edns = edns,
        .client_do = client.do_bit,
        .max_udp_payload = dns.max_message_len,
        .rebinding = rb,
    };
    return response.buildResponseWire(try arena.alloc(u8, dns.max_message_len), ctx, served.reply(), arena) orelse error.OutOfMemory;
}

/// `recall`'s backstop: what it serves from the store, the graph builds
/// too, asking nobody, to the byte.
fn agrees(arena: Allocator, g: *graph.Graph, s: *sim.Sim, scenario: *const rpl.Scenario, q: dns.Question, client: answer.Client, held: *Held, desk: *answer.Desk, rb: *const rebinding.Config, recalled: answer.Served) !void {
    const before = s.log.items.len;
    const built = try shapeClient(arena, g, s, scenario, q, client, held, desk) orelse return error.RecallDisagrees;
    defer built.release(&g.store);
    if (s.log.items.len != before) return error.RecallDisagrees;
    const a = try wireOf(arena, q, client, false, rb, recalled);
    const b = try wireOf(arena, q, client, false, rb, built);
    const ede_eq = if (recalled.ede) |x| if (built.ede) |y| x.code == y.code and mem.eql(u8, x.text, y.text) else false else built.ede == null;
    if (!mem.eql(u8, a, b) or !ede_eq) return error.RecallDisagrees;
}

/// The graph driven synchronously: serve parks the client instead.
fn shapeClient(arena: Allocator, g: *graph.Graph, s: *sim.Sim, scenario: *const rpl.Scenario, q: dns.Question, client: answer.Client, held: *Held, desk: *answer.Desk) !?answer.Served {
    unholdAll(g, held);
    const deadline = s.now_ns + @as(i64, scenario.client_timeout_ms) * std.time.ns_per_ms;
    const asked = try desk.asked(arena, q, client);
    const root = try g.demandRoot(asked.name, asked.qtype, .new);
    held[0] = root;
    try g.drain();
    // RFC 8767 §5: stale at the client's patience, as serve does.
    const patience = s.now_ns + answer.stale_client_ms * std.time.ns_per_ms;
    if (desk.retention.serve_stale_ttl > 0 and !try settleBy(g, s, root, @min(patience, deadline))) {
        if (try desk.memory(arena, q, client, .stale)) |served| {
            unholdAll(g, held);
            return served;
        }
    }
    if (!try settleBy(g, s, root, deadline)) {
        unholdAll(g, held);
        return null;
    }
    const served = try desk.built(arena, root, q, client);
    const aq = desk.wantsA(q, client, served) orelse return try desk.finish(arena, q, client, served, null);
    const a = try g.demandRoot(aq.name, aq.qtype, .new);
    held[1] = a;
    try g.drain();
    if (!try settleBy(g, s, a, deadline)) {
        served.release(&g.store);
        unholdAll(g, held);
        return null;
    }
    return try desk.finish(arena, q, client, served, a);
}

/// False when nothing more arrives before `until`.
fn settleBy(g: *graph.Graph, s: *sim.Sim, root: graph.CellId, until: i64) !bool {
    while (!g.cell(root).settled()) {
        const ev = s.next(until) orelse return false;
        try g.complete(ev.id, ev.completion);
    }
    return true;
}

fn printSections(m: dns.Message) void {
    var nb: [dns.max_dotted_len + 1]u8 = undefined;
    std.debug.print("  actual: rcode={f} aa={} ad={}\n", .{ dns.tag(m.header.flags.rcode), m.header.flags.aa, m.header.flags.ad });
    if (m.opt) |o| for (o.options) |x| std.debug.print("    option {d}: {x}\n", .{ x.code, x.data });
    for ([_][]const dns.ResourceRecord{ m.answers, m.authorities, m.additionals }, [_][]const u8{ "an", "ns", "ar" }) |sec, label| {
        for (sec) |rr| std.debug.print("    {s} {s} {d} {f}\n", .{ label, rr.name.formatInto(&nb), rr.ttl, dns.tag(rr.rtype) });
    }
}

fn formatLog(gpa: Allocator, log: []const sim.LogRow) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (log) |row| {
        var nb: [dns.max_dotted_len + 1]u8 = undefined;
        var ab: [64]u8 = undefined;
        try out.print(gpa, "    {s} <- {s} {f}\n", .{ na.format(row.server, &ab), row.qname.formatInto(&nb), dns.tag(row.qtype) });
    }
    return out.toOwnedSlice(gpa);
}

// ── CHECK_ANSWER ───────────────────────────────────────────────────────

fn answerMismatch(actual: dns.Message, e: rpl.Entry, pass: enum { cold, warm }) ?[]const u8 {
    var m = e.match;
    if (m.isEmpty()) m.all = true;
    m.ttl = m.ttl and pass == .cold;
    if (m.all) {
        m.rcode = true;
        m.flags = true;
        m.question = true;
        m.answer = true;
        m.authority = true;
        m.additional = true;
    }
    const af = actual.header.flags;
    const ef = e.flags;
    if ((m.rcode or m.flags) and af.rcode != ef.rcode) return "rcode mismatch";
    if (m.flags and (af.qr != ef.qr or af.aa != ef.aa or af.tc != ef.tc or af.ra != ef.ra or af.ad != ef.ad)) return "flags mismatch";
    if (m.question) {
        if (actual.questions.len != e.questions.len) return "QUESTION mismatch";
        for (actual.questions, e.questions) |a, b| if (!a.name.eql(b.name) or a.qtype != b.qtype) return "QUESTION mismatch";
    }
    if (m.answer and !sectionEql(actual.answers, e.answers, m.ttl)) return "ANSWER mismatch";
    if (m.authority and !sectionEql(actual.authorities, e.authorities, m.ttl)) return "AUTHORITY mismatch";
    if (m.additional and !sectionEql(actual.additionals, e.additionals, m.ttl)) return "ADDITIONAL mismatch";
    if (e.ede) |want| {
        const opt = actual.opt orelse return "EDE mismatch";
        const held: u16 = @backingInt(dns.Ede.Code.cached_error);
        for (opt.options) |o| {
            if (o.code != dns.edns_opt_ede or o.data.len < 2) continue;
            const code = mem.readInt(u16, o.data[0..2], .big);
            if (code == want or (pass == .warm and code == held)) break;
        } else return "EDE mismatch";
    }
    return null;
}

const ttl_slack: u32 = 3;

/// Multiset equality. RRSIGs in `actual` count only when `expected`
/// carries any; their bytes vary run to run.
fn sectionEql(actual: []const dns.ResourceRecord, expected: []const dns.ResourceRecord, compare_ttl: bool) bool {
    var want_sigs = false;
    for (expected) |rr| want_sigs = want_sigs or rr.rtype == .rrsig;
    var used: [256]bool = @splat(false);
    var count: usize = 0;
    for (actual) |a| {
        if (a.rtype == .rrsig and !want_sigs) continue;
        if (a.rtype == .opt) continue;
        count += 1;
        var found = false;
        for (expected, 0..) |x, i| {
            if (i >= used.len or used[i]) continue;
            if (rrEql(a, x, compare_ttl)) {
                used[i] = true;
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return count == expected.len;
}

fn rrEql(a: dns.ResourceRecord, b: dns.ResourceRecord, compare_ttl: bool) bool {
    // Owners byte-exact: hark scrubs 0x20 case off every owner.
    if (!a.name.eqlExact(b.name) or a.rtype != b.rtype) return false;
    if (compare_ttl and @max(a.ttl, b.ttl) - @min(a.ttl, b.ttl) > ttl_slack) return false;
    return rdataEql(a.rdata, b.rdata);
}

/// Names folded, as the harness lowercases rdata text.
fn rdataEql(a: dns.RData, b: dns.RData) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .a => |v| mem.eql(u8, &v, &b.a),
        .aaaa => |v| mem.eql(u8, &v, &b.aaaa),
        .ns => |v| v.eql(b.ns),
        .cname => |v| v.eql(b.cname),
        .dname => |v| v.eql(b.dname),
        .ptr => |v| v.eql(b.ptr),
        .mx => |v| v.preference == b.mx.preference and v.exchange.eql(b.mx.exchange),
        .soa => |v| v.mname.eql(b.soa.mname) and v.rname.eql(b.soa.rname) and v.serial == b.soa.serial and
            v.refresh == b.soa.refresh and v.retry == b.soa.retry and v.expire == b.soa.expire and v.minimum == b.soa.minimum,
        .txt => |v| blk: {
            if (v.strings.len != b.txt.strings.len) break :blk false;
            for (v.strings, b.txt.strings) |x, y| if (!std.ascii.eqlIgnoreCase(x, y)) break :blk false;
            break :blk true;
        },
        .ds => |v| v.key_tag == b.ds.key_tag and v.algorithm == b.ds.algorithm and v.digest_type == b.ds.digest_type and mem.eql(u8, v.digest, b.ds.digest),
        .nsec => |v| v.next_domain_name.eql(b.nsec.next_domain_name) and mem.eql(u8, v.type_bit_maps, b.nsec.type_bit_maps),
        .dnskey => |v| v.flags == b.dnskey.flags and v.algorithm == b.dnskey.algorithm and mem.eql(u8, v.public_key, b.dnskey.public_key),
        .nsec3 => |v| v.hash_algorithm == b.nsec3.hash_algorithm and v.flags == b.nsec3.flags and v.iterations == b.nsec3.iterations and
            mem.eql(u8, v.salt, b.nsec3.salt) and mem.eql(u8, v.next_hashed_owner, b.nsec3.next_hashed_owner) and mem.eql(u8, v.type_bit_maps, b.nsec3.type_bit_maps),
        .named => |v| blk: {
            if (!mem.eql(u8, v.head, b.named.head) or v.names.len != b.named.names.len) break :blk false;
            for (v.names, b.named.names) |x, y| if (!x.eql(y)) break :blk false;
            break :blk true;
        },
        // A scenario cannot spell a signature minted at run time.
        .rrsig => |v| v.type_covered == b.rrsig.type_covered and v.algorithm == b.rrsig.algorithm and v.labels == b.rrsig.labels and v.signer_name.eql(b.rrsig.signer_name),
        .unknown => |v| std.ascii.eqlIgnoreCase(v, b.unknown),
    };
}

// ── Query-log checks ───────────────────────────────────────────────────

fn rowMatches(rec: sim.LogRow, want: rpl.QueryLogRow) bool {
    if (!rec.qname.eql(want.qname) or rec.qtype != want.qtype) return false;
    if (want.dest) |d| if (!na.ipEqual(rec.server, d)) return false;
    return true;
}

/// Presence of every row, or an ordered subsequence under `MATCH order`.
fn queryLogMismatch(log: []const sim.LogRow, e: rpl.Entry) ?[]const u8 {
    if (e.query_log.len == 0) return "CHECK_QUERY_LOG entry has no rows";
    if (e.match.order) {
        var pos: usize = 0;
        for (e.query_log) |want| {
            while (pos < log.len and !rowMatches(log[pos], want)) pos += 1;
            if (pos == log.len) return "query log order mismatch";
            pos += 1;
        }
        return null;
    }
    for (e.query_log) |want| {
        var found = false;
        for (log) |rec| found = found or rowMatches(rec, want);
        if (!found) return "query log missing a row";
    }
    return null;
}

fn outQueryMismatch(rec: sim.LogRow, e: rpl.Entry) ?[]const u8 {
    if (e.questions.len == 0) return "CHECK_OUT_QUERY entry has no QUESTION";
    var m = e.match;
    if (m.isEmpty()) m.question = true;
    const eq = e.questions[0];
    if ((m.question or m.qname) and !rec.qname.eql(eq.name)) return "out query qname mismatch";
    if ((m.question or m.qtype) and rec.qtype != eq.qtype) return "out query qtype mismatch";
    return null;
}

// ── The suite ──────────────────────────────────────────────────────────

const Replayed = struct { parsed: usize, failed: usize, tally: graph.Tally = .{}, cells: usize = 0, scenarios: usize = 0, compared: usize = 0, departed: usize = 0, fired: Fired = .initFill(0) };

/// One scenario under every seed, each run twice.
const Job = struct {
    path: []const u8,
    scenario: rpl.Scenario,
    seeds: u64,
    expect_fail: bool,
    failed: bool = false,
    tally: graph.Tally = .{},
    cells: usize = 0,
    compared: u32 = 0,
    departed: u32 = 0,
    fired: Fired = .initFill(0),
};

/// Replay every scenario under `root` across `seeds`, checking
/// that one seed replays to one upstream query log. Scenarios share
/// nothing, so debug spreads them over every core.
fn replayDir(root: []const u8, seeds: u64, xfail: []const []const u8) !Replayed {
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch return error.SkipZigTest;
    defer dir.close(io);
    var walker = try dir.walk(testing.allocator);
    defer walker.deinit();
    var r: Replayed = .{ .parsed = 0, .failed = 0 };
    var jobs: std.ArrayList(Job) = .empty;
    while (try walker.next(io)) |ent| {
        if (ent.kind != .file or !mem.endsWith(u8, ent.basename, ".rpl")) continue;
        const text = try dir.readFileAlloc(io, ent.path, arena, .limited(1 << 20));
        var diag: rpl.Diag = .{};
        const scenario = rpl.parse(arena, text, &diag) catch |err| switch (err) {
            error.UnsupportedRType => continue,
            else => {
                std.debug.print("{s}/{s}:{d}: {s}\n", .{ root, ent.path, diag.line, diag.msg });
                return err;
            },
        };
        r.parsed += 1;
        var expect_fail = false;
        for (xfail) |x| expect_fail = expect_fail or mem.eql(u8, x, ent.basename);
        const path = try arena.dupe(u8, ent.path);
        try jobs.append(arena, .{ .path = path, .scenario = scenario, .seeds = seeds, .expect_fail = expect_fail });
    }
    var next: std.atomic.Value(usize) = .init(0);
    var leaked: std.atomic.Value(bool) = .init(false);
    // Release runs time the model: one thread, so the numbers compare.
    const cpus = if (@import("builtin").mode == .debug) std.Thread.getCpuCount() catch 1 else 1;
    const threads = try arena.alloc(std.Thread, @min(jobs.items.len, cpus) -| 1);
    for (threads) |*t| t.* = try std.Thread.spawn(.{}, replayJobs, .{ jobs.items, &next, &leaked });
    replayJobs(jobs.items, &next, &leaked);
    for (threads) |t| t.join();
    for (jobs.items) |j| {
        inline for (@typeInfo(graph.Tally).@"struct".field_names) |f| @field(r.tally, f) += @field(j.tally, f);
        r.cells += j.cells;
        r.scenarios += j.seeds;
        r.failed += @intFromBool(j.failed);
        r.compared += j.compared;
        r.departed += j.departed;
        for (&r.fired.values, j.fired.values) |*a, b| a.* += b;
    }
    if (leaked.load(.monotonic)) r.failed += 1;
    // Debug numbers mean nothing.
    if (@import("builtin").mode == .debug) return r;
    const t = r.tally;
    std.debug.print("  chaos compared {d} answers; {d} more were past the reference's world\n", .{ r.compared, r.departed });
    std.debug.print("  chaos fired", .{});
    var fired = r.fired;
    var it = fired.iterator();
    while (it.next()) |e| std.debug.print(" {t} {d}", .{ e.key, e.value.* });
    std.debug.print("\n", .{});
    std.debug.print("  {d} cycle checks walked {d} cells ({d:.1} each) over {d} cell slots\n", .{ t.reaches, t.reaches_visits, @as(f64, @floatFromInt(t.reaches_visits)) / @as(f64, @floatFromInt(@max(t.reaches, 1))), r.cells });
    std.debug.print("  {d} runs ended waiting ({d} ns each, {d} ns per settlement)\n", .{ t.reruns, t.rerun_ns / @max(t.reruns, 1), t.rerun_ns / @max(t.settles, 1) });
    std.debug.print("{s}: {d} runs / {d} settles = {d:.2} runs per settlement; {d} ns of model per settlement (rules {d}, less {d} building queries, {d} verifying and {d} in the store) vs {d} ns per parse; {d:.0} cells per run\n", .{
        root,
        t.runs,
        t.settles,
        @as(f64, @floatFromInt(t.runs)) / @as(f64, @floatFromInt(@max(t.settles, 1))),
        (t.rule_ns -| t.send_ns -| t.verify_ns -| t.store_ns) / @max(t.settles, 1),
        t.rule_ns / @max(t.settles, 1),
        t.send_ns / @max(t.settles, 1),
        t.verify_ns / @max(t.settles, 1),
        t.store_ns / @max(t.settles, 1),
        t.parse_ns / @max(t.parses, 1),
        @as(f64, @floatFromInt(r.cells)) / @as(f64, @floatFromInt(@max(r.scenarios, 1))),
    });
    return r;
}

/// Take jobs until none are left. Debug catches leaks per thread, without
/// stack traces: each unwinds under a lock every thread shares. A leak's
/// site shows under -Dscenario, on testing.allocator. The tally wants the
/// production allocator.
fn replayJobs(jobs: []Job, next: *std.atomic.Value(usize), leaked: *std.atomic.Value(bool)) void {
    const debug = @import("builtin").mode == .debug;
    var da: std.heap.DebugAllocator(.{ .thread_safe = false, .stack_trace_frames = 0 }) = .init;
    defer if (debug and da.deinit() == .leak) leaked.store(true, .monotonic);
    const gpa = if (debug) da.allocator() else std.heap.smp_allocator;
    while (true) {
        const i = next.fetchAdd(1, .monotonic);
        if (i >= jobs.len) return;
        replayJob(gpa, &jobs[i]);
    }
}

fn replayJob(gpa: Allocator, j: *Job) void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var mint = sign.Mint.init(arena_state.allocator(), &j.scenario) catch |err| {
        j.failed = true;
        std.debug.print("{s}: keys: {t}\n", .{ j.path, err });
        return;
    };
    var seed: u64 = 1;
    while (seed <= j.seeds) : (seed += 1) replaySeed(gpa, j, &mint, seed);
}

fn replaySeed(gpa: Allocator, j: *Job, mint: *sign.Mint, seed: u64) void {
    var first: Report = .{};
    defer first.deinit(gpa);
    const result = runScenario(gpa, &j.scenario, mint, .{ .seed = seed }, &first);
    inline for (@typeInfo(graph.Tally).@"struct".field_names) |f| @field(j.tally, f) += @field(first.tally, f);
    j.cells += first.cells;
    if (j.expect_fail) {
        if (result) |_| {
            j.failed = true;
            std.debug.print("{s} (seed {d}): passed but is marked xfail\n", .{ j.path, seed });
        } else |_| {}
        return;
    }
    result catch |err| {
        j.failed = true;
        std.debug.print("{s} (seed {d}): {t} step {d}: {s} ({s})\n{s}", .{ j.path, seed, first.phase, first.step, first.msg, @errorName(err), first.log });
        return;
    };
    var second: Report = .{};
    defer second.deinit(gpa);
    runScenario(gpa, &j.scenario, mint, .{ .seed = seed }, &second) catch {};
    if (first.schedule != second.schedule or !mem.eql(u8, first.log, second.log)) {
        j.failed = true;
        std.debug.print("{s} (seed {d}): two runs, two schedules\n", .{ j.path, seed });
    }
    var chaotic: Report = .{};
    defer chaotic.deinit(gpa);
    defer {
        j.compared += chaotic.compared;
        j.departed += chaotic.departed;
        for (&j.fired.values, chaotic.fired.values) |*a, b| a.* += b;
    }
    const held: Options = .{ .seed = seed, .chaos = seed, .reference = first.answers.items, .known = &first.heard };
    runScenario(gpa, &j.scenario, mint, held, &chaotic) catch |err| {
        j.failed = true;
        std.debug.print("{s} (seed {d}, chaos): {t} step {d}: {s} ({s})\n{s}", .{ j.path, seed, chaotic.phase, chaotic.step, chaotic.msg, @errorName(err), chaotic.log });
        shrink(gpa, &j.scenario, mint, held, &chaotic) catch |e| std.debug.print("  shrinking failed: {t}\n", .{e});
    };
}

/// The fewest of a failing chaos run's decisions that fail it the same
/// way, by delta debugging (Zeller and Hildebrandt) over the decisions
/// that left hark's own; each try replays with only some of them taken.
fn shrink(gpa: Allocator, scenario: *const rpl.Scenario, mint: *sign.Mint, held: Options, failed: *const Report) !void {
    const Try = struct {
        gpa: Allocator,
        scenario: *const rpl.Scenario,
        mint: *sign.Mint,
        held: Options,
        failed: *const Report,

        fn fails(t: @This(), decisions: []const u64, named: ?*Report) !bool {
            var only: chaos.Events = .empty;
            defer only.deinit(t.gpa);
            for (decisions) |d| try only.put(t.gpa, d, {});
            var opts = t.held;
            opts.only = &only;
            opts.tell = named != null;
            var r: Report = .{};
            defer r.deinit(t.gpa);
            defer if (named) |n| mem.swap(Report, n, &r);
            runScenario(t.gpa, t.scenario, t.mint, opts, &r) catch {};
            return r.msg.len > 0 and r.phase == t.failed.phase and r.step == t.failed.step and mem.eql(u8, r.msg, t.failed.msg);
        }
    };
    const t: Try = .{ .gpa = gpa, .scenario = scenario, .mint = mint, .held = held, .failed = failed };
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const all = failed.left.keys();
    if (!try t.fails(all, null)) return std.debug.print("  chaos run does not fail again: not reproducible\n", .{});
    if (try t.fails(&.{}, null)) return std.debug.print("  fails with no decision left to chaos\n", .{});
    var cur: []const u64 = all;
    var n: usize = 2;
    while (cur.len >= 2) {
        const size = (cur.len + n - 1) / n;
        var reduced = false;
        var at: usize = 0;
        while (at < cur.len and !reduced) : (at += size) {
            const part = cur[at..@min(at + size, cur.len)];
            if (try t.fails(part, null)) {
                cur = part;
                n = 2;
                reduced = true;
            } else if (n > 2) {
                const rest = try mem.concat(arena, u64, &.{ cur[0..at], cur[@min(at + size, cur.len)..] });
                if (try t.fails(rest, null)) {
                    cur = rest;
                    n -= 1;
                    reduced = true;
                }
            }
        }
        if (!reduced) {
            if (n >= cur.len) break;
            n = @min(n * 2, cur.len);
        }
    }
    var named: Report = .{};
    defer named.deinit(gpa);
    _ = try t.fails(cur, &named);
    std.debug.print("  shrunk to {d} of {d} chaos decisions:\n", .{ cur.len, all.len });
    for (named.told.items) |line| std.debug.print("    {s}\n", .{line});
}

// `zig build test -Dscenario=path/to/x.rpl` replays one scenario with
// every completion printed, the build passing the path as HARK_SCENARIO.
test "trace one scenario" {
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const env = testing.environ;
    const path = env.getPosix("HARK_SCENARIO") orelse return error.SkipZigTest;
    const seed = if (env.getPosix("HARK_SEED")) |v| try std.fmt.parseInt(u64, v, 10) else 1;
    const chaotic = env.getPosix("HARK_CHAOS") != null;
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20));
    var diag: rpl.Diag = .{};
    const scenario = try rpl.parse(arena, text, &diag);
    var report: Report = .{};
    defer report.deinit(testing.allocator);
    var mint = try sign.Mint.init(arena, &scenario);
    var reference: Report = .{};
    defer reference.deinit(testing.allocator);
    if (chaotic) try runScenario(testing.allocator, &scenario, &mint, .{ .seed = seed }, &reference);
    const opts: Options = if (chaotic)
        .{ .seed = seed, .trace = true, .chaos = seed, .reference = reference.answers.items, .known = &reference.heard }
    else
        .{ .seed = seed, .trace = true };
    const result = runScenario(testing.allocator, &scenario, &mint, opts, &report);
    std.debug.print("{t} step {d}: {s}\n{s}", .{ report.phase, report.step, report.msg, report.log });
    try result;
}

test "hark walk scenarios settle to today's answers" {
    const r = try replayDir("test/scenarios/hark", 8, &.{});
    try testing.expectEqual(221, r.parsed);
    try testing.expectEqual(0, r.failed);
    // A site that never leaves hark's own choice tests nothing.
    var fired = r.fired;
    var it = fired.iterator();
    while (it.next()) |e| if (e.value.* == 0) {
        std.debug.print("chaos site {t} never fired\n", .{e.key});
        return error.TestUnexpectedResult;
    };
}

// Divergences from Unbound, strict: a pass is a note in
// test/corpus/unbound/DIVERGENCES.md to revisit.
test "lifted unbound walk scenarios settle to today's answers" {
    const r = try replayDir("test/corpus/unbound", 4, &.{
        "iter_resolve_minimised.rpl",
        "iter_resolve_minimised_timeout.rpl",
        "iter_cycle_noh.rpl",
        "iter_dname_insec.rpl",
        "iter_dname_ttl.rpl",
        "iter_dname_ttl0.rpl",
        "iter_domain_sale.rpl",
        "iter_domain_sale_nschange.rpl",
        "iter_cname_nx.rpl",
    });
    try testing.expectEqual(18, r.parsed);
    try testing.expectEqual(0, r.failed);
}

/// ns1 (127.0.10.3) listens nowhere, ns2 (127.0.10.4) answers.
const siblings_rpl =
    \\; hark: root-hints = 127.0.10.1
    \\SCENARIO_BEGIN hedge
    \\RANGE_BEGIN 0 100
    \\  ADDRESS 127.0.10.1
    \\  ENTRY_BEGIN
    \\    MATCH opcode qname
    \\    ADJUST copy_id copy_query
    \\    REPLY QR NOERROR
    \\    SECTION QUESTION
    \\      com. IN A
    \\    SECTION AUTHORITY
    \\      com. 86400 IN NS a.gtld.fake.
    \\    SECTION ADDITIONAL
    \\      a.gtld.fake. 86400 IN A 127.0.10.2
    \\  ENTRY_END
    \\RANGE_END
    \\RANGE_BEGIN 0 100
    \\  ADDRESS 127.0.10.2
    \\  ENTRY_BEGIN
    \\    MATCH opcode qname
    \\    ADJUST copy_id copy_query
    \\    REPLY QR NOERROR
    \\    SECTION QUESTION
    \\      example.com. IN A
    \\    SECTION AUTHORITY
    \\      example.com. 86400 IN NS ns1.example.com.
    \\      example.com. 86400 IN NS ns2.example.com.
    \\    SECTION ADDITIONAL
    \\      ns1.example.com. 86400 IN A 127.0.10.3
    \\      ns2.example.com. 86400 IN A 127.0.10.4
    \\  ENTRY_END
    \\RANGE_END
    \\RANGE_BEGIN 0 100
    \\  ADDRESS 127.0.10.4
    \\  ENTRY_BEGIN
    \\    MATCH opcode qname qtype
    \\    ADJUST copy_id copy_query
    \\    REPLY QR AA NOERROR
    \\    SECTION QUESTION
    \\      www.example.com. IN A
    \\    SECTION ANSWER
    \\      www.example.com. 60 IN A 10.20.30.40
    \\  ENTRY_END
    \\RANGE_END
    \\STEP 1 QUERY
    \\ENTRY_BEGIN
    \\  REPLY RD
    \\  SECTION QUESTION
    \\    www.example.com. IN A
    \\ENTRY_END
    \\SCENARIO_END
;

/// ns1 (127.0.10.3) is glued and listens nowhere. ns2 (127.0.10.4), which
/// answers, and ns3 (127.0.10.6), which listens nowhere, are reached only
/// once their own zone gives their addresses.
const unglued_rpl =
    \\; hark: root-hints = 127.0.10.1
    \\SCENARIO_BEGIN outranked
    \\RANGE_BEGIN 0 100
    \\  ADDRESS 127.0.10.1
    \\  ENTRY_BEGIN
    \\    MATCH opcode qname
    \\    ADJUST copy_id copy_query
    \\    REPLY QR NOERROR
    \\    SECTION QUESTION
    \\      com. IN A
    \\    SECTION AUTHORITY
    \\      com. 86400 IN NS a.gtld.fake.
    \\    SECTION ADDITIONAL
    \\      a.gtld.fake. 86400 IN A 127.0.10.2
    \\  ENTRY_END
    \\RANGE_END
    \\RANGE_BEGIN 0 100
    \\  ADDRESS 127.0.10.2
    \\  ENTRY_BEGIN
    \\    MATCH opcode qname
    \\    ADJUST copy_id copy_query
    \\    REPLY QR NOERROR
    \\    SECTION QUESTION
    \\      example.com. IN A
    \\    SECTION AUTHORITY
    \\      example.com. 86400 IN NS ns1.example.com.
    \\      example.com. 86400 IN NS ns2.hosts.com.
    \\      example.com. 86400 IN NS ns3.hosts.com.
    \\    SECTION ADDITIONAL
    \\      ns1.example.com. 86400 IN A 127.0.10.3
    \\  ENTRY_END
    \\  ENTRY_BEGIN
    \\    MATCH opcode qname
    \\    ADJUST copy_id copy_query
    \\    REPLY QR NOERROR
    \\    SECTION QUESTION
    \\      hosts.com. IN A
    \\    SECTION AUTHORITY
    \\      hosts.com. 86400 IN NS ns.hosts.com.
    \\    SECTION ADDITIONAL
    \\      ns.hosts.com. 86400 IN A 127.0.10.5
    \\  ENTRY_END
    \\RANGE_END
    \\RANGE_BEGIN 0 100
    \\  ADDRESS 127.0.10.5
    \\  ENTRY_BEGIN
    \\    MATCH opcode qname qtype
    \\    ADJUST copy_id copy_query
    \\    REPLY QR AA NOERROR
    \\    SECTION QUESTION
    \\      ns2.hosts.com. IN A
    \\    SECTION ANSWER
    \\      ns2.hosts.com. 86400 IN A 127.0.10.4
    \\  ENTRY_END
    \\  ENTRY_BEGIN
    \\    MATCH opcode qname qtype
    \\    ADJUST copy_id copy_query
    \\    REPLY QR AA NOERROR
    \\    SECTION QUESTION
    \\      ns3.hosts.com. IN A
    \\    SECTION ANSWER
    \\      ns3.hosts.com. 86400 IN A 127.0.10.6
    \\  ENTRY_END
    \\  ENTRY_BEGIN
    \\    MATCH opcode qtype
    \\    ADJUST copy_id copy_query
    \\    REPLY QR AA NOERROR
    \\    SECTION QUESTION
    \\      hosts.com. IN AAAA
    \\    SECTION AUTHORITY
    \\      hosts.com. 3600 IN SOA ns.hosts.com. h.hosts.com. 1 3600 600 86400 3600
    \\  ENTRY_END
    \\RANGE_END
    \\RANGE_BEGIN 0 100
    \\  ADDRESS 127.0.10.4
    \\  ENTRY_BEGIN
    \\    MATCH opcode qname qtype
    \\    ADJUST copy_id copy_query
    \\    REPLY QR AA NOERROR
    \\    SECTION QUESTION
    \\      www.example.com. IN A
    \\    SECTION ANSWER
    \\      www.example.com. 60 IN A 10.20.30.40
    \\  ENTRY_END
    \\RANGE_END
    \\STEP 1 QUERY
    \\ENTRY_BEGIN
    \\  REPLY RD
    \\  SECTION QUESTION
    \\    www.example.com. IN A
    \\ENTRY_END
    \\SCENARIO_END
;

const Siblings = struct {
    ns1: ?ns_rtt.RttState = null,
    ns2: ?ns_rtt.RttState = null,
};

/// Times in ms from the start: the answer, then when each sibling was
/// first asked; the estimates are read after the drain.
const Walked = struct {
    took_ms: i64,
    ns1_ms: ?i64,
    ns2_ms: ?i64,
    ns3_ms: ?i64,
    ns1: ?ns_rtt.RttState,
    ns2: ?ns_rtt.RttState,
};

/// Checks the walk answers, then that the graph drains as exchanges settle.
fn walkSiblings(arena: Allocator, seed: u64, stagger_ms: u32, planted: Siblings) !Walked {
    return walk(arena, siblings_rpl, seed, stagger_ms, planted);
}

fn walk(arena: Allocator, text: []const u8, seed: u64, stagger_ms: u32, planted: Siblings) !Walked {
    var diag: rpl.Diag = .{};
    const scenario = try rpl.parse(arena, text, &diag);
    const q = scenario.steps[0].entry.?.questions[0];
    const ns1 = na.AddressKey.fromAddress(na.initIp4(.{ 127, 0, 10, 3 }, 53));
    const ns2 = na.AddressKey.fromAddress(na.initIp4(.{ 127, 0, 10, 4 }, 53));
    const ns3 = na.AddressKey.fromAddress(na.initIp4(.{ 127, 0, 10, 6 }, 53));
    var mint = try sign.Mint.init(arena, &scenario);
    var s = try sim.Sim.init(arena, testing.allocator, &scenario, &mint, seed);
    defer s.deinit();
    var g = try graph.Graph.init(testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true }, .stagger_ms = stagger_ms }, s.edge());
    defer g.deinit();
    if (planted.ns1) |e| try g.rtt.put(testing.allocator, ns1, e);
    if (planted.ns2) |e| try g.rtt.put(testing.allocator, ns2, e);
    const start = s.now_ns;
    const horizon = start + 10 * std.time.ns_per_s;
    var ns1_ms: ?i64 = null;
    var ns2_ms: ?i64 = null;
    var ns3_ms: ?i64 = null;
    const root = try g.demandRoot(q.name, q.qtype, .new);
    try g.drain();
    while (!g.cell(root).settled()) {
        const ev = s.next(horizon) orelse return error.TestUnexpectedResult;
        try g.complete(ev.id, ev.completion);
        const at_ms = @divTrunc(s.now_ns - start, std.time.ns_per_ms);
        for (s.log.items) |row| {
            const key = na.AddressKey.fromAddress(row.server);
            if (key.eql(ns1) and ns1_ms == null) ns1_ms = at_ms;
            if (key.eql(ns2) and ns2_ms == null) ns2_ms = at_ms;
            if (key.eql(ns3) and ns3_ms == null) ns3_ms = at_ms;
        }
    }
    try testing.expectEqual(.answer, g.cell(g.cell(root).state.fact.answer.hops[0].set).state.fact.rrset.kind);
    g.unhold(root);
    const took_ms = @divTrunc(s.now_ns - start, std.time.ns_per_ms);
    while (s.next(horizon)) |ev| try g.complete(ev.id, ev.completion);
    try testing.expectEqual(0, g.live);
    return .{ .took_ms = took_ms, .ns1_ms = ns1_ms, .ns2_ms = ns2_ms, .ns3_ms = ns3_ms, .ns1 = g.rtt.get(ns1), .ns2 = g.rtt.get(ns2) };
}

/// srtt 1.5 s: a 3 s estimate, past the 2 s cap.
const dead: ns_rtt.RttState = .{ .srtt_us = 1500 * std.time.us_per_ms, .consecutive_timeouts = 4, .dead_until_ms = std.math.maxInt(i64) };

const silent: ns_rtt.RttState = .{ .srtt_us = 400 * std.time.us_per_ms, .consecutive_timeouts = 1 };

const far: ns_rtt.RttState = .{ .srtt_us = 160 * std.time.us_per_ms, .min_rtt_us = 160 * std.time.us_per_ms };

test "a silent sibling is hedged past and still records its timeout" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    // Cold, ns1 gets 400 ms and the hedge asks ns2 at 150.
    var ns1_first_seen = false;
    for (1..9) |seed| for ([_]u32{ 150, 0 }) |stagger| {
        const w = try walkSiblings(arena_state.allocator(), seed, stagger, .{});
        const ns1_first = w.ns1_ms != null and (w.ns2_ms == null or w.ns1_ms.? < w.ns2_ms.?);
        ns1_first_seen = ns1_first_seen or ns1_first;
        try testing.expect(w.ns2 != null);
        if (ns1_first) try testing.expectEqual(1, w.ns1.?.consecutive_timeouts) else try testing.expect(w.ns1 == null);
        if (stagger > 0) {
            // Walk (≤ 2 × 50 ms), the stagger, then ns2 (≤ 50 ms).
            try testing.expect(w.took_ms < 400);
            if (ns1_first) try testing.expect(w.took_ms >= 150);
        } else if (ns1_first) try testing.expect(w.took_ms >= 400);
    };
    try testing.expect(ns1_first_seen);
}

test "a dead server is asked only when nothing live is left" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    for (1..9) |seed| for ([_]bool{ false, true }) |all_dead| {
        const w = try walkSiblings(arena_state.allocator(), seed, 0, .{ .ns1 = dead, .ns2 = if (all_dead) dead else null });
        if (!all_dead) try testing.expect(w.ns1_ms == null);
    };
}

test "the last live server waits its whole estimate, unhedged" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    // srtt 1.5 s: a 3 s estimate.
    for (1..9) |seed| {
        const w = try walkSiblings(arena_state.allocator(), seed, 150, .{ .ns1 = .{ .srtt_us = 1500 * std.time.us_per_ms }, .ns2 = dead });
        try testing.expect(w.ns2_ms.? - w.ns1_ms.? >= 3000);
    }
}

test "servers all dead are hedged through like any list" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    // One stagger, not the 2 s cap.
    var ns1_first_seen = false;
    for (1..9) |seed| {
        const w = try walkSiblings(arena_state.allocator(), seed, 150, .{ .ns1 = dead, .ns2 = dead });
        if (w.ns1_ms == null or w.ns2_ms.? < w.ns1_ms.?) continue;
        ns1_first_seen = true;
        try testing.expect(w.ns2_ms.? - w.ns1_ms.? >= 150);
        try testing.expect(w.ns2_ms.? - w.ns1_ms.? < 500);
    }
    try testing.expect(ns1_first_seen);
}

test "a server never timed is asked as readily as the best that answers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var first: [2]bool = @splat(false);
    for (1..9) |seed| {
        const w = try walkSiblings(arena_state.allocator(), seed, 150, .{ .ns2 = far });
        first[@intFromBool(w.ns1_ms == null or w.ns2_ms.? < w.ns1_ms.?)] = true;
    }
    try testing.expectEqual(.{ true, true }, first);
}

test "a hedge goes to a server that answers before one never timed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // ns1 at a second address, 127.0.10.6, where nothing listens either.
    const glue = "ns1.example.com. 86400 IN A 127.0.10.3";
    const text = try mem.replaceOwned(u8, arena, siblings_rpl, glue, glue ++ "\n ns1.example.com. 86400 IN A 127.0.10.6");
    var hedged = false;
    for (1..9) |seed| {
        const w = try walk(arena, text, seed, 150, .{ .ns2 = far });
        if (w.ns1_ms == null and w.ns3_ms == null) continue;
        hedged = true;
        try testing.expect(w.ns1_ms == null or w.ns3_ms == null);
    }
    try testing.expect(hedged);
}

test "a server that has only been silent holds back no other, one never timed does" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var both_seen = false;
    for (1..9) |seed| {
        const w = try walk(arena_state.allocator(), unglued_rpl, seed, 150, .{ .ns1 = silent });
        // ns1 is all there is to ask at first: the lookups for the others
        // start, and the first address to land is asked, with no stagger.
        const next = @min(w.ns2_ms.?, w.ns3_ms orelse w.ns2_ms.?);
        try testing.expect(next - w.ns1_ms.? < 150);
        const ns3_ms = w.ns3_ms orelse continue;
        both_seen = true;
        try testing.expect(@abs(w.ns2_ms.? - ns3_ms) >= 150);
    }
    try testing.expect(both_seen);
}

test "the door counts exchanges in flight" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diag: rpl.Diag = .{};
    const scenario = try rpl.parse(arena,
        \\; hark: root-hints = 127.0.10.1
        \\SCENARIO_BEGIN admission
        \\RANGE_BEGIN 0 100
        \\  ADDRESS 127.0.10.1
        \\  ENTRY_BEGIN
        \\    MATCH opcode
        \\    ADJUST copy_id copy_query
        \\    REPLY QR AA NOERROR
        \\    SECTION QUESTION
        \\      www.example.com. IN A
        \\    SECTION ANSWER
        \\      www.example.com. 60 IN A 10.20.30.40
        \\  ENTRY_END
        \\RANGE_END
        \\STEP 1 QUERY
        \\ENTRY_BEGIN
        \\  REPLY RD
        \\  SECTION QUESTION
        \\    www.example.com. IN A
        \\ENTRY_END
        \\SCENARIO_END
    , &diag);
    const q = scenario.steps[0].entry.?.questions[0];
    const other = try dns.parseDottedName(arena, "other.example.com.");
    var mint = try sign.Mint.init(arena, &scenario);
    var s = try sim.Sim.init(arena, testing.allocator, &scenario, &mint, 1);
    defer s.deinit();
    var g = try graph.Graph.init(testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true }, .max_flights = 1 }, s.edge());
    defer g.deinit();
    const root = try g.demandRoot(q.name, q.qtype, .new);
    try g.drain();
    try testing.expectEqual(1, g.budgets);
    try testing.expectEqual(1, g.flights);
    // New work is turned away; the same question joins the one in progress.
    try testing.expectError(error.Full, g.demandRoot(other, .a, .new));
    try testing.expectEqual(root, try g.demandRoot(q.name, q.qtype, .new));
    while (s.next(s.now_ns + 10 * std.time.ns_per_s)) |ev| try g.complete(ev.id, ev.completion);
    try testing.expectEqual(0, g.flights);
    g.unhold(root);
    g.unhold(root);
    try testing.expectEqual(0, g.live);
    try testing.expectEqual(0, g.budgets);
}

test "an exchange that never left the host writes no estimate" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diag: rpl.Diag = .{};
    const scenario = try rpl.parse(arena,
        \\; hark: root-hints = 127.0.10.1
        \\SCENARIO_BEGIN unsent
        \\RANGE_BEGIN 0 100
        \\  ADDRESS 127.0.10.1
        \\  ENTRY_BEGIN
        \\    MATCH opcode
        \\    ADJUST copy_id copy_query
        \\    REPLY QR AA NOERROR
        \\    SECTION QUESTION
        \\      www.example.com. IN A
        \\    SECTION ANSWER
        \\      www.example.com. 60 IN A 10.20.30.40
        \\  ENTRY_END
        \\RANGE_END
        \\STEP 1 QUERY
        \\ENTRY_BEGIN
        \\  REPLY RD
        \\  SECTION QUESTION
        \\    www.example.com. IN A
        \\ENTRY_END
        \\SCENARIO_END
    , &diag);
    const q = scenario.steps[0].entry.?.questions[0];
    var mint = try sign.Mint.init(arena, &scenario);
    var s = try sim.Sim.init(arena, testing.allocator, &scenario, &mint, 1);
    defer s.deinit();
    var g = try graph.Graph.init(testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true } }, s.edge());
    defer g.deinit();
    s.pending_unsent = 1;
    const root = try g.demandRoot(q.name, q.qtype, .new);
    try g.drain();
    while (s.next(s.now_ns + 10 * std.time.ns_per_s)) |ev| try g.complete(ev.id, ev.completion);
    try testing.expect(g.cell(root).failure() == null);
    try testing.expectEqual(1, g.stats.resolver.faults.unsent);
    // Only replies wrote it: a timeout would have started it at 400 ms.
    const server = na.AddressKey.fromAddress(scenario.root_hints[0]);
    try testing.expect(g.rtt.get(server).?.srtt_us < 50 * std.time.us_per_ms);
    g.unhold(root);
}
