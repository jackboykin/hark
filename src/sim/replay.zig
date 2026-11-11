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
const model = @import("../model.zig");
const answer = @import("../answer.zig");
const response = @import("../response.zig");
const rebinding = @import("../rebinding.zig");
const config = @import("../config.zig");
const ns_rtt = @import("../ns_rtt.zig");
const chaos = @import("../chaos.zig");
const slab = @import("../slab.zig");

const Phase = enum { steps, warm };

const Fired = std.EnumArray(chaos.Site, u32);

const Report = struct {
    step: u32 = 0,
    msg: []const u8 = "",
    phase: Phase = .steps,
    log: []const u8 = "",
    schedule: u64 = 0,
    answers: std.ArrayList(Answered) = .empty,
    heard: sim.Sim.Heard = .empty,
    departed: u32 = 0,
    compared: u32 = 0,
    starved: bool = false,
    fired: Fired = .initFill(0),
    left: chaos.Events = .empty,
    told: std.ArrayList([]const u8) = .empty,

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

const Answered = struct {
    phase: Phase,
    step: u32,
    wire: []const u8,
    limited: bool,
};

const Options = struct {
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
    var g = try graph.Graph.init(gpa, gpa, .{
        .qmin = scenario.qmin orelse true,
        .root_hints = scenario.root_hints,
        .stub_zones = scenario.stub_zones,
        .addr_policy = .{ .allow_loopback = true },
        .stagger_ms = scenario.stagger_ms orelse 150,
        .max_queries = scenario.max_queries orelse 100,
        .resolve_ms = scenario.resolve_ms orelse 7000,
        .trust_anchors = s.signer.anchor(),
        .prefetch = scenario.prefetch orelse false,
        .trace = opts.trace,
    }, edge);
    defer g.deinit();
    defer {
        report.schedule = g.schedule;
    }

    const rb: rebinding.Config = .{
        .enabled = scenario.rebinding_enabled orelse false,
        .allow_zones = try config.parseZoneList(arena, scenario.rebinding_allow_zones),
        .extra_allow = try config.parseCidrList(arena, scenario.rebinding_extra_allow),
        .nat64 = scenario.dns64_prefix,
    };

    defer report.log = formatLog(gpa, s.log.items) catch "";
    var held: Held = .{};
    defer held.kept.deinit(g.gpa);
    defer letGoAll(&g, &held);
    var desk: answer.Desk = .{
        .g = &g,
        .retention = .{ .min_ttl = scenario.min_ttl orelse 0, .serve_stale_ttl = scenario.serve_stale_ttl orelse 0 },
        .dns64 = scenario.dns64_prefix,
    };
    defer desk.deinit();
    const run: Run = .{ .arena = arena, .g = &g, .s = &s, .scenario = scenario, .held = &held, .desk = &desk, .rb = &rb };
    var last: ?dns.Message = null;
    var cursor: usize = 0;
    for (scenario.steps) |st| {
        s.step = st.n;
        report.step = st.n;
        if (opts.chaos != 0) switch (st.kind) {
            .check_answer, .check_query_log, .check_out_query, .check_max_queries, .check_max_verifies, .check_max_runs => continue,
            .query, .unsent, .time_passes => {},
        };
        try runStep(gpa, run, st, opts, report, &last, &cursor);
    }
    report.phase = .warm;
    try requery(gpa, run, opts, report);
    letGoAll(&g, &held);
    while (s.next(s.now_ns + 60 * std.time.ns_per_s)) |ev| try g.complete(ev.id, ev.completion);
    if (g.live != 0 or g.budgets != 0 or g.flights != 0 or g.work.bytes != 0) {
        report.msg = "cells, budgets, flights or work bytes outlived the scenario";
        return error.ScenarioFailed;
    }
}

/// One scenario step: a question asked, a check made, or time moved.
fn runStep(gpa: Allocator, r: Run, st: rpl.Step, opts: Options, report: *Report, last: *?dns.Message, cursor: *usize) !void {
    const g = r.g;
    const s = r.s;
    switch (st.kind) {
        .query => {
            const sent = try resolveClient(r, st.entry.?);
            try answered(gpa, report, opts, s, .steps, st.n, sent);
            last.* = if (sent) |x| x.msg else null;
            if (sent == null and opts.chaos == 0 and r.scenario.client_timeout_ms == null) {
                report.msg = "client timed out";
                return error.ScenarioFailed;
            }
        },
        .check_answer => {
            const actual = last.* orelse {
                report.msg = "no answer to check";
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
            if (cursor.* >= s.log.items.len) {
                report.msg = "CHECK_OUT_QUERY past the end of the log";
                return error.ScenarioFailed;
            }
            if (outQueryMismatch(s.log.items[cursor.*], st.entry.?)) |why| {
                report.msg = why;
                return error.ScenarioFailed;
            }
            cursor.* += 1;
        },
        .check_max_queries => if (s.log.items.len > st.bound) {
            report.msg = "CHECK_MAX_QUERIES exceeded";
            return error.ScenarioFailed;
        },
        .check_max_verifies => if (g.verify_memo.misses > st.bound) {
            report.msg = "CHECK_MAX_VERIFIES exceeded";
            return error.ScenarioFailed;
        },
        .check_max_runs => if (g.runs > st.bound) {
            report.msg = "CHECK_MAX_RUNS exceeded";
            return error.ScenarioFailed;
        },
        .unsent => s.pending_unsent += 1,
        .time_passes => {
            const until = s.now_ns + @as(i64, st.seconds) * std.time.ns_per_s;
            while (s.next(until)) |ev| try g.complete(ev.id, ev.completion);
        },
    }
}

/// Every checked question, asked again of the settled graph, must answer the
/// same from memory alone, unless the answer was never a fact (TTL 0). Only a
/// question's last check counts; TTLs have aged and are not compared.
fn requery(gpa: Allocator, r: Run, opts: Options, report: *Report) !void {
    const s = r.s;
    const steps = r.scenario.steps;
    for (steps[0..steps.len -| 1], steps[1..], 0..) |query, check, i| {
        if (query.kind != .query or check.kind != .check_answer) continue;
        const q = query.entry.?.question.?;
        var superseded = false;
        for (steps[i + 2 ..]) |st| if (st.kind == .query) {
            const lq = st.entry.?.question.?;
            superseded = superseded or (lq.name.eql(q.name) and lq.qtype == q.qtype);
        };
        if (superseded) continue;
        report.step = query.n;
        const before = s.log.items.len;
        const sent = try resolveClient(r, query.entry.?);
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

/// What one scenario's replay works on.
const Run = struct {
    arena: Allocator,
    g: *graph.Graph,
    s: *sim.Sim,
    scenario: *const rpl.Scenario,
    held: *Held,
    desk: *answer.Desk,
    rb: *const rebinding.Config,
};

const Held = struct {
    roots: [2]?model.CellId = .{ null, null },
    kept: std.ArrayList(model.CellId) = .empty,
};

fn unholdAll(g: *graph.Graph, held: *Held) void {
    for (&held.roots) |*h| if (h.*) |id| {
        g.unhold(id);
        h.* = null;
    };
    var i: usize = 0;
    while (i < held.kept.items.len) {
        const id = held.kept.items[i];
        if (!g.cell(id).settled()) {
            i += 1;
            continue;
        }
        g.unhold(id);
        _ = held.kept.swapRemove(i);
    }
}

fn letGoAll(g: *graph.Graph, held: *Held) void {
    unholdAll(g, held);
    while (held.kept.pop()) |id| g.unhold(id);
}

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
    if (limited or ref.limited) {
        report.starved = report.starved or (limited and !ref.limited);
        return;
    }
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
    // Nor is there anything stale of what a limit kept chaos from hearing.
    if (report.starved and actual.header.flags.rcode == .server_failure and says(want, .stale_answer)) return;
    report.compared += 1;
    if (messageMismatch(actual, want)) |why| {
        std.debug.print("  chaos's answer, then the reference's:\n", .{});
        printSections(actual);
        printSections(want);
        report.msg = why;
        return error.ScenarioFailed;
    }
}

fn says(m: dns.Message, code: dns.Ede.Code) bool {
    const opt = m.opt orelse return false;
    for (opt.options) |o| if (o.code == dns.edns_opt_ede and o.data.len >= 2 and
        mem.readInt(u16, o.data[0..2], .big) == @backingInt(code)) return true;
    return false;
}

fn find(answers: []const Answered, phase: Phase, step: u32) ?Answered {
    for (answers) |a| if (a.phase == phase and a.step == step) return a;
    return null;
}

/// TTLs age from each run's own fetch, and a synthesized denial proves the same
/// answer with other records than the server sent: neither is compared.
fn messageMismatch(actual: dns.Message, want: dns.Message) ?[]const u8 {
    const af = actual.header.flags;
    const wf = want.header.flags;
    if (af.rcode != wf.rcode) return "chaos moved the rcode";
    if (af.aa != wf.aa or af.tc != wf.tc or af.ad != wf.ad or af.ra != wf.ra) return "chaos moved the flags";
    if (!sectionEql(actual.answers, want.answers, false)) return "chaos moved the ANSWER";
    const relayed = !says(actual, .synthesized) and !says(want, .synthesized);
    if (relayed and !sectionEql(actual.authorities, want.authorities, false)) return "chaos moved the AUTHORITY";
    if (!sectionEql(actual.additionals, want.additionals, false)) return "chaos moved the ADDITIONAL";
    if (af.rcode != .server_failure) return null;
    const a_opts: []const dns.EdnsOption = if (actual.opt) |o| o.options else &.{};
    const w_opts: []const dns.EdnsOption = if (want.opt) |o| o.options else &.{};
    if (a_opts.len != w_opts.len) return "chaos moved the EDNS options";
    for (a_opts, w_opts) |x, y| if (x.code != y.code or !mem.eql(u8, x.data, y.data)) return "chaos moved the EDNS options";
    return null;
}

/// The roots stay in `held` until the next question: the answer reads their hops.
fn resolveClient(r: Run, entry: rpl.Entry) !?Sent {
    const arena = r.arena;
    const g = r.g;
    const desk = r.desk;
    const q = entry.question.?;
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
            try agrees(r, q, client, served);
            break :blk served;
        },
        .graph => blk: {
            const built = try shapeClient(r, q, client) orelse return null;
            for (r.held.roots) |h| if (h) |id| if (answer.failureOf(g, id, client.cd)) |why| {
                limited = limited or why.cause == .asker or why.remembered;
            };
            break :blk try desk.derived(q, client, built);
        },
    };
    defer served.release(&g.store);
    const wire = try wireOf(arena, q, client, entry.do_bit or entry.edns, r.rb, served);
    return .{ .msg = try dns.parseMessage(arena, wire), .wire = wire, .cacheable = served.cacheable, .limited = limited };
}

fn wireOf(arena: Allocator, q: dns.Question, client: answer.Client, edns: bool, rb: *const rebinding.Config, served: answer.Served) ![]const u8 {
    const ctx: response.ResponseContext = .{
        .query_id = 0,
        .opcode = .query,
        .rd = client.rd,
        .cd = client.cd,
        .question = q,
        .client_edns = edns,
        .client_do = client.do_bit,
        .max_udp_payload = dns.max_message_len,
        .rebinding = rb,
    };
    return response.buildResponseWire(try arena.alloc(u8, dns.max_message_len), ctx, served.reply(), arena) orelse error.OutOfMemory;
}

/// What recall serves from the store, the graph must build too, to the byte, asking nobody.
fn agrees(r: Run, q: dns.Question, client: answer.Client, recalled: answer.Served) !void {
    const arena = r.arena;
    const g = r.g;
    const s = r.s;
    const rb = r.rb;
    const before = s.log.items.len;
    const built = try shapeClient(r, q, client) orelse return error.RecallDisagrees;
    defer built.release(&g.store);
    if (s.log.items.len != before) return error.RecallDisagrees;
    const a = try wireOf(arena, q, client, false, rb, recalled);
    const b = try wireOf(arena, q, client, false, rb, built);
    const ede_eq = if (recalled.ede) |x| if (built.ede) |y| x.code == y.code and mem.eql(u8, x.text, y.text) else false else built.ede == null;
    if (!mem.eql(u8, a, b) or !ede_eq) return error.RecallDisagrees;
}

fn shapeClient(r: Run, q: dns.Question, client: answer.Client) !?answer.Served {
    const arena = r.arena;
    const g = r.g;
    const s = r.s;
    const held = r.held;
    const desk = r.desk;
    const scenario = r.scenario;
    unholdAll(g, held);
    const deadline = s.now_ns + @as(i64, scenario.client_timeout_ms orelse 5000) * std.time.ns_per_ms;
    const asked = try desk.asked(arena, q, client);
    const root = try g.demandRoot(asked.name, asked.qtype, .new);
    held.roots[0] = root;
    try g.drain();
    const patience = s.now_ns + answer.stale_client_ms * std.time.ns_per_ms;
    if (desk.retention.serve_stale_ttl > 0 and !try settleBy(g, s, root, @min(patience, deadline))) {
        if (try desk.memory(arena, q, client, .stale)) |served| {
            errdefer served.release(&g.store);
            held.roots[0] = null;
            if (g.cell(root).holds == 1) try held.kept.append(g.gpa, root) else g.unhold(root);
            return served;
        }
    }
    if (!try settleBy(g, s, root, deadline)) return leave(g, held);
    const served = try desk.built(arena, root, q, client);
    const aq = desk.wantsA(q, client, served) orelse return try desk.finish(arena, q, client, served, null);
    const a = try g.demandRoot(aq.name, aq.qtype, .new);
    held.roots[1] = a;
    try g.drain();
    if (!try settleBy(g, s, a, deadline)) {
        served.release(&g.store);
        return leave(g, held);
    }
    return try desk.finish(arena, q, client, served, a);
}

fn leave(g: *graph.Graph, held: *Held) !?answer.Served {
    for (&held.roots) |*h| if (h.*) |id| {
        if (g.cell(id).holds == 1) try held.kept.append(g.gpa, id) else g.unhold(id);
        h.* = null;
    };
    return null;
}

fn settleBy(g: *graph.Graph, s: *sim.Sim, root: model.CellId, until: i64) !bool {
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
        if ((actual.question == null) != (e.question == null)) return "QUESTION mismatch";
        if (actual.question) |a| if (!a.name.eql(e.question.?.name) or a.qtype != e.question.?.qtype) return "QUESTION mismatch";
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

/// Multiset equality. RRSIGs in `actual` count only when `expected` carries any.
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
    if (!a.name.eql(b.name) or a.rtype != b.rtype) return false;
    if (compare_ttl and @max(a.ttl, b.ttl) - @min(a.ttl, b.ttl) > ttl_slack) return false;
    return rdataEql(a, b);
}

fn rdataEql(a: dns.ResourceRecord, b: dns.ResourceRecord) bool {
    return switch (a.rtype) {
        .nsec => blk: {
            var na_buf: dns.Name.Buf = undefined;
            var nb_buf: dns.Name.Buf = undefined;
            const x = a.nsec(&na_buf);
            const y = b.nsec(&nb_buf);
            break :blk x.next_domain_name.eql(y.next_domain_name) and mem.eql(u8, x.type_bit_maps, y.type_bit_maps);
        },
        // A scenario cannot spell a signature minted at run time.
        .rrsig => blk: {
            const x = a.rrsig();
            const y = b.rrsig();
            break :blk x.type_covered == y.type_covered and x.algorithm == y.algorithm and x.labels == y.labels and x.signer_name.eql(y.signer_name);
        },
        .a, .aaaa, .ns, .cname, .dname, .ptr, .mx, .soa, .ds, .dnskey, .nsec3, .rp, .afsdb, .rt, .kx, .px, .srv, .naptr => mem.eql(u8, a.rdata, b.rdata),
        else => std.ascii.eqlIgnoreCase(a.rdata, b.rdata),
    };
}

fn rowMatches(rec: sim.LogRow, want: rpl.QueryLogRow) bool {
    if (!rec.qname.eql(want.qname) or rec.qtype != want.qtype) return false;
    if (want.dest) |d| if (!na.ipEqual(rec.server, d)) return false;
    return true;
}

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
    const eq = e.question orelse return "CHECK_OUT_QUERY entry has no QUESTION";
    var m = e.match;
    if (m.isEmpty()) m.question = true;
    if ((m.question or m.qname) and !rec.qname.eql(eq.name)) return "out query qname mismatch";
    if ((m.question or m.qtype) and rec.qtype != eq.qtype) return "out query qtype mismatch";
    return null;
}

const Replayed = struct { parsed: usize, failed: usize, compared: usize = 0, departed: usize = 0, fired: Fired = .initFill(0) };

const Job = struct {
    path: []const u8,
    scenario: rpl.Scenario,
    seeds: u64,
    failed: bool = false,
    compared: u32 = 0,
    departed: u32 = 0,
    fired: Fired = .initFill(0),
};

fn replayDir(root: []const u8, seeds: u64) !Replayed {
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
        const scenario = rpl.parse(arena, text, &diag) catch |err| {
            std.debug.print("{s}/{s}:{d}: {s}\n", .{ root, ent.path, diag.line, diag.msg });
            return err;
        };
        r.parsed += 1;
        const path = try arena.dupe(u8, ent.path);
        try jobs.append(arena, .{ .path = path, .scenario = scenario, .seeds = seeds });
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
        r.failed += @intFromBool(j.failed);
        r.compared += j.compared;
        r.departed += j.departed;
        for (&r.fired.values, j.fired.values) |*a, b| a.* += b;
    }
    if (leaked.load(.monotonic)) r.failed += 1;
    if (@import("builtin").mode == .debug) return r;
    std.debug.print("  chaos compared {d} answers; {d} more were past the reference's world\n", .{ r.compared, r.departed });
    std.debug.print("  chaos fired", .{});
    var fired = r.fired;
    var it = fired.iterator();
    while (it.next()) |e| std.debug.print(" {t} {d}", .{ e.key, e.value.* });
    std.debug.print("\n", .{});
    return r;
}

/// Runs on the production allocator, so leaks are counted, not traced;
/// -Dscenario replays one on testing.allocator to show the site.
fn replayJobs(jobs: []Job, next: *std.atomic.Value(usize), leaked: *std.atomic.Value(bool)) void {
    var reserve: slab.Reserve = .{};
    defer reserve.deinit();
    var tenant: slab.Tenant = .init(&reserve);
    var counted: std.testing.FailingAllocator = .init(tenant.allocator(), .{});
    defer if (counted.allocated_bytes != counted.freed_bytes) {
        std.debug.print("replays leaked {d} bytes; -Dscenario shows where\n", .{counted.allocated_bytes - counted.freed_bytes});
        leaked.store(true, .monotonic);
    };
    const gpa = counted.allocator();
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

// `zig build test -Dscenario=path/to/x.rpl` runs this, the build passing
// the path as HARK_SCENARIO.
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
    const r = try replayDir("test/scenarios", 8);
    try testing.expectEqual(223, r.parsed);
    try testing.expectEqual(0, r.failed);
    var fired = r.fired;
    var it = fired.iterator();
    while (it.next()) |e| if (e.value.* == 0) {
        std.debug.print("chaos site {t} never fired\n", .{e.key});
        return error.TestUnexpectedResult;
    };
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

/// ns1 (.3) is glued and silent. ns2 (.4) answers and ns3 (.6) is silent;
/// both are reached only once hosts.com gives their addresses.
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

const Walked = struct {
    took_ms: i64,
    ns1_ms: ?i64,
    ns2_ms: ?i64,
    ns3_ms: ?i64,
    ns1: ?ns_rtt.RttState,
    ns2: ?ns_rtt.RttState,
};

fn walkSiblings(arena: Allocator, seed: u64, stagger_ms: u32, planted: Siblings) !Walked {
    return walk(arena, siblings_rpl, seed, stagger_ms, planted);
}

fn walk(arena: Allocator, text: []const u8, seed: u64, stagger_ms: u32, planted: Siblings) !Walked {
    var diag: rpl.Diag = .{};
    const scenario = try rpl.parse(arena, text, &diag);
    const q = scenario.steps[0].entry.?.question.?;
    const ns1 = na.AddressKey.fromAddress(na.initIp4(.{ 127, 0, 10, 3 }, 53));
    const ns2 = na.AddressKey.fromAddress(na.initIp4(.{ 127, 0, 10, 4 }, 53));
    const ns3 = na.AddressKey.fromAddress(na.initIp4(.{ 127, 0, 10, 6 }, 53));
    var mint = try sign.Mint.init(arena, &scenario);
    var s = try sim.Sim.init(arena, testing.allocator, &scenario, &mint, seed);
    defer s.deinit();
    var g = try graph.Graph.init(testing.allocator, testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true }, .stagger_ms = stagger_ms }, s.edge());
    defer g.deinit();
    if (planted.ns1) |e| g.rtt.write(ns1, 0).* = e;
    if (planted.ns2) |e| g.rtt.write(ns2, 0).* = e;
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
    return .{ .took_ms = took_ms, .ns1_ms = ns1_ms, .ns2_ms = ns2_ms, .ns3_ms = ns3_ms, .ns1 = if (g.rtt.get(ns1)) |e| e.* else null, .ns2 = if (g.rtt.get(ns2)) |e| e.* else null };
}

const dead: ns_rtt.RttState = .{ .consecutive_timeouts = 4, .dead_until_ms = std.math.maxInt(i64) };

const silent: ns_rtt.RttState = .{ .consecutive_timeouts = 1 };

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
    for (1..9) |seed| {
        const w = try walkSiblings(arena_state.allocator(), seed, 150, .{ .ns1 = .{ .srtt_us = 1500 * std.time.us_per_ms, .min_rtt_us = 1500 * std.time.us_per_ms }, .ns2 = dead });
        try testing.expect(w.ns2_ms.? - w.ns1_ms.? >= 3000);
    }
}

test "servers all dead are hedged through like any list" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
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
        const next = @min(w.ns2_ms.?, w.ns3_ms orelse w.ns2_ms.?);
        try testing.expect(next - w.ns1_ms.? < 150);
        const ns3_ms = w.ns3_ms orelse continue;
        both_seen = true;
        try testing.expect(@abs(w.ns2_ms.? - ns3_ms) >= 150);
    }
    try testing.expect(both_seen);
}

const one_hop_rpl =
    \\; hark: root-hints = 127.0.10.1
    \\SCENARIO_BEGIN one hop
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
;

test "the door counts exchanges in flight" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diag: rpl.Diag = .{};
    const scenario = try rpl.parse(arena, one_hop_rpl, &diag);
    const q = scenario.steps[0].entry.?.question.?;
    const other = try dns.parseDottedName(arena, "other.example.com.");
    var mint = try sign.Mint.init(arena, &scenario);
    var s = try sim.Sim.init(arena, testing.allocator, &scenario, &mint, 1);
    defer s.deinit();
    var g = try graph.Graph.init(testing.allocator, testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true }, .max_flights = 1 }, s.edge());
    defer g.deinit();
    const root = try g.demandRoot(q.name, q.qtype, .new);
    try g.drain();
    try testing.expectEqual(1, g.budgets);
    try testing.expectEqual(1, g.flights);
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
    const scenario = try rpl.parse(arena, one_hop_rpl, &diag);
    const q = scenario.steps[0].entry.?.question.?;
    var mint = try sign.Mint.init(arena, &scenario);
    var s = try sim.Sim.init(arena, testing.allocator, &scenario, &mint, 1);
    defer s.deinit();
    var g = try graph.Graph.init(testing.allocator, testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true } }, s.edge());
    defer g.deinit();
    s.pending_unsent = 1;
    const root = try g.demandRoot(q.name, q.qtype, .new);
    try g.drain();
    const unsent = s.next(s.now_ns + 10 * std.time.ns_per_s).?;
    try g.complete(unsent.id, unsent.completion);
    try testing.expectEqual(1, g.stats.resolver.faults.unsent);
    const server = na.AddressKey.fromAddress(scenario.root_hints[0]);
    try testing.expectEqual(null, g.rtt.get(server));
    while (s.next(s.now_ns + 10 * std.time.ns_per_s)) |ev| try g.complete(ev.id, ev.completion);
    try testing.expect(g.cell(root).failure() == null);
    g.unhold(root);
}
