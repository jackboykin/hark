//! Replay a `.rpl` scenario against the graph in the simulator: the
//! graph's test suite. Mirrors test/conftest.py `_run_steps` and test/harness/client.py.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;
const dns = @import("../dns.zig");
const na = @import("../net_address.zig");
const rpl = @import("rpl.zig");
const sim = @import("sim.zig");
const graph = @import("../graph.zig");
const answer = @import("../answer.zig");
const response = @import("../response.zig");
const rebinding = @import("../rebinding.zig");
const config = @import("../config.zig");

pub const Report = struct {
    /// The failing step and why.
    step: u32 = 0,
    msg: []const u8 = "",
    phase: enum { steps, warm } = .steps,
    /// The upstream query log, one `server <- qname qtype` per line,
    /// gpa-owned. Two runs of one seed must produce the same text.
    log: []const u8 = "",
    tally: graph.Tally = .{},
    cells: usize = 0,
};

pub const Options = struct {
    seed: u64 = 1,
    trace: bool = false,
};

fn runScenario(gpa: Allocator, scenario: *const rpl.Scenario, opts: Options, report: *Report) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var s = try sim.Sim.init(arena, gpa, scenario, opts.seed);
    defer s.deinit();
    var g = try graph.Graph.init(gpa, .{
        .qmin = scenario.qmin orelse true,
        .root_hints = scenario.root_hints,
        .addr_policy = .{ .allow_loopback = true },
        .stagger_ms = scenario.stagger_ms orelse 150,
        .max_queries = scenario.max_queries orelse 100,
        .trust_anchor = s.signer.anchor(),
        .prefetch = scenario.prefetch orelse false,
        .trace = opts.trace,
    }, s.edge());
    defer g.deinit();
    defer {
        report.tally = g.tally;
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
        switch (st.kind) {
            .query => last = (try resolveClient(arena, &g, &s, scenario, st.entry.?, &held, &desk, &rb) orelse {
                report.msg = "client timed out";
                return error.ScenarioFailed;
            }).msg,
            .check_answer => {
                const actual = last orelse {
                    report.msg = "CHECK_ANSWER before any QUERY";
                    return error.ScenarioFailed;
                };
                if (answerMismatch(actual, st.entry.?, true)) |why| {
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
            .check_max_queries => if (s.log.items.len > st.max_queries) {
                report.msg = "CHECK_MAX_QUERIES exceeded";
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
    try requery(arena, &g, &s, scenario, report, &held, &desk, &rb);
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
/// check of a question is in force; TTLs have aged and are not compared.
fn requery(arena: Allocator, g: *graph.Graph, s: *sim.Sim, scenario: *const rpl.Scenario, report: *Report, held: *Held, desk: *answer.Desk, rb: *const rebinding.Config) !void {
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
        const actual = try resolveClient(arena, g, s, scenario, query.entry.?, held, desk, rb) orelse {
            report.msg = "client timed out";
            return error.ScenarioFailed;
        };
        if (answerMismatch(actual.msg, check.entry.?, false)) |why| {
            report.msg = why;
            return error.ScenarioFailed;
        }
        if (s.log.items.len != before and actual.cacheable) {
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
const Sent = struct { msg: dns.Message, cacheable: bool };

/// Null when the client's timer fires first. The roots stay in `held`,
/// since the answer reads their hops, until the next question.
fn resolveClient(arena: Allocator, g: *graph.Graph, s: *sim.Sim, scenario: *const rpl.Scenario, entry: rpl.Entry, held: *Held, desk: *answer.Desk, rb: *const rebinding.Config) !?Sent {
    const q = entry.questions[0];
    const client: answer.Client = .{ .rd = entry.flags.rd, .cd = entry.flags.cd, .do_bit = entry.do_bit, .ad = entry.flags.ad };
    const served = switch (try desk.early(arena, q, client)) {
        .synthesized, .replayed, .floored => |served| served,
        .recalled => |served| blk: {
            errdefer served.release(&g.store);
            try agrees(arena, g, s, scenario, q, client, held, desk, rb, served);
            break :blk served;
        },
        .graph => try desk.derived(q, client, try shapeClient(arena, g, s, scenario, q, client, held, desk) orelse return null),
    };
    defer served.release(&g.store);
    return .{ .msg = try dns.parseMessage(arena, try wireOf(arena, q, client, rb, served)), .cacheable = served.cacheable };
}

/// The bytes serve would send `client` for `served`, bar the query id and OPT.
fn wireOf(arena: Allocator, q: dns.Question, client: answer.Client, rb: *const rebinding.Config, served: answer.Served) ![]const u8 {
    const ctx: response.ResponseContext = .{
        .query_id = 0,
        .opcode = .query,
        .rd = client.rd,
        .cd = client.cd,
        .questions = try arena.dupe(dns.Question, &.{q}),
        .client_edns = false,
        .client_do = client.do_bit,
        .client_wants_ad = client.do_bit or client.ad,
        .max_udp_payload = dns.max_message_len,
        .rebinding = rb,
    };
    const reply: response.Reply = .{ .rcode = served.rcode, .ad = served.ad, .answers = served.answers, .authorities = served.authorities, .additionals = served.additionals };
    return response.buildResponseWire(try arena.alloc(u8, dns.max_message_len), ctx, reply, arena) orelse error.OutOfMemory;
}

/// `recall`'s backstop: what it serves from the store, the graph builds
/// too, asking nobody, to the byte.
fn agrees(arena: Allocator, g: *graph.Graph, s: *sim.Sim, scenario: *const rpl.Scenario, q: dns.Question, client: answer.Client, held: *Held, desk: *answer.Desk, rb: *const rebinding.Config, recalled: answer.Served) !void {
    const before = s.log.items.len;
    const built = try shapeClient(arena, g, s, scenario, q, client, held, desk) orelse return error.RecallDisagrees;
    defer built.release(&g.store);
    if (s.log.items.len != before) return error.RecallDisagrees;
    const a = try wireOf(arena, q, client, rb, recalled);
    const b = try wireOf(arena, q, client, rb, built);
    const ede_eq = if (recalled.ede) |x| if (built.ede) |y| x.code == y.code and mem.eql(u8, x.text, y.text) else false else built.ede == null;
    if (!mem.eql(u8, a, b) or !ede_eq) return error.RecallDisagrees;
}

/// The graph driven synchronously: serve parks the client instead.
fn shapeClient(arena: Allocator, g: *graph.Graph, s: *sim.Sim, scenario: *const rpl.Scenario, q: dns.Question, client: answer.Client, held: *Held, desk: *answer.Desk) !?answer.Served {
    unholdAll(g, held);
    const deadline = s.now_ns + @as(i64, scenario.client_timeout_ms) * std.time.ns_per_ms;
    const asked = try desk.asked(arena, q, client);
    const root = (try g.demandRoot(asked.name, asked.qtype, true)).?;
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
    const a = (try g.demandRoot(aq.name, aq.qtype, true)).?;
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
    std.debug.print("  actual: rcode={t} aa={} ad={}\n", .{ m.header.flags.rcode, m.header.flags.aa, m.header.flags.ad });
    for ([_][]const dns.ResourceRecord{ m.answers, m.authorities, m.additionals }, [_][]const u8{ "an", "ns", "ar" }) |sec, label| {
        for (sec) |rr| std.debug.print("    {s} {s} {d} {t}\n", .{ label, rr.name.formatInto(&nb), rr.ttl, rr.rtype });
    }
}

fn formatLog(gpa: Allocator, log: []const sim.LogRow) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (log) |row| {
        var nb: [dns.max_dotted_len + 1]u8 = undefined;
        var ab: [64]u8 = undefined;
        try out.print(gpa, "    {s} <- {s} {t}\n", .{ na.format(row.server, &ab), row.qname.formatInto(&nb), row.qtype });
    }
    return out.toOwnedSlice(gpa);
}

// ── CHECK_ANSWER ───────────────────────────────────────────────────────

fn answerMismatch(actual: dns.Message, e: rpl.Entry, compare_ttl: bool) ?[]const u8 {
    var m = e.match;
    if (m.isEmpty()) m.all = true;
    m.ttl = m.ttl and compare_ttl;
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
        // A scenario cannot spell a signature minted at run time; the
        // Python harness matches the header too.
        .rrsig => |v| v.type_covered == b.rrsig.type_covered and v.algorithm == b.rrsig.algorithm and v.signer_name.eql(b.rrsig.signer_name),
        .unknown => |v| std.ascii.eqlIgnoreCase(v, b.unknown),
        else => false,
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

const Replayed = struct { parsed: usize, failed: usize, tally: graph.Tally = .{}, cells: usize = 0, scenarios: usize = 0 };

/// Replay every scenario under `root` across `seeds`, checking
/// that one seed replays to one upstream query log.
fn replayDir(root: []const u8, seeds: u64, xfail: []const []const u8) !Replayed {
    const io = testing.io;
    // Debug catches leaks; the tally wants the production allocator.
    const gpa = if (@import("builtin").mode == .debug) testing.allocator else std.heap.smp_allocator;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch return error.SkipZigTest;
    defer dir.close(io);
    var walker = try dir.walk(testing.allocator);
    defer walker.deinit();
    var r: Replayed = .{ .parsed = 0, .failed = 0 };
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
        var seed: u64 = 1;
        while (seed <= seeds) : (seed += 1) {
            var first: Report = .{};
            defer gpa.free(first.log);
            const result = runScenario(gpa, &scenario, .{ .seed = seed }, &first);
            inline for (@typeInfo(graph.Tally).@"struct".field_names) |f| @field(r.tally, f) += @field(first.tally, f);
            r.cells += first.cells;
            r.scenarios += 1;
            if (expect_fail) {
                if (result) |_| {
                    r.failed += 1;
                    std.debug.print("{s}: passed but is marked xfail\n", .{ent.path});
                } else |_| {}
                continue;
            }
            result catch |err| {
                r.failed += 1;
                std.debug.print("{s} (seed {d}): {t} step {d}: {s} ({s})\n{s}", .{ ent.path, seed, first.phase, first.step, first.msg, @errorName(err), first.log });
                break;
            };
            var second: Report = .{};
            defer gpa.free(second.log);
            runScenario(gpa, &scenario, .{ .seed = seed }, &second) catch {};
            if (!mem.eql(u8, first.log, second.log)) {
                r.failed += 1;
                std.debug.print("{s} (seed {d}): two runs, two query logs\n", .{ ent.path, seed });
                break;
            }
        }
    }
    // Debug numbers mean nothing.
    if (@import("builtin").mode == .debug) return r;
    const t = r.tally;
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

// `HARK_SCENARIO=path/to/x.rpl zig build test` replays one scenario with
// every completion printed.
test "trace one scenario" {
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // procfs reports size 0, so stream it.
    const f = try std.Io.Dir.cwd().openFile(io, "/proc/self/environ", .{});
    defer f.close(io);
    var env_buf: [1 << 16]u8 = undefined;
    var n: usize = 0;
    while (true) {
        n += f.readStreaming(io, &.{env_buf[n..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
    }
    var vars = mem.splitScalar(u8, env_buf[0..n], 0);
    const path = while (vars.next()) |v| {
        if (mem.startsWith(u8, v, "HARK_SCENARIO=")) break v["HARK_SCENARIO=".len..];
    } else return error.SkipZigTest;
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20));
    var diag: rpl.Diag = .{};
    const scenario = try rpl.parse(arena, text, &diag);
    var report: Report = .{};
    defer testing.allocator.free(report.log);
    const result = runScenario(testing.allocator, &scenario, .{ .seed = 1, .trace = true }, &report);
    std.debug.print("{t} step {d}: {s}\n{s}", .{ report.phase, report.step, report.msg, report.log });
    try result;
}

test "hark walk scenarios settle to today's answers" {
    const r = try replayDir("test/scenarios/hark", 8, &.{});
    try testing.expectEqual(123, r.parsed);
    try testing.expectEqual(0, r.failed);
}

// test/scenarios/lifted/manifest.py's xfails, strict: a pass there is a
// divergence note to revisit.
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
    });
    try testing.expectEqual(18, r.parsed);
    try testing.expectEqual(0, r.failed);
}

test "a silent sibling is hedged past and still records its timeout" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // ns1 (127.0.10.3) listens nowhere, ns2 answers: cold, ns1 gets 400 ms
    // and the hedge asks ns2 at 150.
    var diag: rpl.Diag = .{};
    const scenario = try rpl.parse(arena,
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
    , &diag);
    const q = scenario.steps[0].entry.?.questions[0];
    const ns1 = na.AddressKey.fromAddress(na.initIp4(.{ 127, 0, 10, 3 }, 53));
    const ns2 = na.AddressKey.fromAddress(na.initIp4(.{ 127, 0, 10, 4 }, 53));
    var ns1_first_seen = false;
    for (1..9) |seed| for ([_]u32{ 150, 0 }) |stagger| {
        var s = try sim.Sim.init(arena, testing.allocator, &scenario, seed);
        defer s.deinit();
        var g = try graph.Graph.init(testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true }, .stagger_ms = stagger }, s.edge());
        defer g.deinit();
        const start = s.now_ns;
        const root = (try g.demandRoot(q.name, q.qtype, true)).?;
        try g.drain();
        while (!g.cell(root).settled()) {
            const ev = s.next(start + 5 * std.time.ns_per_s) orelse return error.TestUnexpectedResult;
            try g.complete(ev.id, ev.completion);
        }
        try testing.expectEqual(.answer, g.cell(g.cell(root).state.fact.answer.hops[0]).state.fact.rrset.kind);
        g.unhold(root);
        const took_ms = @divTrunc(s.now_ns - start, std.time.ns_per_ms);
        while (s.next(start + 5 * std.time.ns_per_s)) |ev| try g.complete(ev.id, ev.completion);
        try testing.expectEqual(0, g.live);
        try testing.expect(s.log.items[2].qname.eql(q.name));
        const ns1_first = na.AddressKey.fromAddress(s.log.items[2].server).eql(ns1);
        ns1_first_seen = ns1_first_seen or ns1_first;
        try testing.expect(g.rtt.get(ns2) != null);
        if (ns1_first) try testing.expectEqual(1, g.rtt.get(ns1).?.consecutive_timeouts) else try testing.expect(g.rtt.get(ns1) == null);
        if (stagger > 0) {
            // Walk (≤ 2 × 50 ms), the stagger, then ns2 (≤ 50 ms).
            try testing.expect(took_ms < 400);
            if (ns1_first) try testing.expect(took_ms >= 150);
        } else if (ns1_first) try testing.expect(took_ms >= 400);
    };
    try testing.expect(ns1_first_seen);

    for (1..9) |seed| for ([_]bool{ false, true }) |all_dead| {
        var s = try sim.Sim.init(arena, testing.allocator, &scenario, seed);
        defer s.deinit();
        var g = try graph.Graph.init(testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true } }, s.edge());
        defer g.deinit();
        const dead: @import("../ns_rtt.zig").RttState = .{ .srtt_us = 1, .consecutive_timeouts = 4, .dead_until_ms = std.math.maxInt(i64) };
        try g.rtt.put(testing.allocator, ns1, dead);
        if (all_dead) try g.rtt.put(testing.allocator, ns2, dead);
        const root = (try g.demandRoot(q.name, q.qtype, true)).?;
        try g.drain();
        while (!g.cell(root).settled()) {
            const ev = s.next(s.now_ns + 5 * std.time.ns_per_s) orelse return error.TestUnexpectedResult;
            try g.complete(ev.id, ev.completion);
        }
        try testing.expectEqual(.answer, g.cell(g.cell(root).state.fact.answer.hops[0]).state.fact.rrset.kind);
        g.unhold(root);
        var asked_ns1 = false;
        for (s.log.items) |row| asked_ns1 = asked_ns1 or na.AddressKey.fromAddress(row.server).eql(ns1);
        if (!all_dead) try testing.expect(!asked_ns1);
    };
}

test "the door counts resolutions and exchanges in flight" {
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
    for ([_][2]u32{ .{ 1, std.math.maxInt(u32) }, .{ 1024, 1 } }) |door| {
        var s = try sim.Sim.init(arena, testing.allocator, &scenario, 1);
        defer s.deinit();
        var g = try graph.Graph.init(testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true }, .max_in_flight = door[0], .max_flights = door[1] }, s.edge());
        defer g.deinit();
        const root = (try g.demandRoot(q.name, q.qtype, true)).?;
        try g.drain();
        try testing.expectEqual(1, g.budgets);
        try testing.expectEqual(1, g.flights);
        // New work is turned away; the same question joins the one in progress.
        try testing.expectEqual(null, try g.demandRoot(other, .a, true));
        try testing.expectEqual(root, (try g.demandRoot(q.name, q.qtype, true)).?);
        try testing.expectEqual(1, g.stats.clients.dropped);
        while (s.next(s.now_ns + 10 * std.time.ns_per_s)) |ev| try g.complete(ev.id, ev.completion);
        try testing.expectEqual(0, g.flights);
        g.unhold(root);
        g.unhold(root);
        try testing.expectEqual(0, g.live);
        try testing.expectEqual(0, g.budgets);
    }
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
    var s = try sim.Sim.init(arena, testing.allocator, &scenario, 1);
    defer s.deinit();
    var g = try graph.Graph.init(testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true } }, s.edge());
    defer g.deinit();
    s.pending_unsent = 1;
    const root = (try g.demandRoot(q.name, q.qtype, true)).?;
    try g.drain();
    while (s.next(s.now_ns + 10 * std.time.ns_per_s)) |ev| try g.complete(ev.id, ev.completion);
    try testing.expect(g.cell(root).failure() == null);
    try testing.expectEqual(1, g.stats.resolver.unsent);
    // Only replies wrote it: a timeout would have started it at 400 ms.
    const server = na.AddressKey.fromAddress(scenario.root_hints[0]);
    try testing.expect(g.rtt.get(server).?.srtt_us < 50 * std.time.us_per_ms);
    g.unhold(root);
}
