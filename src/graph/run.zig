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
const graph = @import("graph.zig");

pub const Report = struct {
    /// The failing step and why.
    step: u32 = 0,
    msg: []const u8 = "",
    /// The upstream query log, one `server <- qname qtype` per line,
    /// gpa-owned. Two runs of one seed must produce the same text.
    log: []const u8 = "",
};

pub const Options = struct {
    seed: u64 = 1,
    trace: bool = false,
};

pub fn runScenario(gpa: Allocator, scenario: *const rpl.Scenario, opts: Options, report: *Report) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var s = sim.Sim.init(arena, gpa, scenario, opts.seed);
    defer s.deinit();
    var g = try graph.Graph.init(arena, gpa, .{
        .qmin = scenario.qmin orelse true,
        .root_hints = scenario.root_hints,
        .addr_policy = .{ .allow_loopback = true },
        .trace = opts.trace,
    }, &s);
    defer g.deinit();

    var drops: u32 = 0;
    for (scenario.steps) |st| drops += @intFromBool(st.kind == .timeout);
    s.pending_drops = drops;

    defer report.log = formatLog(gpa, s.log.items) catch "";
    var last: ?dns.Message = null;
    var cursor: usize = 0;
    for (scenario.steps) |st| {
        s.step = st.n;
        report.step = st.n;
        switch (st.kind) {
            .query => last = try resolveClient(arena, &g, &s, scenario, st.entry.?) orelse {
                report.msg = "client timed out";
                return error.ScenarioFailed;
            },
            .check_answer => {
                const actual = last orelse {
                    report.msg = "CHECK_ANSWER before any QUERY";
                    return error.ScenarioFailed;
                };
                if (answerMismatch(actual, st.entry.?)) |why| {
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
            .time_passes => s.advance(st.seconds),
        }
    }
}

/// A client question: demand the RRset, follow aliases, shape the reply.
/// Null when the client's timer fires first.
fn resolveClient(arena: Allocator, g: *graph.Graph, s: *sim.Sim, scenario: *const rpl.Scenario, entry: rpl.Entry) !?dns.Message {
    const q = entry.questions[0];
    const client_deadline = s.now_ns + @as(i64, scenario.client_timeout_ms) * std.time.ns_per_ms;
    var chain: std.ArrayList(dns.ResourceRecord) = .empty;
    var name = q.name;
    var seen: [17]dns.Name = undefined;
    var hops: usize = 0;
    var payer: ?graph.CellId = null;
    while (true) {
        const root = try g.demandRoot(name, q.qtype, payer);
        payer = g.cell(root).root;
        try g.drain();
        while (!g.cell(root).settled) {
            const ev = s.next(client_deadline) orelse return null;
            try g.complete(ev.id, ev.completion);
        }
        var r = g.cell(root).value.rrset;
        const age: u32 = @intCast(@divTrunc(s.now_ns - r.stored_ns, std.time.ns_per_s));
        // A CNAME question is answered by the alias itself.
        if (r.kind == .alias and q.qtype != .cname) {
            // A chain revisiting an owner, or past max_cname_chain, is a
            // resolution failure (today's loopServfail / CnameChainTooLong).
            seen[hops] = name;
            var looped = hops >= 16;
            for (seen[0..hops]) |n| looped = looped or n.eql(r.target);
            if (!looped) {
                try appendAged(arena, &chain, r.answers, age);
                name = r.target;
                hops += 1;
                continue;
            }
            r = .{ .kind = .servfail, .rcode = .server_failure, .aa = false };
            chain.clearRetainingCapacity();
        }
        const positive = r.kind == .answer or r.kind == .alias;
        const minimal = scenario.minimal_responses orelse true;
        var authorities: std.ArrayList(dns.ResourceRecord) = .empty;
        var additionals: std.ArrayList(dns.ResourceRecord) = .empty;
        if (!(positive and minimal and q.qtype != .ns)) {
            try appendAged(arena, &authorities, r.authorities, age);
            try appendAged(arena, &additionals, r.additionals, age);
        }
        try appendAged(arena, &chain, r.answers, age);
        return .{
            .header = .{ .id = 0, .flags = .{
                .qr = true,
                .opcode = .query,
                .aa = false,
                .tc = false,
                .rd = entry.flags.rd,
                .ra = true,
                .z = 0,
                .ad = false,
                .cd = entry.flags.cd,
                .rcode = if (r.kind == .servfail) r.rcode else if (r.kind == .nxdomain) .name_error else .no_error,
            } },
            .questions = try arena.dupe(dns.Question, &.{q}),
            .answers = chain.items,
            .authorities = authorities.items,
            .additionals = additionals.items,
        };
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

/// Records as served now: TTLs less the time since the reply was taken.
fn appendAged(arena: Allocator, out: *std.ArrayList(dns.ResourceRecord), rrs: []const dns.ResourceRecord, age: u32) !void {
    for (rrs) |rr| {
        var aged = rr;
        aged.ttl = rr.ttl -| age;
        try out.append(arena, aged);
    }
}

// ── CHECK_ANSWER ───────────────────────────────────────────────────────

fn answerMismatch(actual: dns.Message, e: rpl.Entry) ?[]const u8 {
    var m = e.match;
    if (m.isEmpty()) m.all = true;
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
        .unknown => |v| mem.eql(u8, v, b.unknown),
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

/// Step 1 covers the walk: scenarios that need no signing, DNS64, stale
/// serving or rebinding policy.
fn walkOnly(s: *const rpl.Scenario) bool {
    return s.dnssec_zones.len == 0 and s.dns64_prefix == null and s.serve_stale_ttl == null and s.rebinding_enabled == null;
}

/// Replay every walk-only scenario under `root`, each under `seeds` seeds,
/// and check that one seed replays to one upstream query log.
fn replayDir(root: []const u8, seeds: u64, xfail: []const []const u8) !struct { ran: usize, failed: usize } {
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch return error.SkipZigTest;
    defer dir.close(io);
    var walker = try dir.walk(testing.allocator);
    defer walker.deinit();
    var ran: usize = 0;
    var failed: usize = 0;
    while (try walker.next(io)) |ent| {
        if (ent.kind != .file or !mem.endsWith(u8, ent.basename, ".rpl")) continue;
        const text = try dir.readFileAlloc(io, ent.path, arena, .limited(1 << 20));
        var diag: rpl.Diag = .{};
        const scenario = rpl.parse(arena, text, &diag) catch |err| switch (err) {
            error.UnsupportedRType => continue,
            else => return err,
        };
        if (!walkOnly(&scenario)) continue;
        var expect_fail = false;
        for (xfail) |x| expect_fail = expect_fail or mem.eql(u8, x, ent.basename);
        ran += 1;
        var seed: u64 = 1;
        while (seed <= seeds) : (seed += 1) {
            var first: Report = .{};
            defer testing.allocator.free(first.log);
            const result = runScenario(testing.allocator, &scenario, .{ .seed = seed }, &first);
            if (expect_fail) {
                if (result) |_| {
                    failed += 1;
                    std.debug.print("{s}: passed but is marked xfail\n", .{ent.path});
                } else |_| {}
                continue;
            }
            result catch |err| {
                failed += 1;
                std.debug.print("{s} (seed {d}): step {d}: {s} ({s})\n{s}", .{ ent.path, seed, first.step, first.msg, @errorName(err), first.log });
                break;
            };
            var second: Report = .{};
            defer testing.allocator.free(second.log);
            runScenario(testing.allocator, &scenario, .{ .seed = seed }, &second) catch {};
            if (!mem.eql(u8, first.log, second.log)) {
                failed += 1;
                std.debug.print("{s} (seed {d}): two runs, two query logs\n", .{ ent.path, seed });
                break;
            }
        }
    }
    return .{ .ran = ran, .failed = failed };
}

test "hark walk scenarios settle to today's answers" {
    const r = try replayDir("test/scenarios/hark", 8, &.{});
    try testing.expectEqual(44, r.ran);
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
    try testing.expectEqual(16, r.ran);
    try testing.expectEqual(0, r.failed);
}
