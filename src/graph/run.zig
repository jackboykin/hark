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
    phase: enum { steps, warm } = .steps,
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

    var s = try sim.Sim.init(arena, gpa, scenario, opts.seed);
    defer s.deinit();
    var g = try graph.Graph.init(arena, gpa, .{
        .qmin = scenario.qmin orelse true,
        .root_hints = scenario.root_hints,
        .addr_policy = .{ .allow_loopback = true },
        .stagger_ms = scenario.stagger_ms orelse 150,
        .trust_anchor = s.signer.anchor(),
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
            .query => last = (try resolveClient(arena, &g, &s, scenario, st.entry.?) orelse {
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
            .time_passes => s.advance(st.seconds),
        }
    }
    report.phase = .warm;
    try requery(arena, &g, &s, scenario, report);
}

/// Every checked question, re-asked against the settled graph, must answer
/// the same and from memory alone unless the answer was never a fact (TTL
/// 0). A cell that expired as it settled, or a memoised head that lost its
/// chain, shows up as an upstream query or a different answer. The last
/// check of a question is in force; TTLs have aged and are not compared.
fn requery(arena: Allocator, g: *graph.Graph, s: *sim.Sim, scenario: *const rpl.Scenario, report: *Report) !void {
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
        const actual = try resolveClient(arena, g, s, scenario, query.entry.?) orelse {
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

/// A reply, and whether it is a fact past this instant (TTL 0 is served
/// but never memoised).
const Served = struct { msg: dns.Message, cacheable: bool };

/// Demand the answer, wait for it, age and shape it. Null when the
/// client's timer fires first.
fn resolveClient(arena: Allocator, g: *graph.Graph, s: *sim.Sim, scenario: *const rpl.Scenario, entry: rpl.Entry) !?Served {
    const q = entry.questions[0];
    // RFC 8482: ANY is answered with a synthetic HINFO, asking nobody.
    if (q.qtype == .any) {
        const hinfo: dns.ResourceRecord = .{ .name = q.name, .rtype = @fromBackingInt(13), .rclass = .in, .ttl = 0, .rdata = .{ .unknown = "\x07RFC8482\x00" } };
        return .{ .cacheable = false, .msg = .{
            .header = .{ .id = 0, .flags = .{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = entry.flags.rd, .ra = true, .z = 0, .ad = false, .cd = entry.flags.cd, .rcode = .no_error } },
            .questions = try arena.dupe(dns.Question, &.{q}),
            .answers = try arena.dupe(dns.ResourceRecord, &.{hinfo}),
        } };
    }
    const client_deadline = s.now_ns + @as(i64, scenario.client_timeout_ms) * std.time.ns_per_ms;
    const root = try g.demandRoot(q.name, q.qtype);
    try g.drain();
    while (!g.cell(root).settled) {
        const ev = s.next(client_deadline) orelse return null;
        try g.complete(ev.id, ev.completion);
    }
    const a = g.cell(root).value.answer;
    var chain: std.ArrayList(dns.ResourceRecord) = .empty;
    var last: graph.Reply = .{ .kind = .servfail, .rcode = .server_failure, .aa = false };
    var age: u32 = 0;
    // A bogus chain is SERVFAIL unless CD; signatures only to a DO client;
    // AD claims the whole chain, set only when asked for (RFC 6840 §5.7).
    const served = !a.broken and (a.status != .bogus or entry.flags.cd);
    if (served) for (a.hops) |h| {
        last = g.cell(h).value.rrset;
        age = @intCast(@divTrunc(s.now_ns - last.stored_ns, std.time.ns_per_s));
        try appendAged(arena, &chain, last.answers, age, entry.do_bit);
    };
    const positive = last.kind == .answer or last.kind == .alias;
    const minimal = scenario.minimal_responses orelse true;
    var authorities: std.ArrayList(dns.ResourceRecord) = .empty;
    var additionals: std.ArrayList(dns.ResourceRecord) = .empty;
    if (!(positive and minimal and q.qtype != .ns)) {
        try appendAged(arena, &authorities, last.authorities, age, entry.do_bit);
        try appendAged(arena, &additionals, last.additionals, age, entry.do_bit);
    }
    return .{ .cacheable = g.cell(root).expires_ns > s.now_ns, .msg = .{
        .header = .{ .id = 0, .flags = .{
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = entry.flags.rd,
            .ra = true,
            .z = 0,
            .ad = served and a.status == .secure and (entry.do_bit or entry.flags.ad),
            .cd = entry.flags.cd,
            .rcode = if (last.kind == .servfail) last.rcode else if (last.kind == .nxdomain) .name_error else .no_error,
        } },
        .questions = try arena.dupe(dns.Question, &.{q}),
        .answers = chain.items,
        .authorities = authorities.items,
        .additionals = additionals.items,
    } };
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

/// TTLs less the time since the reply was taken; signatures only when
/// wanted.
fn appendAged(arena: Allocator, out: *std.ArrayList(dns.ResourceRecord), rrs: []const dns.ResourceRecord, age: u32, sigs: bool) !void {
    for (rrs) |rr| {
        if (rr.rtype == .rrsig and !sigs) continue;
        var aged = rr;
        aged.ttl = rr.ttl -| age;
        try out.append(arena, aged);
    }
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

/// The graph has no DNS64, stale serving or rebinding policy yet.
fn walkOnly(s: *const rpl.Scenario) bool {
    return s.dns64_prefix == null and s.serve_stale_ttl == null and s.rebinding_enabled == null;
}

/// Replay every walk-only scenario under `root` across `seeds`, checking
/// that one seed replays to one upstream query log.
fn replayDir(root: []const u8, seeds: u64, xfail: []const []const u8) !struct { parsed: usize, ran: usize, failed: usize } {
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch return error.SkipZigTest;
    defer dir.close(io);
    var walker = try dir.walk(testing.allocator);
    defer walker.deinit();
    var parsed: usize = 0;
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
        parsed += 1;
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
                std.debug.print("{s} (seed {d}): {t} step {d}: {s} ({s})\n{s}", .{ ent.path, seed, first.phase, first.step, first.msg, @errorName(err), first.log });
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
    return .{ .parsed = parsed, .ran = ran, .failed = failed };
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
    // Aggressive NSEC synthesis (RFC 8198) is the NSEC-index rule, not built.
    const r = try replayDir("test/scenarios/hark", 8, &.{"007_aggressive_nsec_synthesises_sibling_nxdomain.rpl"});
    try testing.expectEqual(89, r.parsed);
    try testing.expectEqual(77, r.ran);
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
    try testing.expectEqual(18, r.ran);
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
        var g = try graph.Graph.init(arena, testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true }, .stagger_ms = stagger }, &s);
        defer g.deinit();
        const start = s.now_ns;
        const root = try g.demandRoot(q.name, q.qtype);
        try g.drain();
        while (!g.cell(root).settled) {
            const ev = s.next(start + 5 * std.time.ns_per_s) orelse return error.TestUnexpectedResult;
            try g.complete(ev.id, ev.completion);
        }
        try testing.expectEqual(.answer, g.cell(g.cell(root).value.answer.hops[0]).value.rrset.kind);
        const took_ms = @divTrunc(s.now_ns - start, std.time.ns_per_ms);
        while (s.next(start + 5 * std.time.ns_per_s)) |ev| try g.complete(ev.id, ev.completion);
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
        var g = try graph.Graph.init(arena, testing.allocator, .{ .root_hints = scenario.root_hints, .addr_policy = .{ .allow_loopback = true } }, &s);
        defer g.deinit();
        const dead: @import("../ns_rtt.zig").RttState = .{ .srtt_us = 1, .consecutive_timeouts = 4, .dead_until_ms = std.math.maxInt(i64) };
        try g.rtt.put(testing.allocator, ns1, dead);
        if (all_dead) try g.rtt.put(testing.allocator, ns2, dead);
        const root = try g.demandRoot(q.name, q.qtype);
        try g.drain();
        while (!g.cell(root).settled) {
            const ev = s.next(s.now_ns + 5 * std.time.ns_per_s) orelse return error.TestUnexpectedResult;
            try g.complete(ev.id, ev.completion);
        }
        try testing.expectEqual(.answer, g.cell(g.cell(root).value.answer.hops[0]).value.rrset.kind);
        var asked_ns1 = false;
        for (s.log.items) |row| asked_ns1 = asked_ns1 or na.AddressKey.fromAddress(row.server).eql(ns1);
        if (!all_dead) try testing.expect(!asked_ns1);
    };
}
