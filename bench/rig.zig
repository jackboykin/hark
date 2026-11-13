//! The rig: an authority and a resolver on loopback, in a user and network
//! namespace of their own, all on one CCD since crossing dies costs a hit a
//! fifth. The CCD's last two cores hold the authority and the samplers;
//! `place` draws the resolver's cores from the rest at random, siblings
//! idle, and gives the load what remains.
//!
//! The root's nsd on 198.41.0.4 delegates bench. to a second nsd on the
//! addresses in zones/bench.ns, so a miss starts at a cached 26-server cut,
//! as under com.
//!
//! Knobs: CCD (the last), N (resolver threads, 1), V6=0 (no AAAA servers),
//! LATENCY_MS (netem on lo), PERF=1 (counters on the resolver's cores),
//! PERF_EVENTS (user and kernel instructions and cycles).
const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const os = @import("os.zig");
const load = @import("load.zig");
const Observer = @import("observe.zig");

arena: Allocator,
config: []const u8,
scratch: []const u8,
threads: u32,
observer: Observer,
pool: []Core,
cpu_authority: []const u16,
cpu_aux: []const u16,
cpu_res: []const u16 = &.{},
cpu_load: []const u16 = &.{},
authorities: [2]?os.Child = .{ null, null },
resolver: []os.Child = &.{},
random: std.Random.DefaultPrng,

const Rig = @This();

pub const port = 5354;

const Core = struct { id: u32, threads: [2]?u16 = .{ null, null } };

pub const Peer = enum { unbound, pdns, kresd, bind };

fn number(arena: Allocator, comptime fmt: []const u8, args: anytype) !u32 {
    const text = try os.slurp(arena, try arena.print(fmt, args));
    return std.fmt.parseInt(u32, std.mem.trim(u8, text, " \n"), 10);
}

fn topology(arena: Allocator) ![]Core {
    const At = struct { cpu: u16, core: u32, l3: u32 };
    var cpus: std.ArrayList(At) = .empty;
    var last: u32 = 0;
    var cpu: u16 = 0;
    while (number(arena, "/sys/devices/system/cpu/cpu{d}/topology/core_id", .{cpu})) |core| : (cpu += 1) {
        const l3 = try number(arena, "/sys/devices/system/cpu/cpu{d}/cache/index3/id", .{cpu});
        try cpus.append(arena, .{ .cpu = cpu, .core = core, .l3 = l3 });
        last = @max(last, l3);
    } else |_| {}
    const want = os.knob(u32, "CCD", last);
    var cores: std.ArrayList(Core) = .empty;
    for (cpus.items) |c| {
        if (c.l3 != want) continue;
        const core = for (cores.items) |*k| {
            if (k.id == c.core) break k;
        } else blk: {
            try cores.append(arena, .{ .id = c.core });
            break :blk &cores.items[cores.items.len - 1];
        };
        core.threads[if (core.threads[0] == null) 0 else 1] = c.cpu;
    }
    std.mem.sort(Core, cores.items, {}, struct {
        fn lessThan(_: void, a: Core, b: Core) bool {
            return a.id < b.id;
        }
    }.lessThan);
    if (cores.items.len < 4) return error.TooFewCores;
    return cores.items;
}

/// Call before any thread starts.
pub fn enter(arena: Allocator, config: []const u8) !Rig {
    const cores = try topology(arena);
    const observer = try Observer.start();
    const uid = linux.getuid();
    const gid = linux.getgid();
    if (!os.ok(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWNET))) return error.Unshare;
    try os.spit("/proc/self/setgroups", "deny");
    try os.spit("/proc/self/uid_map", try arena.print("0 {d} 1", .{uid}));
    try os.spit("/proc/self/gid_map", try arena.print("0 {d} 1", .{gid}));

    const a = cores[cores.len - 1].threads;
    const c = cores[cores.len - 2].threads;
    var held: std.ArrayList(u16) = .empty;
    for ([_]?u16{ a[0], a[1], c[0] }) |t| if (t) |cpu| try held.append(arena, cpu);
    var seed: u64 = undefined;
    _ = linux.getrandom(std.mem.asBytes(&seed), 8, 0);
    return .{
        .arena = arena,
        .config = config,
        .scratch = try arena.print("/tmp/bench-{d}", .{linux.getpid()}),
        .threads = os.knob(u32, "N", 1),
        .observer = observer,
        .pool = cores[0 .. cores.len - 2],
        .cpu_authority = held.items,
        .cpu_aux = try arena.dupe(u16, &.{c[1] orelse c[0].?}),
        .random = .init(seed),
    };
}

pub fn place(r: *Rig, n: usize) !void {
    r.random.random().shuffle(Core, r.pool);
    var res: std.ArrayList(u16) = .empty;
    var gen: std.ArrayList(u16) = .empty;
    for (r.pool, 0..) |core, i| {
        if (i < n) {
            try res.append(r.arena, core.threads[0].?);
        } else for (core.threads) |t| if (t) |cpu| try gen.append(r.arena, cpu);
    }
    r.cpu_res = res.items;
    r.cpu_load = gen.items;
}

fn path(r: *const Rig, comptime fmt: []const u8, args: anytype) ![]const u8 {
    return r.arena.print("{s}/" ++ fmt, .{r.scratch} ++ args);
}

fn template(r: *const Rig, file: []const u8, name: []const u8) ![]u8 {
    var text = try os.slurp(r.arena, try r.arena.print("{s}/{s}", .{ r.config, file }));
    const n = try r.arena.print("{d}", .{r.threads});
    for ([_][2][]const u8{ .{ "__RUN__", r.scratch }, .{ "__DIR__", r.config }, .{ "__NAME__", name }, .{ "__N__", n } }) |sub|
        text = try std.mem.replaceOwned(u8, r.arena, text, sub[0], sub[1]);
    return text;
}

fn authority(r: *Rig, name: []const u8, cpus: []const u16, zone: []const u8, addrs: []const []const u8) !os.Child {
    var conf: std.ArrayList(u8) = .fromOwnedSlice(try r.template("nsd.conf", name));
    for (addrs) |a| try conf.print(r.arena, "    ip-address: {s}\n", .{a});
    try conf.print(r.arena, "zone:\n    name: \"{s}\"\n    zonefile: \"{s}.zone\"\n", .{ zone, name });
    const file = try r.path("nsd-{s}.conf", .{name});
    try os.spit(file, conf.items);
    const err = try os.writer(try r.path("nsd-{s}.err", .{name}), false);
    defer _ = linux.close(err);
    return os.spawn(r.arena, .{ .argv = &.{ "nsd", "-c", file, "-d" }, .cpus = cpus, .stderr = err });
}

pub fn up(r: *Rig) !void {
    try os.run(r.arena, &.{ "mkdir", "-p", r.scratch });
    var addrs: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.tokenizeScalar(u8, try os.slurp(r.arena, try r.arena.print("{s}/zones/bench.ns", .{r.config})), '\n');
    const v6 = os.knob(bool, "V6", true);
    while (lines.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \t");
        var field: [5][]const u8 = undefined;
        for (&field) |*x| x.* = f.next() orelse break;
        if (std.mem.eql(u8, field[3], "A") or (v6 and std.mem.eql(u8, field[3], "AAAA"))) try addrs.append(r.arena, field[4]);
    }
    var batch: std.ArrayList(u8) = .empty;
    try batch.appendSlice(r.arena, "link set lo up\naddr add 198.41.0.4/32 dev lo\n");
    for (addrs.items) |a| try batch.print(r.arena, "addr add {s} dev lo\n", .{a});
    const file = try r.path("ip", .{});
    try os.spit(file, batch.items);
    try os.run(r.arena, &.{ "ip", "-batch", file });
    r.authorities[0] = try r.authority("root", r.cpu_aux, ".", &.{"198.41.0.4"});
    r.authorities[1] = try r.authority("bench", r.cpu_authority, "bench.", addrs.items);
    if (os.knob(?[]const u8, "LATENCY_MS", null)) |ms|
        try os.run(r.arena, &.{ "tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", try r.arena.print("{s}ms", .{ms}), "limit", "200000" });
    try r.place(r.threads);
    os.sleep(500 * std.time.ns_per_ms);
}

pub fn down(r: *Rig) void {
    for (r.resolver) |c| c.signal(.KILL);
    for (r.authorities) |a| if (a) |c| c.stop();
    os.run(r.arena, &.{ "rm", "-rf", r.scratch }) catch {};
}

fn ask(name: []const u8) bool {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (!os.ok(rc)) return false;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const addr: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
    if (!os.ok(linux.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))))) return false;
    var buf: [512]u8 = undefined;
    const len = load.question(&buf, name, 1);
    if (!os.ok(linux.sendto(fd, &buf, len, 0, null, 0))) return false;
    var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&pfd, 1, 1000) != 1) return false;
    const n = linux.recvfrom(fd, &buf, buf.len, 0, null, null);
    return os.ok(n) and n >= 12;
}

pub fn warm(_: *const Rig) void {
    var name: [16]u8 = undefined;
    for (1..9) |i| _ = ask(std.mem.print(&name, "host{d}.bench", .{i}) catch unreachable);
}

fn logFile(r: *const Rig) ![]const u8 {
    return r.path("res.log", .{});
}

fn command(r: *Rig, side: []const u8) ![]const []const u8 {
    const peer = std.meta.stringToEnum(Peer, side) orelse
        return r.arena.dupe([]const u8, &.{ side, "serve", "--config", try r.arena.print("{s}/hark.toml", .{r.config}) });
    for ([_][]const u8{ "unbound.conf", "recursor.yml", "named.conf" }) |f| try os.spit(try r.path("{s}", .{f}), try r.template(f, ""));
    return r.arena.dupe([]const u8, switch (peer) {
        .unbound => &.{ "unbound", "-d", "-c", try r.path("unbound.conf", .{}) },
        .pdns => &.{ "pdns_recursor", try r.arena.print("--config-dir={s}", .{r.scratch}) },
        .kresd => blk: {
            const dir = try r.path("kres", .{});
            try os.run(r.arena, &.{ "rm", "-rf", dir });
            try os.run(r.arena, &.{ "mkdir", "-p", dir });
            break :blk &.{ "kresd", "-n", "-q", "-c", try r.arena.print("{s}/kresd.conf", .{r.config}), dir };
        },
        .bind => &.{ "named", "-g", "-n", try r.arena.print("{d}", .{r.threads}), "-c", try r.path("named.conf", .{}) },
    });
}

/// kresd is one thread a process: N of them share the port and the cache.
pub fn start(r: *Rig, side: []const u8) !void {
    const argv = try r.command(side);
    const log = try os.writer(try r.logFile(), true);
    defer _ = linux.close(log);
    const count = if (std.mem.eql(u8, side, "kresd")) r.threads else 1;
    r.resolver = try r.arena.alloc(os.Child, count);
    for (r.resolver) |*c| c.* = try os.spawn(r.arena, .{ .argv = argv, .cpus = r.cpu_res, .stdout = log, .stderr = log, .bare = true });
    for (0..50) |_| {
        if (ask("smoke.bench")) return;
        os.sleep(100 * std.time.ns_per_ms);
    }
    const said = try os.slurp(r.arena, try r.logFile());
    std.debug.print("bench: {s} did not come up\n{s}\n", .{ side, said[said.len -| 2000..] });
    return error.NotUp;
}

pub fn stop(r: *Rig) void {
    for (r.resolver) |c| c.signal(.TERM);
    for (r.resolver) |c| _ = c.wait();
    r.resolver = &.{};
}

pub fn pid(r: *const Rig) linux.pid_t {
    return r.resolver[0].pid;
}

pub fn dump(r: *const Rig) ![]const u8 {
    const before = (try os.slurp(r.arena, try r.logFile())).len;
    r.resolver[0].signal(.USR1);
    for (0..500) |_| {
        const said = (try os.slurp(r.arena, try r.logFile()))[before..];
        if (std.mem.find(u8, said, "stats clients.queries.udp") != null and std.mem.find(u8, said, "stats window (") != null) return said;
        os.sleep(20 * std.time.ns_per_ms);
    }
    return error.NoStats;
}

/// The resolver's cores from /proc/stat: user nice system idle iowait irq
/// softirq steal, summed.
pub fn snap(r: *const Rig) ![8]u64 {
    var sum: [8]u64 = @splat(0);
    var lines = std.mem.tokenizeScalar(u8, try os.slurp(r.arena, "/proc/stat"), '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const name = f.next().?;
        if (name.len < 4 or !std.mem.startsWith(u8, name, "cpu")) continue;
        const cpu = std.fmt.parseInt(u16, name[3..], 10) catch continue;
        if (std.mem.findScalar(u16, r.cpu_res, cpu) == null) continue;
        for (&sum) |*s| s.* += try std.fmt.parseInt(u64, f.next().?, 10);
    }
    return sum;
}

pub fn busy(a: [8]u64, b: [8]u64) [4]f64 {
    var d: [8]f64 = undefined;
    var total: f64 = 0;
    for (&d, a, b) |*x, before, after| {
        x.* = @floatFromInt(after - before);
        total += x.*;
    }
    return .{ 100 * (total - d[3] - d[4]) / total, 100 * d[0] / total, 100 * d[2] / total, 100 * d[6] / total };
}

pub fn cpuList(arena: Allocator, cpus: []const u16) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (cpus, 0..) |c, i| try out.print(arena, "{s}{d}", .{ if (i == 0) "" else ",", c });
    return out.items;
}

pub fn perfOn(r: *const Rig) !void {
    if (!os.knob(bool, "PERF", false)) return;
    const events = os.knob([]const u8, "PERF_EVENTS", "instructions:u,cycles:u,instructions:k,cycles:k");
    try r.observer.statOn(r.arena, try cpuList(r.arena, r.cpu_res), events, try r.path("counts.csv", .{}));
}

pub fn perfOff(r: *const Rig) ![]const u8 {
    if (!os.knob(bool, "PERF", false)) return "";
    return r.observer.statOff(r.arena);
}

pub const Sampler = struct {
    thread: std.Thread = undefined,
    cpus: []const u16,
    done: std.atomic.Value(bool) = .init(false),
    rxq_max: u64 = 0,
    listener: std.array_hash_map.Auto(u64, u64) = .empty,
    generator: std.array_hash_map.Auto(u64, u64) = .empty,

    pub const Seen = struct { rxq_max: u64, listener_drops: u64, generator_drops: u64 };

    pub fn start(s: *Sampler) !void {
        s.thread = try std.Thread.spawn(.{}, watch, .{s});
    }

    pub fn stop(s: *Sampler) Seen {
        s.done.store(true, .release);
        s.thread.join();
        var seen: Seen = .{ .rxq_max = s.rxq_max, .listener_drops = 0, .generator_drops = 0 };
        for (s.listener.values()) |d| seen.listener_drops += d;
        for (s.generator.values()) |d| seen.generator_drops += d;
        return seen;
    }

    fn watch(s: *Sampler) void {
        os.pin(s.cpus);
        var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena_state.deinit();
        const gpa = std.heap.smp_allocator;
        var suffix: [5]u8 = undefined;
        _ = std.mem.print(&suffix, ":{X:0>4}", .{port}) catch unreachable;
        while (!s.done.load(.acquire)) : (os.sleep(50 * std.time.ns_per_ms)) {
            _ = arena_state.reset(.retain_capacity);
            var lines = std.mem.tokenizeScalar(u8, os.slurp(arena_state.allocator(), "/proc/net/udp") catch return, '\n');
            while (lines.next()) |line| s.read(gpa, line, &suffix) catch return;
        }
    }

    fn read(s: *Sampler, gpa: Allocator, line: []const u8, suffix: []const u8) !void {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        var field: [13][]const u8 = undefined;
        for (&field) |*x| x.* = f.next() orelse return;
        const listening = std.mem.endsWith(u8, field[1], suffix);
        if (!listening and !std.mem.endsWith(u8, field[2], suffix)) return;
        const inode = try std.fmt.parseInt(u64, field[9], 10);
        const drops = try std.fmt.parseInt(u64, field[12], 10);
        if (listening) {
            const queues = field[4];
            const rxq = try std.fmt.parseInt(u64, queues[std.mem.findScalar(u8, queues, ':').? + 1 ..], 16);
            s.rxq_max = @max(s.rxq_max, rxq);
            try s.listener.put(gpa, inode, drops);
        } else {
            const at = try s.generator.getOrPutValue(gpa, inode, 0);
            at.value_ptr.* = @max(at.value_ptr.*, drops);
        }
    }
};
