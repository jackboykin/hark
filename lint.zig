//! hark's own lint, on the compiler's parser: what `zig fmt` leaves alone
//! and hark holds itself to. `zig build lint` runs it.
//!
//! - Every file opens with a `//!` naming what it holds.
//! - No comment trails code outside a test.
//! - A switch over a closed enum or union of hark's own names every tag.
//! - Nothing std marks deprecated is used.
//! - No `@constCast`.
//! - A function or test is at most 100 lines of code, nests control flow at
//!   most 4 deep, and takes at most 7 parameters.
//! - A `pub` declaration is named by another file.
//! - No import cycle outside the named knots.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Ast = std.zig.Ast;
const Io = std.Io;

const File = struct { path: []const u8, tree: Ast };

var problems: usize = 0;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    var lib: Std = .{ .arena = arena, .io = io, .dir = try Io.Dir.path.join(arena, &.{ args.next().?, "std" }) };

    var paths: std.ArrayList([]const u8) = .empty;
    while (args.next()) |root| try collect(arena, io, root, &paths);
    mem.sort([]const u8, paths.items, {}, lessThan);
    const files = try arena.alloc(File, paths.items.len);
    for (files, paths.items) |*f, path| f.* = .{ .path = path, .tree = try load(arena, io, path) };

    const enums = try ownEnums(arena, files);
    for (files) |f| {
        header(f);
        try trailing(arena, f);
        try switches(arena, f, enums);
        try deprecated(arena, f, &lib);
        constCast(f);
        try shape(arena, f);
    }
    try needlessPub(arena, files);
    try cycles(arena, files);
    if (problems > 0) {
        std.debug.print("lint: {d} problem{s}\n", .{ problems, if (problems == 1) "" else "s" });
        std.process.exit(1);
    }
}

fn report(f: File, token: Ast.TokenIndex, comptime fmt: []const u8, args: anytype) void {
    const at = f.tree.tokenLocation(0, token);
    std.debug.print("{s}:{d}:{d}: " ++ fmt ++ "\n", .{ f.path, at.line + 1, at.column + 1 } ++ args);
    problems += 1;
}

fn header(f: File) void {
    if (f.tree.tokenTag(0) != .container_doc_comment) report(f, 0, "the file opens with no //! naming what it holds", .{});
}

/// A trailing comment labels what a name, or the line above, should say.
fn trailing(arena: Allocator, f: File) !void {
    const t = f.tree;
    const tests = try testRanges(arena, t);
    const starts = t.tokens.items(.start);
    tokens: for (0..t.tokens.len - 1) |i| {
        for (tests) |r| if (i >= r[0] and i <= r[1]) continue :tokens;
        const gap = t.source[starts[i] + t.tokenSlice(@intCast(i)).len .. starts[i + 1]];
        const line = gap[0 .. mem.findScalar(u8, gap, '\n') orelse gap.len];
        if (mem.find(u8, line, "//") != null) report(f, @intCast(i), "a comment trails this line", .{});
    }
}

fn testRanges(arena: Allocator, t: Ast) ![]const [2]Ast.TokenIndex {
    var ranges: std.ArrayList([2]Ast.TokenIndex) = .empty;
    for (0..t.nodes.len) |n| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(n));
        if (t.nodeTag(node) == .test_decl) try ranges.append(arena, .{ t.firstToken(node), t.lastToken(node) });
    }
    return ranges.items;
}

const Tags = struct { open: bool, names: std.StringHashMapUnmanaged(void) };

fn ownEnums(arena: Allocator, files: []const File) ![]const Tags {
    var all: std.ArrayList(Tags) = .empty;
    for (files) |f| {
        const t = f.tree;
        for (0..t.nodes.len) |n| {
            var buf: [2]Ast.Node.Index = undefined;
            const decl = t.fullContainerDecl(&buf, @fromBackingInt(@intCast(n))) orelse continue;
            switch (t.tokenTag(decl.ast.main_token)) {
                .keyword_enum, .keyword_union => {},
                else => continue,
            }
            var tags: Tags = .{ .open = false, .names = .empty };
            for (decl.ast.members) |m| {
                const field = t.fullContainerField(m) orelse continue;
                const name = t.tokenSlice(field.ast.main_token);
                if (mem.eql(u8, name, "_")) tags.open = true else try tags.names.put(arena, name, {});
            }
            try all.append(arena, tags);
        }
    }
    return all.items;
}

/// An `else` takes any tag added later without asking. Without types, a
/// switch's tag literals say what it is over. Tags that
/// fit an open enum of hark's (a wire type) need the `else`; tags that fit
/// none are std's. Only tags that fit closed enums alone are judged.
fn switches(arena: Allocator, f: File, enums: []const Tags) !void {
    const t = f.tree;
    for (0..t.nodes.len) |n| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(n));
        const sw = t.fullSwitch(node) orelse continue;
        var else_token: ?Ast.TokenIndex = null;
        var tags: std.ArrayList([]const u8) = .empty;
        var literals = true;
        for (sw.ast.cases) |c| {
            const case = t.fullSwitchCase(c).?;
            if (case.ast.values.len == 0) {
                if (case.inline_token == null) else_token = case.ast.arrow_token - 1;
                continue;
            }
            for (case.ast.values) |v| {
                if (t.nodeTag(v) != .enum_literal) literals = false else try tags.append(arena, t.tokenSlice(t.nodeMainToken(v)));
            }
        }
        const at = else_token orelse continue;
        if (!literals or tags.items.len == 0) continue;
        var open = false;
        var closed = false;
        for (enums) |e| {
            const fits = for (tags.items) |tag| {
                if (!e.names.contains(tag)) break false;
            } else true;
            if (fits) {
                if (e.open) open = true else closed = true;
            }
        }
        if (closed and !open) report(f, at, "an else over a closed enum or union: name its tags", .{});
    }
}

/// std marks deprecations in doc comments only, so the compiler never warns
/// before they go.
fn deprecated(arena: Allocator, f: File, lib: *Std) !void {
    const t = f.tree;
    const aliases = try stdAliases(arena, t);
    for (0..t.nodes.len) |n| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(n));
        if (t.nodeTag(node) != .field_access) continue;
        const path = try chain(arena, t, node, aliases) orelse continue;
        // Reported where the deprecated name is, not again on what follows.
        if (try lib.deprecation(path)) |d| if (d.step == path.len - 1) report(f, t.nodeData(node).node_and_token[1], "{s}", .{d.why});
    }
}

fn stdAliases(arena: Allocator, t: Ast) !std.StringHashMapUnmanaged([]const []const u8) {
    var aliases: std.StringHashMapUnmanaged([]const []const u8) = .empty;
    for (t.rootDecls()) |d| {
        const v = t.fullVarDecl(d) orelse continue;
        const init = v.ast.init_node.unwrap() orelse continue;
        const name = t.tokenSlice(v.ast.mut_token + 1);
        if (isImport(t, init, "std")) {
            try aliases.put(arena, name, &.{});
        } else if (try chain(arena, t, init, aliases)) |path| try aliases.put(arena, name, path);
    }
    return aliases;
}

fn chain(arena: Allocator, t: Ast, node: Ast.Node.Index, aliases: std.StringHashMapUnmanaged([]const []const u8)) !?[]const []const u8 {
    return switch (t.nodeTag(node)) {
        .identifier => aliases.get(t.tokenSlice(t.nodeMainToken(node))),
        .field_access => {
            const lhs, const field = t.nodeData(node).node_and_token;
            const head = try chain(arena, t, lhs, aliases) orelse return null;
            return try mem.concat(arena, []const u8, &.{ head, &.{t.tokenSlice(field)} });
        },
        else => null,
    };
}

fn isImport(t: Ast, node: Ast.Node.Index, target: []const u8) bool {
    return mem.eql(u8, importTarget(t, node) orelse return false, target);
}

fn importTarget(t: Ast, node: Ast.Node.Index) ?[]const u8 {
    var buf: [2]Ast.Node.Index = undefined;
    const params = t.builtinCallParams(&buf, node) orelse return null;
    if (!mem.eql(u8, t.tokenSlice(t.nodeMainToken(node)), "@import") or params.len != 1) return null;
    if (t.nodeTag(params[0]) != .string_literal) return null;
    const quoted = t.tokenSlice(t.nodeMainToken(params[0]));
    return quoted[1 .. quoted.len - 1];
}

const Std = struct {
    arena: Allocator,
    io: Io,
    dir: []const u8,
    trees: std.StringHashMapUnmanaged(*const Ast) = .empty,

    const Error = Io.Dir.ReadFileAllocError;

    const Scope = struct { path: []const u8, tree: *const Ast, members: []const Ast.Node.Index };

    fn file(s: *Std, path: []const u8) Error!Scope {
        const entry = try s.trees.getOrPut(s.arena, path);
        if (!entry.found_existing) {
            const tree = try s.arena.create(Ast);
            tree.* = try load(s.arena, s.io, path);
            entry.value_ptr.* = tree;
        }
        return .{ .path = path, .tree = entry.value_ptr.*, .members = entry.value_ptr.*.rootDecls() };
    }

    fn deprecation(s: *Std, path: []const []const u8) !?struct { step: usize, why: []const u8 } {
        var at = try s.file(try Io.Dir.path.join(s.arena, &.{ s.dir, "std.zig" }));
        for (path, 0..) |name, step| {
            const decl = find(at, name) orelse return null;
            if (docDeprecated(at.tree.*, decl)) |why| return .{ .step = step, .why = why };
            at = try s.into(at, decl, 0) orelse return null;
        }
        return null;
    }

    fn into(s: *Std, at: Scope, decl: Ast.Node.Index, depth: u8) Error!?Scope {
        if (depth > 8) return null;
        const t = at.tree.*;
        const v = t.fullVarDecl(decl) orelse return null;
        const init = v.ast.init_node.unwrap() orelse return null;
        if (importTarget(t, init)) |target| {
            if (!mem.endsWith(u8, target, ".zig")) return null;
            return try s.file(try Io.Dir.path.join(s.arena, &.{ Io.Dir.path.dirname(at.path).?, target }));
        }
        var buf: [2]Ast.Node.Index = undefined;
        if (t.fullContainerDecl(&buf, init)) |c| return .{ .path = at.path, .tree = at.tree, .members = c.ast.members };
        return switch (t.nodeTag(init)) {
            .identifier => {
                const root: Scope = .{ .path = at.path, .tree = at.tree, .members = t.rootDecls() };
                return try s.into(root, find(root, t.tokenSlice(t.nodeMainToken(init))) orelse return null, depth + 1);
            },
            .field_access => {
                const lhs, const field = t.nodeData(init).node_and_token;
                const lhs_decl = try s.resolve(at, lhs, depth + 1) orelse return null;
                return try s.into(lhs_decl, find(lhs_decl, t.tokenSlice(field)) orelse return null, depth + 1);
            },
            else => null,
        };
    }

    fn resolve(s: *Std, at: Scope, node: Ast.Node.Index, depth: u8) Error!?Scope {
        const t = at.tree.*;
        const root: Scope = .{ .path = at.path, .tree = at.tree, .members = t.rootDecls() };
        return switch (t.nodeTag(node)) {
            .identifier => try s.into(root, find(root, t.tokenSlice(t.nodeMainToken(node))) orelse return null, depth),
            .field_access => {
                const lhs, const name = t.nodeData(node).node_and_token;
                const outer = try s.resolve(at, lhs, depth + 1) orelse return null;
                return try s.into(outer, find(outer, t.tokenSlice(name)) orelse return null, depth + 1);
            },
            else => if (importTarget(t, node)) |target| try s.file(try Io.Dir.path.join(s.arena, &.{ Io.Dir.path.dirname(at.path).?, target })) else null,
        };
    }
};

fn find(at: Std.Scope, name: []const u8) ?Ast.Node.Index {
    const t = at.tree.*;
    for (at.members) |m| {
        var buf: [1]Ast.Node.Index = undefined;
        const name_token = if (t.fullVarDecl(m)) |v| v.ast.mut_token + 1 else if (t.fullFnProto(&buf, m)) |p| p.name_token orelse continue else continue;
        if (mem.eql(u8, t.tokenSlice(name_token), name)) return m;
    }
    return null;
}

fn docDeprecated(t: Ast, decl: Ast.Node.Index) ?[]const u8 {
    var i = t.firstToken(decl);
    while (i > 0 and t.tokenTag(i - 1) == .doc_comment) {
        i -= 1;
        const line = mem.trimStart(u8, t.tokenSlice(i)[3..], " ");
        if (mem.startsWith(u8, line, "Deprecated")) return line;
    }
    return null;
}

/// What is typed const stays const.
fn constCast(f: File) void {
    for (0..f.tree.tokens.len) |i| {
        const token: Ast.TokenIndex = @intCast(i);
        if (f.tree.tokenTag(token) == .builtin and mem.eql(u8, f.tree.tokenSlice(token), "@constCast"))
            report(f, token, "@constCast: what is typed const stays const", .{});
    }
}

const max_lines = 100;
const max_depth = 4;
const max_params = 7;

/// Length finds the outlier; depth finds the stacked cases a count of lines
/// cannot see.
fn shape(arena: Allocator, f: File) !void {
    const t = f.tree;
    const line_of = try arena.alloc(u32, t.tokens.len);
    var line: u32 = 0;
    var at: usize = 0;
    for (line_of, t.tokens.items(.start)) |*l, start| {
        line += @intCast(mem.countScalar(u8, t.source[at..start], '\n'));
        at = start;
        l.* = line;
    }
    for (0..t.nodes.len) |n| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(n));
        const body = switch (t.nodeTag(node)) {
            .fn_decl => t.nodeData(node).node_and_node[1],
            .test_decl => t.nodeData(node).opt_token_and_node[1],
            else => continue,
        };
        const name = t.nodeMainToken(node);
        const first = t.firstToken(body) + 1;
        const last = t.lastToken(body);
        var lines: u32 = 0;
        var seen: ?u32 = null;
        for (line_of[first..last]) |l| if (seen != l) {
            seen = l;
            lines += 1;
        };
        if (lines > max_lines) report(f, name, "{d} lines of code, over {d}", .{ lines, max_lines });
        const depth = try nesting(arena, t, first, last);
        if (depth > max_depth) report(f, name, "control flow nests {d} deep, over {d}", .{ depth, max_depth });
        if (t.nodeTag(node) != .fn_decl) continue;
        var buf: [1]Ast.Node.Index = undefined;
        const params = t.fullFnProto(&buf, t.nodeData(node).node_and_node[0]).?.ast.params.len;
        if (params > max_params) report(f, name, "{d} parameters, over {d}", .{ params, max_params });
    }
}

/// The deepest stack of if, while, for and switch between two tokens. An
/// `else if` continues its chain, it does not nest.
fn nesting(arena: Allocator, t: Ast, first: Ast.TokenIndex, last: Ast.TokenIndex) !u32 {
    var spans: std.ArrayList([2]Ast.TokenIndex) = .empty;
    for (0..t.nodes.len) |n| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(n));
        var end = t.lastToken(node);
        if (t.fullIf(node)) |full| {
            if (full.ast.else_expr.unwrap()) |e| if (t.fullIf(e) != null) {
                end = t.lastToken(full.ast.then_expr);
            };
        } else if (t.fullWhile(node) == null and t.fullFor(node) == null and t.fullSwitch(node) == null) continue;
        const start = t.firstToken(node);
        if (start >= first and end <= last) try spans.append(arena, .{ start, end });
    }
    var deepest: u32 = 0;
    for (spans.items) |inner| {
        var depth: u32 = 0;
        for (spans.items) |outer| depth += @intFromBool(outer[0] <= inner[0] and inner[1] <= outer[1]);
        deepest = @max(deepest, depth);
    }
    return deepest;
}

/// Names std calls by convention, which no file of hark's needs to name.
const called_by_std = [_][]const u8{ "main", "std_options", "panic", "format" };

/// A name another file never says is a private name.
fn needlessPub(arena: Allocator, files: []const File) !void {
    const said = try arena.alloc(std.StringHashMapUnmanaged(void), files.len);
    for (said, files) |*names, f| {
        names.* = .empty;
        for (0..f.tree.tokens.len) |i| {
            const token: Ast.TokenIndex = @intCast(i);
            if (f.tree.tokenTag(token) == .identifier) try names.put(arena, f.tree.tokenSlice(token), {});
        }
    }
    for (files, 0..) |f, own| {
        const t = f.tree;
        tokens: for (0..t.tokens.len) |i| {
            if (t.tokenTag(@intCast(i)) != .keyword_pub) continue;
            var token: Ast.TokenIndex = @intCast(i + 1);
            while (t.tokenTag(token) != .identifier) token += 1;
            const name = t.tokenSlice(token);
            for (called_by_std) |known| if (mem.eql(u8, name, known)) continue :tokens;
            for (said, 0..) |names, other| if (other != own and names.contains(name)) continue :tokens;
            report(f, token, "pub {s} is named by no other file", .{name});
        }
    }
}

/// Files that are one module by design: each imports the others freely.
const knots = [_][]const []const u8{
    &.{ "src/chaos.zig", "src/denial.zig", "src/graph.zig", "src/store.zig", "src/stub.zig", "src/trust.zig", "src/walk.zig" },
    &.{ "src/carrier.zig", "src/doq_socket.zig", "src/dot_socket.zig", "src/edge.zig", "src/sessions.zig" },
};

/// A cycle makes its files one unit; outside a named knot that is an accident.
fn cycles(arena: Allocator, files: []const File) !void {
    const reach = try reaches(arena, try imports(arena, files));
    for (files, 0..) |f, i| for (files[i + 1 ..], i + 1..) |g, j| {
        if (!reach[i].isSet(j) or !reach[j].isSet(i)) continue;
        if (!knotted(f.path, g.path)) report(f, 0, "in an import cycle with {s}, outside a named knot", .{g.path});
    };
}

fn knotted(a: []const u8, b: []const u8) bool {
    for (knots) |knot| if (holds(knot, a) and holds(knot, b)) return true;
    return false;
}

fn holds(paths: []const []const u8, path: []const u8) bool {
    for (paths) |p| if (mem.eql(u8, p, path)) return true;
    return false;
}

/// Per file, the files of hark's it imports.
fn imports(arena: Allocator, files: []const File) ![]const []const usize {
    const edges = try arena.alloc([]const usize, files.len);
    for (edges, files) |*out, f| {
        var to: std.ArrayList(usize) = .empty;
        for (0..f.tree.nodes.len) |n| {
            const target = importTarget(f.tree, @fromBackingInt(@intCast(n))) orelse continue;
            const path = try Io.Dir.path.resolveAlloc(arena, &.{ Io.Dir.path.dirname(f.path) orelse ".", target });
            for (files, 0..) |g, i| if (mem.eql(u8, g.path, path)) try to.append(arena, i);
        }
        out.* = to.items;
    }
    return edges;
}

/// Per file, every file its imports lead to.
fn reaches(arena: Allocator, edges: []const []const usize) ![]const std.bit_set.Dynamic {
    const reach = try arena.alloc(std.bit_set.Dynamic, edges.len);
    for (reach, 0..) |*r, from| {
        r.* = try .initEmpty(arena, edges.len);
        var stack: std.ArrayList(usize) = .empty;
        try stack.append(arena, from);
        while (stack.pop()) |at| for (edges[at]) |to| {
            if (r.isSet(to)) continue;
            r.set(to);
            try stack.append(arena, to);
        };
    }
    return reach;
}

fn collect(arena: Allocator, io: Io, root: []const u8, paths: *std.ArrayList([]const u8)) !void {
    if (mem.endsWith(u8, root, ".zig")) return paths.append(arena, root);
    var dir = try Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer dir.close(io);
    var it = try dir.walkSelectively(arena);
    while (try it.next(io)) |entry| switch (entry.kind) {
        .directory => if (entry.basename[0] != '.') try it.enter(io, entry),
        .file => if (mem.endsWith(u8, entry.path, ".zig")) try paths.append(arena, try Io.Dir.path.join(arena, &.{ root, entry.path })),
        else => {},
    };
}

fn load(arena: Allocator, io: Io, path: []const u8) Io.Dir.ReadFileAllocError!Ast {
    const source = try Io.Dir.cwd().readFileAllocOptions(io, path, arena, .limited(1 << 24), .of(u8), 0);
    return Ast.parse(arena, source, .{});
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return mem.order(u8, a, b) == .lt;
}
