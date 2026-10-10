const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;

pub const Value = union(enum) {
    string: []const u8,
    integer: i64,
    boolean: bool,
    string_array: []const []const u8,
    table: Table,
};

pub const Table = struct {
    map: std.StringHashMapUnmanaged(Value),

    /// The value at `key` if it is a `kind`.
    pub fn get(t: Table, key: []const u8, comptime kind: std.meta.Tag(Value)) ?@FieldType(Value, @tagName(kind)) {
        const v = t.map.get(key) orelse return null;
        return if (v == kind) @field(v, @tagName(kind)) else null;
    }
};

pub const ParseError = error{
    InvalidSyntax,
    UnterminatedString,
    InvalidEscape,
    InvalidBareKey,
    DuplicateKey,
    DuplicateSection,
    InvalidInteger,
    OutOfMemory,
};

/// Allocated from `arena` and freed with it; keys point into `input`.
pub fn parse(arena: Allocator, input: []const u8) ParseError!Table {
    var root = Table{ .map = .empty };
    var section = &root.map;
    var lines = mem.splitScalar(u8, input, '\n');

    while (lines.next()) |raw_line| {
        const line = stripComment(mem.trim(u8, raw_line, &std.ascii.whitespace));

        if (line.len == 0) continue;

        if (line[0] == '[') {
            const close = mem.indexOfScalar(u8, line, ']') orelse return error.InvalidSyntax;
            const section_name = mem.trim(u8, line[1..close], &std.ascii.whitespace);

            if (!isValidBareKey(section_name)) return error.InvalidBareKey;

            const after_close = mem.trim(u8, line[close + 1 ..], &std.ascii.whitespace);
            if (after_close.len > 0) return error.InvalidSyntax;

            const entry = try root.map.getOrPut(arena, section_name);
            if (entry.found_existing) return error.DuplicateSection;
            entry.value_ptr.* = .{ .table = .{ .map = .empty } };
            section = &entry.value_ptr.table.map;
        } else {
            const eq_pos = mem.indexOfScalar(u8, line, '=') orelse return error.InvalidSyntax;
            const key = mem.trim(u8, line[0..eq_pos], &std.ascii.whitespace);
            var raw_val = mem.trim(u8, line[eq_pos + 1 ..], &std.ascii.whitespace);

            if (!isValidBareKey(key)) return error.InvalidBareKey;
            if (raw_val.len == 0) return error.InvalidSyntax;

            // An array may span lines, with comments between its elements.
            if (raw_val[0] == '[' and unquoted(raw_val, ']') == null) {
                var joined: std.ArrayList(u8) = .empty;
                try joined.appendSlice(arena, raw_val);
                while (unquoted(joined.items, ']') == null) {
                    const more = lines.next() orelse return error.InvalidSyntax;
                    try joined.append(arena, '\n');
                    try joined.appendSlice(arena, stripComment(mem.trim(u8, more, &std.ascii.whitespace)));
                }
                raw_val = joined.items;
            }

            const entry = try section.getOrPut(arena, key);
            if (entry.found_existing) return error.DuplicateKey;
            entry.value_ptr.* = try parseValue(arena, raw_val);
        }
    }

    return root;
}

fn stripComment(line: []const u8) []const u8 {
    const at = unquoted(line, '#') orelse return line;
    return mem.trim(u8, line[0..at], &std.ascii.whitespace);
}

/// Where `target` first appears outside a string.
fn unquoted(text: []const u8, target: u8) ?usize {
    var in_string = false;
    var escaped = false;
    for (text, 0..) |c, i| {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (c == '\\' and in_string) {
            escaped = true;
            continue;
        }
        if (c == '"') {
            in_string = !in_string;
            continue;
        }
        if (c == target and !in_string) return i;
    }
    return null;
}

fn isValidBareKey(key: []const u8) bool {
    for (key) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return false;
    return key.len > 0;
}

fn parseValue(arena: Allocator, raw: []const u8) ParseError!Value {
    if (raw[0] == '"') return .{ .string = try parseString(arena, raw) };
    if (raw[0] == '[') return .{ .string_array = try parseArray(arena, raw) };
    if (mem.eql(u8, raw, "true")) return .{ .boolean = true };
    if (mem.eql(u8, raw, "false")) return .{ .boolean = false };
    return .{ .integer = std.fmt.parseInt(i64, raw, 10) catch return error.InvalidInteger };
}

fn parseString(arena: Allocator, raw: []const u8) ParseError![]const u8 {
    var result: std.ArrayList(u8) = .empty;
    var i: usize = 1;
    while (i < raw.len) : (i += 1) {
        const c = raw[i];
        if (c == '"') {
            const after = mem.trim(u8, raw[i + 1 ..], &std.ascii.whitespace);
            if (after.len > 0) return error.InvalidSyntax;
            return result.items;
        }
        try result.append(arena, if (c != '\\') c else blk: {
            i += 1;
            if (i >= raw.len) return error.InvalidEscape;
            break :blk switch (raw[i]) {
                '\\' => '\\',
                '"' => '"',
                'n' => '\n',
                't' => '\t',
                else => return error.InvalidEscape,
            };
        });
    }
    return error.UnterminatedString;
}

/// Only arrays of strings.
fn parseArray(arena: Allocator, raw: []const u8) ParseError![]const []const u8 {
    const close = mem.lastIndexOfScalar(u8, raw, ']') orelse return error.InvalidSyntax;
    // Trailing garbage, as in `key = ["x"] junk`, is a typo, not a comment.
    for (raw[close + 1 ..]) |c| if (!std.ascii.isWhitespace(c)) return error.InvalidSyntax;
    const inner = raw[1..close];

    var items: std.ArrayList([]const u8) = .empty;
    var pos: usize = 0;
    while (true) {
        while (pos < inner.len and std.ascii.isWhitespace(inner[pos])) pos += 1;
        if (pos >= inner.len) break;
        if (inner[pos] != '"') return error.InvalidSyntax;

        var end = pos + 1;
        while (end < inner.len) {
            if (inner[end] == '\\') {
                if (end + 1 >= inner.len) break;
                end += 2;
                continue;
            }
            end += 1;
            if (inner[end - 1] == '"') break;
        }
        try items.append(arena, try parseString(arena, inner[pos..end]));
        pos = end;

        while (pos < inner.len and std.ascii.isWhitespace(inner[pos])) pos += 1;
        if (pos < inner.len and inner[pos] == ',') pos += 1;
    }
    return items.items;
}

var test_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);

fn parseTest(input: []const u8) ParseError!Table {
    return parse(test_arena.allocator(), input);
}

test "parse comments and blank lines" {
    try testing.expectEqual(0, (try parseTest("")).map.count());
    try testing.expectEqual(0, (try parseTest(
        \\# This is a comment
        \\
        \\# Another comment
    )).map.count());
}

test "parse strings" {
    const t = try parseTest(
        \\name = "hello#world" # a comment
        \\path = "a\"b\\c"
    );
    try testing.expectEqualStrings("hello#world", t.get("name", .string).?);
    try testing.expectEqualStrings("a\"b\\c", t.get("path", .string).?);
}

test "parse integers" {
    const t = try parseTest(
        \\port = 53 # standard DNS port
        \\offset = -10
        \\size = 16_777_216
    );
    try testing.expectEqual(53, t.get("port", .integer).?);
    try testing.expectEqual(-10, t.get("offset", .integer).?);
    try testing.expectEqual(16_777_216, t.get("size", .integer).?);
    try testing.expectError(error.InvalidInteger, parseTest("size = _1"));
}

test "parse boolean values" {
    const t = try parseTest(
        \\enabled = true
        \\disabled = false
    );
    try testing.expectEqual(true, t.get("enabled", .boolean).?);
    try testing.expectEqual(false, t.get("disabled", .boolean).?);
}

test "parse string arrays" {
    const t = try parseTest(
        \\listen = ["127.0.0.1:53", "[::1]:53"]
        \\items = []
    );
    const arr = t.get("listen", .string_array).?;
    try testing.expectEqual(2, arr.len);
    try testing.expectEqualStrings("127.0.0.1:53", arr[0]);
    try testing.expectEqualStrings("[::1]:53", arr[1]);
    try testing.expectEqual(0, t.get("items", .string_array).?.len);
}

test "parse an array across lines" {
    const t = try parseTest(
        \\zones = [
        \\  "internal 192.0.2.1", # a comment
        \\  "a]b#c",
        \\]
        \\after = 1
    );
    const arr = t.get("zones", .string_array).?;
    try testing.expectEqual(2, arr.len);
    try testing.expectEqualStrings("internal 192.0.2.1", arr[0]);
    try testing.expectEqualStrings("a]b#c", arr[1]);
    try testing.expectEqual(1, t.get("after", .integer).?);
}

test "parse section tables" {
    const t = try parseTest(
        \\[server]
        \\listen = ["127.0.0.1:53"]
        \\workers = 4
        \\
        \\[resolver]
        \\qname-minimization = true
    );
    const server = t.get("server", .table).?;
    try testing.expectEqual(4, server.get("workers", .integer).?);
    try testing.expectEqual(1, server.get("listen", .string_array).?.len);
    try testing.expectEqual(true, t.get("resolver", .table).?.get("qname-minimization", .boolean).?);
}

test "parse errors" {
    try testing.expectError(error.InvalidSyntax, parseTest("zones = [\n  \"internal 192.0.2.1\""));
    try testing.expectError(error.DuplicateKey, parseTest("key = \"a\"\nkey = \"b\""));
    try testing.expectError(error.DuplicateSection, parseTest("[server]\nport = 53\n[server]\nport = 80"));
    try testing.expectError(error.UnterminatedString, parseTest("name = \"hello"));
    try testing.expectError(error.InvalidBareKey, parseTest("bad key = \"value\""));
    try testing.expectError(error.InvalidBareKey, parseTest("[ ]"));
    try testing.expectError(error.InvalidSyntax, parseTest("key ="));
}
