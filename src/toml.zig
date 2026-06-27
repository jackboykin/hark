const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;

// ── Types ──────────────────────────────────────────────────────────────

pub const Value = union(enum) {
    string: []const u8,
    integer: i64,
    boolean: bool,
    string_array: []const []const u8,
    table: Table,
};

pub const Table = struct {
    map: std.StringHashMapUnmanaged(Value),

    pub fn getString(self: Table, key: []const u8) ?[]const u8 {
        const val = self.map.get(key) orelse return null;
        return switch (val) {
            .string => |s| s,
            else => null,
        };
    }

    pub fn getInteger(self: Table, key: []const u8) ?i64 {
        const val = self.map.get(key) orelse return null;
        return switch (val) {
            .integer => |i| i,
            else => null,
        };
    }

    pub fn getBool(self: Table, key: []const u8) ?bool {
        const val = self.map.get(key) orelse return null;
        return switch (val) {
            .boolean => |b| b,
            else => null,
        };
    }

    pub fn getStringArray(self: Table, key: []const u8) ?[]const []const u8 {
        const val = self.map.get(key) orelse return null;
        return switch (val) {
            .string_array => |a| a,
            else => null,
        };
    }

    pub fn getTable(self: Table, key: []const u8) ?Table {
        const val = self.map.get(key) orelse return null;
        return switch (val) {
            .table => |t| t,
            else => null,
        };
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

pub const ParseResult = struct {
    table: Table,
    allocator: Allocator,

    pub fn deinit(self: *ParseResult) void {
        freeTable(self.allocator, &self.table);
    }
};

fn freeValue(allocator: Allocator, value: *Value) void {
    switch (value.*) {
        .string => |s| allocator.free(s),
        .integer, .boolean => {},
        .string_array => |arr| {
            for (arr) |s| allocator.free(s);
            allocator.free(arr);
        },
        .table => |*t| freeTable(allocator, t),
    }
}

fn freeTable(allocator: Allocator, table: *Table) void {
    var it = table.map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        freeValue(allocator, entry.value_ptr);
    }
    table.map.deinit(allocator);
}

// ── Parser ─────────────────────────────────────────────────────────────

pub fn parse(allocator: Allocator, input: []const u8) ParseError!ParseResult {
    var root = Table{ .map = .empty };
    errdefer freeTable(allocator, &root);

    var current_section: ?[]const u8 = null;
    var lines = mem.splitScalar(u8, input, '\n');

    while (lines.next()) |raw_line| {
        const line = stripComment(mem.trim(u8, raw_line, &std.ascii.whitespace));

        if (line.len == 0) continue;

        if (line[0] == '[') {
            const close = mem.indexOfScalar(u8, line, ']') orelse return error.InvalidSyntax;
            if (close == 1) return error.InvalidBareKey; // empty section name
            const section_name = mem.trim(u8, line[1..close], &std.ascii.whitespace);

            // Validate bare key chars
            if (!isValidBareKey(section_name)) return error.InvalidBareKey;

            // Check for trailing garbage after ]
            const after_close = mem.trim(u8, line[close + 1 ..], &std.ascii.whitespace);
            if (after_close.len > 0) return error.InvalidSyntax;

            // Check for duplicate section
            if (root.map.get(section_name)) |_| return error.DuplicateSection;

            // Create section table
            const duped_name = try allocator.dupe(u8, section_name);
            errdefer allocator.free(duped_name);

            const empty_table = Value{ .table = .{ .map = .empty } };
            try root.map.put(allocator, duped_name, empty_table);
            current_section = duped_name;
        } else {
            const eq_pos = mem.indexOfScalar(u8, line, '=') orelse return error.InvalidSyntax;
            const raw_key = mem.trim(u8, line[0..eq_pos], &std.ascii.whitespace);
            const raw_val = mem.trim(u8, line[eq_pos + 1 ..], &std.ascii.whitespace);

            if (raw_key.len == 0) return error.InvalidBareKey;
            if (!isValidBareKey(raw_key)) return error.InvalidBareKey;
            if (raw_val.len == 0) return error.InvalidSyntax;

            const value = try parseValue(allocator, raw_val);
            errdefer {
                var v = value;
                freeValue(allocator, &v);
            }

            const duped_key = try allocator.dupe(u8, raw_key);
            errdefer allocator.free(duped_key);

            // Insert into current section or root
            const target = if (current_section) |sec| blk: {
                const entry = root.map.getPtr(sec).?;
                break :blk &entry.table.map;
            } else &root.map;

            if (target.get(duped_key) != null) return error.DuplicateKey;
            try target.put(allocator, duped_key, value);
        }
    }

    return .{ .table = root, .allocator = allocator };
}

fn stripComment(line: []const u8) []const u8 {
    // Find # that's not inside a string
    var in_string = false;
    var escaped = false;
    for (line, 0..) |c, i| {
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
        if (c == '#' and !in_string) {
            return mem.trim(u8, line[0..i], &std.ascii.whitespace);
        }
    }
    return line;
}

fn isValidBareKey(key: []const u8) bool {
    for (key) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return false;
    }
    return true;
}

fn parseValue(allocator: Allocator, raw: []const u8) ParseError!Value {
    if (raw.len == 0) return error.InvalidSyntax;

    // String
    if (raw[0] == '"') return .{ .string = try parseString(allocator, raw) };

    // Array
    if (raw[0] == '[') return parseArray(allocator, raw);

    // Boolean
    if (mem.eql(u8, raw, "true")) return .{ .boolean = true };
    if (mem.eql(u8, raw, "false")) return .{ .boolean = false };

    // Integer
    return .{ .integer = parseInteger(raw) orelse return error.InvalidInteger };
}

fn parseString(allocator: Allocator, raw: []const u8) ParseError![]const u8 {
    if (raw.len < 2 or raw[0] != '"') return error.InvalidSyntax;

    var result = std.ArrayList(u8).empty;
    defer result.deinit(allocator);

    var i: usize = 1;
    while (i < raw.len) {
        const c = raw[i];
        if (c == '"') {
            // Found closing quote — check nothing follows
            const after = mem.trim(u8, raw[i + 1 ..], &std.ascii.whitespace);
            if (after.len > 0) return error.InvalidSyntax;
            return try allocator.dupe(u8, result.items);
        }
        if (c == '\\') {
            i += 1;
            if (i >= raw.len) return error.InvalidEscape;
            switch (raw[i]) {
                '\\' => try result.append(allocator, '\\'),
                '"' => try result.append(allocator, '"'),
                'n' => try result.append(allocator, '\n'),
                't' => try result.append(allocator, '\t'),
                else => return error.InvalidEscape,
            }
        } else {
            try result.append(allocator, c);
        }
        i += 1;
    }
    return error.UnterminatedString;
}

fn parseInteger(raw: []const u8) ?i64 {
    if (raw.len == 0) return null;
    var start: usize = 0;
    var negative = false;
    if (raw[0] == '+') {
        start = 1;
    } else if (raw[0] == '-') {
        start = 1;
        negative = true;
    }
    if (start >= raw.len) return null;

    // Filter underscores (TOML allows 1_000)
    var digits: [64]u8 = undefined;
    var len: usize = 0;
    for (raw[start..]) |c| {
        if (c == '_') continue;
        if (!std.ascii.isDigit(c)) return null;
        if (len >= digits.len) return null;
        digits[len] = c;
        len += 1;
    }
    if (len == 0) return null;

    const abs = std.fmt.parseInt(i64, digits[0..len], 10) catch return null;
    return if (negative) -abs else abs;
}

fn parseArray(allocator: Allocator, raw: []const u8) ParseError!Value {
    if (raw.len < 2 or raw[0] != '[') return error.InvalidSyntax;

    // Find closing bracket
    const close = mem.lastIndexOfScalar(u8, raw, ']') orelse return error.InvalidSyntax;
    // Reject trailing garbage so a typo like `key = ["x"] junk` surfaces as
    // an error instead of silently dropping the trailing characters.
    for (raw[close + 1 ..]) |c| if (!std.ascii.isWhitespace(c)) return error.InvalidSyntax;
    const inner = mem.trim(u8, raw[1..close], &std.ascii.whitespace);

    if (inner.len == 0) {
        // Empty array
        const empty = try allocator.alloc([]const u8, 0);
        return .{ .string_array = empty };
    }

    // Split array elements — need to handle quoted strings with commas
    var items = std.ArrayList([]const u8).empty;
    defer {
        for (items.items) |s| allocator.free(s);
        items.deinit(allocator);
    }

    var pos: usize = 0;
    while (pos < inner.len) {
        // Skip whitespace
        while (pos < inner.len and std.ascii.isWhitespace(inner[pos])) pos += 1;
        if (pos >= inner.len) break;

        if (inner[pos] == '"') {
            // Find end of quoted string
            var end = pos + 1;
            while (end < inner.len) {
                if (inner[end] == '\\') {
                    if (end + 1 >= inner.len) break;
                    end += 2;
                    continue;
                }
                if (inner[end] == '"') {
                    end += 1;
                    break;
                }
                end += 1;
            }
            const str = try parseString(allocator, inner[pos..end]);
            try items.append(allocator, str);
            pos = end;
        } else {
            return error.InvalidSyntax; // Only string arrays supported
        }

        // Skip whitespace and comma
        while (pos < inner.len and std.ascii.isWhitespace(inner[pos])) pos += 1;
        if (pos < inner.len and inner[pos] == ',') pos += 1;
    }

    const result = try allocator.dupe([]const u8, items.items);
    // Clear items without freeing strings (ownership transferred)
    items.items.len = 0;
    return .{ .string_array = result };
}

// ── Tests ──────────────────────────────────────────────────────────────

test "parse empty input" {
    var result = try parse(testing.allocator, "");
    defer result.deinit();
    try testing.expectEqual(@as(u32, 0), result.table.map.count());
}

test "parse comments and blank lines" {
    var result = try parse(testing.allocator,
        \\# This is a comment
        \\
        \\# Another comment
    );
    defer result.deinit();
    try testing.expectEqual(@as(u32, 0), result.table.map.count());
}

test "parse string value" {
    var result = try parse(testing.allocator,
        \\name = "hello"
    );
    defer result.deinit();
    try testing.expectEqualStrings("hello", result.table.getString("name").?);
}

test "parse string escapes" {
    // TOML input: path = "a\"b\\c"  (with literal backslash escapes)
    const input = "path = \"a\\\"b\\\\c\"";
    var result = try parse(testing.allocator, input);
    defer result.deinit();
    try testing.expectEqualStrings("a\"b\\c", result.table.getString("path").?);
}

test "parse integer value" {
    var result = try parse(testing.allocator,
        \\port = 8053
    );
    defer result.deinit();
    try testing.expectEqual(@as(i64, 8053), result.table.getInteger("port").?);
}

test "parse negative integer" {
    var result = try parse(testing.allocator,
        \\offset = -10
    );
    defer result.deinit();
    try testing.expectEqual(@as(i64, -10), result.table.getInteger("offset").?);
}

test "parse integer with underscores" {
    var result = try parse(testing.allocator,
        \\size = 16_777_216
    );
    defer result.deinit();
    try testing.expectEqual(@as(i64, 16_777_216), result.table.getInteger("size").?);
}

test "parse boolean values" {
    var result = try parse(testing.allocator,
        \\enabled = true
        \\disabled = false
    );
    defer result.deinit();
    try testing.expectEqual(true, result.table.getBool("enabled").?);
    try testing.expectEqual(false, result.table.getBool("disabled").?);
}

test "parse string array" {
    var result = try parse(testing.allocator,
        \\listen = ["127.0.0.1:53", "[::1]:53"]
    );
    defer result.deinit();
    const arr = result.table.getStringArray("listen").?;
    try testing.expectEqual(@as(usize, 2), arr.len);
    try testing.expectEqualStrings("127.0.0.1:53", arr[0]);
    try testing.expectEqualStrings("[::1]:53", arr[1]);
}

test "parse empty array" {
    var result = try parse(testing.allocator,
        \\items = []
    );
    defer result.deinit();
    const arr = result.table.getStringArray("items").?;
    try testing.expectEqual(@as(usize, 0), arr.len);
}

test "parse section tables" {
    var result = try parse(testing.allocator,
        \\[server]
        \\listen = ["127.0.0.1:53"]
        \\workers = 4
        \\
        \\[resolver]
        \\qname-minimization = true
        \\dnssec = false
    );
    defer result.deinit();

    const server = result.table.getTable("server").?;
    try testing.expectEqual(@as(i64, 4), server.getInteger("workers").?);
    const arr = server.getStringArray("listen").?;
    try testing.expectEqual(@as(usize, 1), arr.len);

    const resolver = result.table.getTable("resolver").?;
    try testing.expectEqual(true, resolver.getBool("qname-minimization").?);
    try testing.expectEqual(false, resolver.getBool("dnssec").?);
}

test "parse inline comment" {
    var result = try parse(testing.allocator,
        \\port = 53 # standard DNS port
    );
    defer result.deinit();
    try testing.expectEqual(@as(i64, 53), result.table.getInteger("port").?);
}

test "parse comment with hash in string" {
    var result = try parse(testing.allocator,
        \\name = "hello#world"
    );
    defer result.deinit();
    try testing.expectEqualStrings("hello#world", result.table.getString("name").?);
}

test "error on duplicate key" {
    const result = parse(testing.allocator,
        \\key = "a"
        \\key = "b"
    );
    try testing.expectError(error.DuplicateKey, result);
}

test "error on duplicate section" {
    const result = parse(testing.allocator,
        \\[server]
        \\port = 53
        \\[server]
        \\port = 80
    );
    try testing.expectError(error.DuplicateSection, result);
}

test "error on unterminated string" {
    const result = parse(testing.allocator,
        \\name = "hello
    );
    try testing.expectError(error.UnterminatedString, result);
}

test "error on invalid bare key" {
    const result = parse(testing.allocator,
        \\bad key = "value"
    );
    try testing.expectError(error.InvalidBareKey, result);
}

test "error on missing value" {
    const result = parse(testing.allocator,
        \\key =
    );
    try testing.expectError(error.InvalidSyntax, result);
}

test "full config example" {
    var result = try parse(testing.allocator,
        \\[server]
        \\listen = ["127.0.0.1:53", "[::1]:53"]
        \\workers = 4
        \\
        \\[resolver]
        \\dnssec = false
        \\qname-minimization = true
        \\
        \\[cache]
        \\size = 16777216
        \\entries = 10000
    );
    defer result.deinit();

    const server = result.table.getTable("server").?;
    try testing.expectEqual(@as(i64, 4), server.getInteger("workers").?);

    const resolver = result.table.getTable("resolver").?;
    try testing.expectEqual(true, resolver.getBool("qname-minimization").?);

    const cache = result.table.getTable("cache").?;
    try testing.expectEqual(@as(i64, 16777216), cache.getInteger("size").?);
    try testing.expectEqual(@as(i64, 10000), cache.getInteger("entries").?);
}

test "key with hyphens" {
    var result = try parse(testing.allocator,
        \\qname-minimization = true
    );
    defer result.deinit();
    try testing.expectEqual(true, result.table.getBool("qname-minimization").?);
}
