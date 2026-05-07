//! Reusable privacy redaction primitive (DG-1).
//!
//! Detects and replaces email, phone (E.164), card numbers (Luhn-checked),
//! anchored ID/passport runs, and known token/secret patterns with
//! deterministic numbered placeholders like `[EMAIL_1]`, `[CARD_2]`.
//!
//! Stateful: same value within or across `redact()` calls reuses the same id.

const std = @import("std");

pub const Config = struct {
    redact_email: bool = true,
    redact_phone: bool = true,
    redact_card: bool = true,
    redact_id: bool = true,
    redact_tokens: bool = true,
};

pub const Redactor = struct {
    allocator: std.mem.Allocator,
    config: Config,
    email_map: std.StringHashMap(u32),
    phone_map: std.StringHashMap(u32),
    card_map: std.StringHashMap(u32),
    id_map: std.StringHashMap(u32),
    token_map: std.StringHashMap(u32),
    email_count: u32,
    phone_count: u32,
    card_count: u32,
    id_count: u32,
    token_count: u32,

    pub fn init(allocator: std.mem.Allocator, config: Config) Redactor {
        return .{
            .allocator = allocator,
            .config = config,
            .email_map = std.StringHashMap(u32).init(allocator),
            .phone_map = std.StringHashMap(u32).init(allocator),
            .card_map = std.StringHashMap(u32).init(allocator),
            .id_map = std.StringHashMap(u32).init(allocator),
            .token_map = std.StringHashMap(u32).init(allocator),
            .email_count = 0,
            .phone_count = 0,
            .card_count = 0,
            .id_count = 0,
            .token_count = 0,
        };
    }

    pub fn deinit(self: *Redactor) void {
        freeKeys(&self.email_map, self.allocator);
        freeKeys(&self.phone_map, self.allocator);
        freeKeys(&self.card_map, self.allocator);
        freeKeys(&self.id_map, self.allocator);
        freeKeys(&self.token_map, self.allocator);
        self.email_map.deinit();
        self.phone_map.deinit();
        self.card_map.deinit();
        self.id_map.deinit();
        self.token_map.deinit();
    }

    /// Redact PII / sensitive data from `input`. Returns slice owned by `dest_allocator`;
    /// caller must free with the same allocator. Internal state (maps, counters) lives
    /// on `self.allocator`, so a single Redactor can serve many short-lived destination
    /// allocators (e.g. per-turn arenas) while preserving cross-call placeholder ids.
    pub fn redact(self: *Redactor, dest_allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(dest_allocator);

        var i: usize = 0;
        while (i < input.len) {
            // Priority order: tokens > email > card > phone > id.
            if (self.config.redact_tokens) {
                if (matchKeyValueSecret(input, i)) |kv| {
                    try out.appendSlice(dest_allocator, input[i..kv.value_start]);
                    const id = try self.intern(&self.token_map, &self.token_count, input[kv.value_start..kv.value_end]);
                    try writePlaceholder(&out, dest_allocator, "TOKEN", id);
                    i = kv.value_end;
                    continue;
                }
                if (matchBearerToken(input, i)) |bt| {
                    try out.appendSlice(dest_allocator, input[i .. i + bt.prefix_len]);
                    const id = try self.intern(&self.token_map, &self.token_count, input[i + bt.prefix_len .. bt.end]);
                    try writePlaceholder(&out, dest_allocator, "TOKEN", id);
                    i = bt.end;
                    continue;
                }
                if (matchPrefixToken(input, i)) |pt| {
                    const id = try self.intern(&self.token_map, &self.token_count, input[i..pt.end]);
                    try writePlaceholder(&out, dest_allocator, "TOKEN", id);
                    i = pt.end;
                    continue;
                }
            }
            if (self.config.redact_email) {
                if (matchEmail(input, i)) |em| {
                    const id = try self.intern(&self.email_map, &self.email_count, input[em.start..em.end]);
                    try writePlaceholder(&out, dest_allocator, "EMAIL", id);
                    i = em.end;
                    continue;
                }
            }
            if (self.config.redact_card) {
                if (matchCard(input, i)) |cd| {
                    const id = try self.intern(&self.card_map, &self.card_count, input[cd.start..cd.end]);
                    try writePlaceholder(&out, dest_allocator, "CARD", id);
                    i = cd.end;
                    continue;
                }
            }
            if (self.config.redact_phone) {
                if (matchPhone(input, i)) |ph| {
                    const id = try self.intern(&self.phone_map, &self.phone_count, input[ph.start..ph.end]);
                    try writePlaceholder(&out, dest_allocator, "PHONE", id);
                    i = ph.end;
                    continue;
                }
            }
            if (self.config.redact_id) {
                if (matchAnchoredId(input, i)) |idm| {
                    try out.appendSlice(dest_allocator, input[i..idm.value_start]);
                    const id = try self.intern(&self.id_map, &self.id_count, input[idm.value_start..idm.value_end]);
                    try writePlaceholder(&out, dest_allocator, "ID", id);
                    i = idm.value_end;
                    continue;
                }
            }

            try out.append(dest_allocator, input[i]);
            i += 1;
        }

        return try out.toOwnedSlice(dest_allocator);
    }

    fn intern(self: *Redactor, map: *std.StringHashMap(u32), counter: *u32, value: []const u8) !u32 {
        if (map.get(value)) |existing| return existing;
        const key_dup = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(key_dup);
        const new_id = counter.* + 1;
        try map.put(key_dup, new_id);
        counter.* = new_id;
        return new_id;
    }
};

fn freeKeys(map: *std.StringHashMap(u32), allocator: std.mem.Allocator) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
}

fn writePlaceholder(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, kind: []const u8, id: u32) !void {
    var buf: [32]u8 = undefined;
    const formatted = try std.fmt.bufPrint(&buf, "[{s}_{d}]", .{ kind, id });
    try out.appendSlice(allocator, formatted);
}

// ════════════════════════════════════════════════════════════════════════════
// Detectors
// ════════════════════════════════════════════════════════════════════════════

fn isSecretChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == ':';
}

fn tokenEnd(input: []const u8, from: usize) usize {
    var end = from;
    while (end < input.len and isSecretChar(input[end])) end += 1;
    return end;
}

fn eqlLowercase(input: []const u8, kw: []const u8) bool {
    if (input.len != kw.len) return false;
    for (input, kw) |a, b| {
        if (std.ascii.toLower(a) != b) return false;
    }
    return true;
}

const PrefixToken = struct { end: usize };

fn matchPrefixToken(input: []const u8, pos: usize) ?PrefixToken {
    const prefixes = [_][]const u8{
        "sk-",  "xoxb-", "xoxp-", "ghp_",
        "gho_", "ghs_",  "ghu_",  "glpat-",
        "AKIA", "pypi-", "npm_",  "shpat_",
    };
    if (pos > 0) {
        const prev = input[pos - 1];
        if (std.ascii.isAlphanumeric(prev) or prev == '_') return null;
    }
    for (prefixes) |prefix| {
        if (pos + prefix.len > input.len) continue;
        if (!std.mem.eql(u8, input[pos .. pos + prefix.len], prefix)) continue;
        const content_start = pos + prefix.len;
        const end = tokenEnd(input, content_start);
        if (end > content_start) {
            return .{ .end = end };
        }
    }
    return null;
}

const KeyValueMatch = struct { value_start: usize, value_end: usize };

fn matchKeyValueSecret(input: []const u8, pos: usize) ?KeyValueMatch {
    const keywords = [_][]const u8{
        "api_key", "api-key",    "apikey",
        "token",   "password",   "passwd",
        "secret",  "api_secret", "access_key",
    };
    if (pos > 0) {
        const prev = input[pos - 1];
        if (std.ascii.isAlphanumeric(prev) or prev == '_' or prev == '-') return null;
    }
    for (keywords) |kw| {
        if (pos + kw.len >= input.len) continue;
        if (!eqlLowercase(input[pos .. pos + kw.len], kw)) continue;
        var sep_end = pos + kw.len;
        if (sep_end < input.len and (input[sep_end] == '=' or input[sep_end] == ':')) {
            sep_end += 1;
            while (sep_end < input.len and input[sep_end] == ' ') sep_end += 1;
            var quote: u8 = 0;
            if (sep_end < input.len and (input[sep_end] == '"' or input[sep_end] == '\'')) {
                quote = input[sep_end];
                sep_end += 1;
            }
            const value_start = sep_end;
            var value_end = value_start;
            if (quote != 0) {
                while (value_end < input.len and input[value_end] != quote) value_end += 1;
                if (value_end < input.len) value_end += 1;
            } else {
                value_end = tokenEnd(input, value_start);
            }
            if (value_end > value_start) {
                return .{ .value_start = value_start, .value_end = value_end };
            }
        }
    }
    return null;
}

const BearerMatch = struct { prefix_len: usize, end: usize };

fn matchBearerToken(input: []const u8, pos: usize) ?BearerMatch {
    const variants = [_][]const u8{ "Bearer ", "bearer ", "BEARER " };
    if (pos > 0) {
        const prev = input[pos - 1];
        if (std.ascii.isAlphanumeric(prev) or prev == '_') return null;
    }
    for (variants) |prefix| {
        if (pos + prefix.len > input.len) continue;
        if (!std.mem.eql(u8, input[pos .. pos + prefix.len], prefix)) continue;
        const token_start = pos + prefix.len;
        const end = tokenEnd(input, token_start);
        if (end > token_start) {
            return .{ .prefix_len = prefix.len, .end = end };
        }
    }
    return null;
}

const EmailMatch = struct { start: usize, end: usize };

fn isEmailLocalChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '+' or c == '-';
}

fn isEmailDomainChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '-';
}

fn matchEmail(input: []const u8, pos: usize) ?EmailMatch {
    if (pos > 0 and isEmailLocalChar(input[pos - 1])) return null;
    var i = pos;
    while (i < input.len and isEmailLocalChar(input[i])) i += 1;
    if (i == pos) return null;
    if (i >= input.len or input[i] != '@') return null;
    i += 1;
    const domain_start = i;
    while (i < input.len and isEmailDomainChar(input[i])) i += 1;
    if (i == domain_start) return null;
    const domain = input[domain_start..i];
    const last_dot = std.mem.lastIndexOfScalar(u8, domain, '.') orelse return null;
    if (last_dot == 0) return null;
    const tld = domain[last_dot + 1 ..];
    if (tld.len < 2) return null;
    for (tld) |c| {
        if (!std.ascii.isAlphabetic(c)) return null;
    }
    return .{ .start = pos, .end = i };
}

const CardMatch = struct { start: usize, end: usize };

fn matchCard(input: []const u8, pos: usize) ?CardMatch {
    if (pos >= input.len or !std.ascii.isDigit(input[pos])) return null;
    if (pos > 0 and std.ascii.isDigit(input[pos - 1])) return null;
    var digits: [19]u8 = undefined;
    var digit_count: usize = 0;
    var i = pos;
    while (i < input.len and digit_count < 19) {
        const c = input[i];
        if (std.ascii.isDigit(c)) {
            digits[digit_count] = c;
            digit_count += 1;
            i += 1;
        } else if ((c == '-' or c == ' ') and digit_count > 0 and i + 1 < input.len and std.ascii.isDigit(input[i + 1])) {
            i += 1;
        } else {
            break;
        }
    }
    if (digit_count < 13 or digit_count > 19) return null;
    if (i < input.len and std.ascii.isDigit(input[i])) return null;
    if (!luhnValid(digits[0..digit_count])) return null;
    return .{ .start = pos, .end = i };
}

fn luhnValid(digits: []const u8) bool {
    if (digits.len == 0) return false;
    var sum: u32 = 0;
    var alt = false;
    var idx: usize = digits.len;
    while (idx > 0) {
        idx -= 1;
        var d: u32 = digits[idx] - '0';
        if (alt) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        alt = !alt;
    }
    return sum % 10 == 0;
}

const PhoneMatch = struct { start: usize, end: usize };

fn matchPhone(input: []const u8, pos: usize) ?PhoneMatch {
    if (pos >= input.len or input[pos] != '+') return null;
    if (pos > 0 and std.ascii.isAlphanumeric(input[pos - 1])) return null;
    var digit_count: usize = 0;
    var i = pos + 1;
    while (i < input.len and digit_count < 15) {
        const c = input[i];
        if (std.ascii.isDigit(c)) {
            digit_count += 1;
            i += 1;
        } else if ((c == '-' or c == ' ' or c == '(' or c == ')') and digit_count > 0) {
            i += 1;
        } else {
            break;
        }
    }
    if (digit_count < 7 or digit_count > 15) return null;
    if (i < input.len and std.ascii.isDigit(input[i])) return null;
    while (i > pos + 1) {
        const last = input[i - 1];
        if (last == ' ' or last == '-' or last == '(' or last == ')') {
            i -= 1;
        } else break;
    }
    return .{ .start = pos, .end = i };
}

const IdMatch = struct { value_start: usize, value_end: usize };

fn matchAnchoredId(input: []const u8, pos: usize) ?IdMatch {
    const keywords = [_][]const u8{
        "passport_no:", "passport_no=",
        "passport:",    "passport=",
        "id:",          "id=",
    };
    if (pos > 0) {
        const prev = input[pos - 1];
        if (std.ascii.isAlphanumeric(prev) or prev == '_' or prev == '-') return null;
    }
    for (keywords) |kw| {
        if (pos + kw.len > input.len) continue;
        if (!eqlLowercase(input[pos .. pos + kw.len], kw)) continue;
        var sep_end = pos + kw.len;
        while (sep_end < input.len and input[sep_end] == ' ') sep_end += 1;
        const value_start = sep_end;
        var value_end = value_start;
        while (value_end < input.len and std.ascii.isDigit(input[value_end])) value_end += 1;
        const digits_count = value_end - value_start;
        if (digits_count < 6 or digits_count > 12) continue;
        if (value_end < input.len) {
            const next = input[value_end];
            if (std.ascii.isAlphanumeric(next) or next == '_') continue;
        }
        return .{ .value_start = value_start, .value_end = value_end };
    }
    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "Redactor redacts email to numbered placeholder" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "contact me at user@example.com");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("contact me at [EMAIL_1]", out);
}

test "Redactor email deterministic across calls" {
    // Regression: same email mentioned in different calls must reuse the same id.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const a = try r.redact(allocator, "a@b.co");
    defer allocator.free(a);
    const b = try r.redact(allocator, "a@b.co");
    defer allocator.free(b);
    try std.testing.expectEqualStrings("[EMAIL_1]", a);
    try std.testing.expectEqualStrings("[EMAIL_1]", b);
}

test "Redactor different emails get sequential ids" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "a@b.co and x@y.zz");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("[EMAIL_1] and [EMAIL_2]", out);
}

test "Redactor phone E.164 redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "call +12025551234 now");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("call [PHONE_1] now", out);
}

test "Redactor phone without plus prefix is preserved" {
    // Regression: bare digit sequences without `+` must not match as phone numbers.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "see issue 12025551234");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("see issue 12025551234", out);
}

test "Redactor card with valid Luhn redacted" {
    // 4111 1111 1111 1111 is the standard Visa Luhn-valid test card.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "paid with 4111 1111 1111 1111");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("paid with [CARD_1]", out);
}

test "Redactor card without valid Luhn preserved" {
    // Regression: random 16-digit sequences must not match as cards.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "ref 1234567890123456");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("ref 1234567890123456", out);
}

test "Redactor passport anchored ID redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "passport: 4516378901");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("passport: [ID_1]", out);
}

test "Redactor unanchored digit run preserved" {
    // Regression: digit runs without keyword anchor must not match as IDs.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "see ticket 4516378901 next week");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("see ticket 4516378901 next week", out);
}

test "Redactor token prefix sk- redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "got sk-abcdef123");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("got [TOKEN_1]", out);
}

test "Redactor key-value secret redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "api_key=mysecret");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("api_key=[TOKEN_1]", out);
}

test "Redactor Bearer token redacted" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "auth Bearer eyJhbGciOiJ");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("auth Bearer [TOKEN_1]", out);
}

test "Redactor preserves non-sensitive text verbatim" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "hello world, no secrets here");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("hello world, no secrets here", out);
}

test "Redactor idempotent on already-redacted text" {
    // Regression: re-running redact on its own output must produce identical text.
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out1 = try r.redact(allocator, "user a@b.co exists");
    defer allocator.free(out1);
    const out2 = try r.redact(allocator, out1);
    defer allocator.free(out2);
    try std.testing.expectEqualStrings(out1, out2);
}

test "Redactor multi-category in single input" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "user a@b.co paid 4111 1111 1111 1111");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("user [EMAIL_1] paid [CARD_1]", out);
}

test "Redactor config disables category" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{ .redact_email = false });
    defer r.deinit();
    const out = try r.redact(allocator, "contact a@b.co");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("contact a@b.co", out);
}

test "Redactor empty input returns empty output" {
    const allocator = std.testing.allocator;
    var r = Redactor.init(allocator, .{});
    defer r.deinit();
    const out = try r.redact(allocator, "");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("", out);
}

test "luhnValid accepts known valid card numbers" {
    try std.testing.expect(luhnValid("4111111111111111"));
    try std.testing.expect(luhnValid("5555555555554444"));
    try std.testing.expect(luhnValid("378282246310005"));
}

test "luhnValid rejects invalid sequences" {
    try std.testing.expect(!luhnValid("1234567890123456"));
    try std.testing.expect(!luhnValid("0000000000000001"));
    try std.testing.expect(!luhnValid(""));
}
