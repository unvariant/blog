const std = @import("std");
const syscall = std.os.linux.syscall3;
const SYS = std.os.linux.SYS;

const hex_print_bits = 64;
const hex_print_t = std.meta.Int(.unsigned, hex_print_bits);
const hex_print_nibbles = @divExact(hex_print_bits, 4);

noinline fn printCharacter(ch: u8) void {
    const write: u32 = 1;
    const fd: u32 = 1;
    const len: u32 = 1;
    _ = syscall(@enumFromInt(write), fd, @intFromPtr(&ch), len);
}

noinline fn printString(str: []const u8) void {
    if (str.len != 0) {
        printCharacter(str[0]);
        @call(.always_tail, printString, .{str[1..]});
    }
}

const hex_chars: [*]const u8 = "0123456789ABCDEF";

noinline fn printRuntimeValueAsZeroPaddedHex(val: hex_print_t) void {
    var i: u6 = hex_print_nibbles - 1;
    while (true) : (i -= 1) {
        const v = @as(u4, @truncate(val >> (4 * i)));

        printCharacter(hex_chars[v]);

        if (i == 0)
            break;
    }
}

fn comptimeValToZeroPaddedHexString(in_val: anytype) [hex_print_nibbles]u8 {
    const val = @as(hex_print_t, @intCast(in_val));

    var i: u6 = 0;
    var result: [hex_print_nibbles]u8 = undefined;
    while (i < hex_print_nibbles) : (i += 1) {
        result[i] = hex_chars[@as(u4, @truncate(val >> ((hex_print_nibbles - i - 1) * 4)))];
    }
    return result;
}

inline fn formatMatches(fmt: []const u8, idx: usize, to_match: []const u8) bool {
    const curr_fmt = fmt[idx..];
    return std.mem.startsWith(u8, curr_fmt, to_match);
}

fn lengthOfIntAsString(num: anytype, comptime base: comptime_int) usize {
    if (num < base)
        return 1;
    const rest = num / base;
    return lengthOfIntAsString(rest, base) + 1;
}

fn comptimeValToString(val: anytype, comptime base: comptime_int) [lengthOfIntAsString(val, base)]u8 {
    const current = hex_chars[val % base];
    const rest = val / base;
    if (rest == 0)
        return [_]u8{current};
    return comptimeValToString(rest, base) ++ [_]u8{current};
}

noinline fn printRuntimeValue(val: usize, comptime base: comptime_int) void {
    const rest = val / base;
    if (rest != 0)
        printRuntimeValue(rest, base);
    return printCharacter(hex_chars[val % base]);
}

inline fn putComptimeStr(comptime str: []const u8) void {
    if (str.len == 1) {
        printCharacter(str[0]);
    } else {
        printString(str);
    }
}

noinline fn defaultFormatStruct(value: anytype) void {
    const arg_fields = @typeInfo(@TypeOf(value.*)).Struct.fields;

    comptime var current_fmt: [:0]const u8 = @typeName(@TypeOf(value.*)) ++ "{{ ";

    inline for (arg_fields, 0..) |field, i| {
        current_fmt = current_fmt ++ "." ++ field.name ++ " = ";
        switch (@typeInfo(field.field_type)) {
            .Int => doFmtNoEndl(current_fmt ++ "{d}", .{@field(value.*, field.name)}),
            .Struct => doFmtNoEndl(current_fmt ++ "{}", .{@field(value.*, field.name)}),
            else => @compileError("No idea how to format this struct field type: '" ++ @typeName(field.field_type) ++ "'!"),
        }
        current_fmt = if (i == current_fmt.len - 1) "" else ", ";
    }

    current_fmt = current_fmt ++ " }}";

    doFmtNoEndl(current_fmt, .{});
}

pub fn doFmtNoEndl(comptime fmt: []const u8, args: anytype) void {
    comptime var fmt_idx = 0;
    comptime var arg_idx = 0;
    comptime var current_str: []const u8 = "";

    const arg_fields = @typeInfo(@TypeOf(args)).Struct.fields;

    @setEvalBranchQuota(9999999);

    inline while (fmt_idx < fmt.len) {
        if (comptime formatMatches(fmt, fmt_idx, "{{")) {
            current_str = current_str ++ [_]u8{'{'};
            fmt_idx += 2;
        } else if (comptime formatMatches(fmt, fmt_idx, "}}")) {
            current_str = current_str ++ [_]u8{'}'};
            fmt_idx += 2;
        } else if (comptime formatMatches(fmt, fmt_idx, "{0X}")) {
            const value = @field(args, arg_fields[arg_idx].name);
            if (arg_fields[arg_idx].is_comptime) {
                current_str = current_str ++ comptime comptimeValToZeroPaddedHexString(value);
            } else {
                printString(current_str);
                current_str = "";
                printRuntimeValueAsZeroPaddedHex(value);
            }
            fmt_idx += 4;
            arg_idx += 1;
        } else if (comptime formatMatches(fmt, fmt_idx, "{X}")) {
            const value = @field(args, arg_fields[arg_idx].name);
            if (arg_fields[arg_idx].is_comptime) {
                current_str = current_str ++ comptime comptimeValToString(value, 16);
            } else {
                printString(current_str);
                current_str = "";
                printRuntimeValue(value, 16);
            }
            fmt_idx += 3;
            arg_idx += 1;
        } else if (comptime formatMatches(fmt, fmt_idx, "{d}")) {
            const value = @field(args, arg_fields[arg_idx].name);
            if (arg_fields[arg_idx].is_comptime) {
                current_str = current_str ++ comptime comptimeValToString(value, 10);
            } else {
                printString(current_str);
                current_str = "";
                printRuntimeValue(value, 10);
            }
            fmt_idx += 3;
            arg_idx += 1;
        } else if (comptime formatMatches(fmt, fmt_idx, "{e}")) {
            const value = @field(args, arg_fields[arg_idx].name);

            switch (@typeInfo(@TypeOf(value))) {
                .Enum => current_str = current_str ++ @typeName(@TypeOf(value)),
                else => {},
            }
            current_str = current_str ++ ".";

            if (arg_fields[arg_idx].is_comptime) {
                current_str = current_str ++ comptime @tagName(value);
            } else {
                printString(current_str);
                current_str = "";
                printString(@tagName(value));
            }
            fmt_idx += 3;
            arg_idx += 1;
        } else if (comptime formatMatches(fmt, fmt_idx, "{s}")) {
            const value = @field(args, arg_fields[arg_idx].name);
            if (arg_fields[arg_idx].is_comptime) {
                current_str = current_str ++ comptime value;
            } else {
                printString(current_str);
                current_str = "";
                // TODO: Different paths depending on the string type: [*:0]const u8, []const u8, ...
                // For now we just assume [*:0]const u8
                printString(value);
            }
            fmt_idx += 3;
            arg_idx += 1;
        } else if (comptime formatMatches(fmt, fmt_idx, "{c}")) {
            const value = @field(args, arg_fields[arg_idx].name);
            if (arg_fields[arg_idx].is_comptime) {
                current_str = current_str ++ comptime [_]u8{value};
            } else {
                printString(current_str);
                current_str = "";
                printCharacter(value);
            }
            fmt_idx += 3;
            arg_idx += 1;
        } else if (comptime formatMatches(fmt, fmt_idx, "{}")) {
            const value = @field(args, arg_fields[arg_idx].name);
            printString(current_str);
            current_str = "";

            if (comptime @hasDecl(@TypeOf(value), "format")) {
                @call(.never_inline, value.format, .{});
            } else {
                defaultFormatStruct(&value);
            }
            fmt_idx += 2;
            arg_idx += 1;
        } else if (comptime formatMatches(fmt, fmt_idx, "{")) {
            @compileError("Unknown format specifier: '" ++ [_]u8{fmt[fmt_idx + 1]} ++ "'");
        } else {
            current_str = current_str ++ [_]u8{fmt[fmt_idx]};
            fmt_idx += 1;
        }
    }

    putComptimeStr(current_str);

    if (arg_idx < arg_fields.len) {
        @compileError("Unused fmt arguments!");
    }
}

pub inline fn doFmt(comptime fmt: []const u8, args: anytype) void {
    return doFmtNoEndl(fmt ++ "\n", args);
}

fn rdrand() u64 {
    return asm volatile ("rdrand %[result]"
        : [result] "=r" (-> u64),
    );
}

const TestStructWithFormat = struct {
    value: u64,

    pub const format = (struct {
        pub fn f(self: *const TestStructWithFormat) void {
            doFmtNoEndl("{{ .value = {0X} }}", .{self.value});
        }
    }.f);
};

const TestEnum = enum {
    World,
};

const TestStructWithoutFormat = struct {
    value: u64,

    oobooii: TestStructWithFormat = .{ .value = 5 },
};

export fn _start() linksection(".entry") noreturn {
    const ptr = &_start;
    _ = ptr;
    doFmt("hello my address is at {X}", .{@intFromPtr(&_start)});
    const a: TestEnum = .World;
    doFmt("{e}", .{a});
    while (true) {}
    // unreachable;
}
