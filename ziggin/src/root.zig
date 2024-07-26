const std = @import("std");
const testing = std.testing;
const print = std.debug.print;
const py = @cImport({
    @cDefine("Py_LIMITED_API", "0x030a00f0");
    @cDefine("PY_SSIZE_T_CLEAN", {});
    @cInclude("Python.h");
});

const PyObject = py.PyObject;
const PyMethodDef = py.PyMethodDef;
const PyModuleDef = py.PyModuleDef;
const PyModuleDef_Base = py.PyModuleDef_Base;
const Py_BuildValue = py.Py_BuildValue;
const PyModule_Create = py.PyModule_Create;

// TODO maybe use?
// const Buffer = packed struct {
//     valid_buffer: ?[*]bool,
//     main_buffer: ?[*]anyopaque,
//     data_buffer: ?[*]u8,
// };

const Decimal = packed struct {
    size: u8,
    precision: u8,
    sign: i8,
    int_data: i128,
};

const DateTime64 = packed struct {
    /// unit is 100ns
    time: u40,
    date: u24,

    inline fn from_ns_factor(val: i64, ns_factor: i64) !DateTime64 {
        const as_ns = val * ns_factor;
        const ns_in_day = 1000 * 1000 * 1000 * 60 * 60 * 24;
        return DateTime64{
            .date = try DateTime64.date_arrow_to_bcp(@divFloor(as_ns, ns_in_day)),
            .time = @intCast(@divFloor(@mod(as_ns, ns_in_day), 100)),
        };
    }

    inline fn date_arrow_to_bcp(val_arrow: anytype) !u24 {
        return std.math.cast(u24, val_arrow + 719162) orelse return WriteError.int_cast;
    }

    inline fn date_bcp_to_arrow(val_bcp: u24) i32 {
        return val_bcp - 719162;
    }

    inline fn to_ns(self: DateTime64) i64 {
        const ns_in_day = 1000 * 1000 * 1000 * 60 * 60 * 24;
        return @as(i64, date_bcp_to_arrow(self.date)) * ns_in_day + @as(i64, self.time) * 100;
    }
};

const DateTimeOffset = packed struct {
    time: u40,
    date: u24,
    offset: i16,

    inline fn from_ns_factor(val: i64, ns_factor: i64, offset: i16) !DateTimeOffset {
        const dt64 = try DateTime64.from_ns_factor(val, ns_factor);
        return DateTimeOffset{
            .time = dt64.time,
            .date = dt64.date,
            .offset = offset,
        };
    }
};

fn dummy_release_schema(self: *ArrowSchema) void {
    // _ = self;
    // unreachable; // handled by capsule
    // self.private_data.deinit();
    self.release = null;
}

const ArrowSchema = extern struct {
    // Array type description
    format: [*:0]const u8,
    name: ?[*:0]const u8 = null,
    metadata: ?[*]const u8 = null,
    flags: i64 = 0,
    n_children: i64 = 0,
    children: ?[*][*]ArrowSchema = null,
    dictionary: ?[*]ArrowSchema = null,

    // Release callback
    release: ?*fn (*ArrowSchema) void = @constCast(&dummy_release_schema),
    // Opaque producer-specific data
    private_data: ?*anyopaque = null,
};

fn release_state(state: *StateContainer) void {
    state.arena.deinit();
    state.file.close();
}
const StateContainer = struct {
    arena: std.heap.ArenaAllocator,
    columns: []ReaderState,
    file: std.fs.File,
    release: ?*fn (*StateContainer) void = @constCast(&release_state),
};

const ReaderState = struct {
    parent: *StateContainer,
    schema: *ArrowSchema,
    decimal: ?struct { size: u8, precision: u8 } = null,
    offset: ?i16 = null,
    format: formats_sql,
    read_cell: type_read_cell,

    inline fn has_data_buffer(self: ReaderState) bool {
        return switch (self.format) {
            .char, .binary => true,
            else => false,
        };
    }

    inline fn read(self: *ReaderState, target_ptr: anytype) !bool {
        const info = @typeInfo(@TypeOf(target_ptr)).Pointer;
        const target_as_bytes = switch (info.size) {
            inline .One => std.mem.asBytes(target_ptr)[0..@divExact(@bitSizeOf(info.child), 8)],
            inline .Slice => target_ptr,
            inline else => comptime unreachable,
        };

        const bytes_read = self.parent.file.read(target_as_bytes) catch return ReadError.file_error;

        if (bytes_read == target_as_bytes.len) {
            return true;
        } else if (bytes_read == 0) {
            return false;
        } else {
            return ReadError.EOF_unexpected;
        }
    }

    fn validate_decimal(self: *ReaderState, size: u8, precision: u8) !void {
        if (self.decimal) |dec| {
            if (size != dec.size or precision != dec.precision) {
                return ReadError.DecimalChanged;
            }
        } else {
            self.decimal = .{ .size = size, .precision = precision };
            self.schema.format = std.fmt.allocPrintZ(
                self.parent.arena.allocator(),
                "d:{},{}",
                .{ size, precision },
            ) catch return ReadError.no_memory;
        }
    }

    fn validate_timezone(self: *ReaderState, offset: i16) !void {
        if (self.offset) |off| {
            if (off != offset) {
                return ReadError.TimezoneChanged;
            }
        } else {
            self.offset = offset;
            const sign: u8 = if (offset >= 0) '+' else blk: {
                offset = -offset;
                break :blk '-';
            };
            const hours: i16 = @divFloor(offset, 60);
            const minutes: i16 = @mod(offset, 60);
            self.schema.format = std.fmt.allocPrintZ(
                self.parent.arena.allocator(),
                "tsn:{c}{}{}",
                .{ sign, hours, minutes },
            ) catch return ReadError.no_memory;
        }
    }
};

fn release_array(self: *ArrowArray) void {
    for (self.buffers[0..@intCast(self.n_buffers)]) |buf| {
        std.c.free(buf);
    }
    std.c.free(@ptrCast(self.buffers));
    self.release = null;
}

const ArrowArray = extern struct {
    // Array data description
    length: i64,
    null_count: i64,
    offset: i64 = 0,
    n_buffers: i64,
    n_children: i64 = 0,
    buffers: [*]?*anyopaque,
    children: ?[*][*]ArrowArray = null,
    dictionary: ?[*]ArrowArray = null,

    // Release callback
    release: ?*fn (*ArrowArray) void = @constCast(&release_array),
    // Opaque producer-specific data, must be pointer sized
    // private_data: ?*anyopaque = null,
    length_data_buffer: usize,
};

fn capsule_name(T: type) [*c]const u8 {
    return switch (T) {
        ArrowArray => "arrow_array",
        ArrowSchema => "arrow_schema",
        StateContainer => "arrow_bcp_reader_state",
        else => unreachable,
    };
}

fn from_capsule(T: type, capsule: *PyObject) ?*T {
    const ptr = py.PyCapsule_GetPointer(capsule, capsule_name(T)) orelse return null;
    return @alignCast(@ptrCast(ptr));
}

fn to_capsule(c_data: anytype) !*PyObject {
    const T = @typeInfo(@TypeOf(c_data)).Pointer.child;
    const dummy = struct {
        fn release_capsule(capsule: ?*PyObject) callconv(.C) void {
            if (capsule) |c| {
                if (from_capsule(T, c)) |c_data_inner| {
                    if (c_data_inner.release) |release| {
                        release(c_data_inner);
                    }
                    malloc.destroy(c_data_inner);
                }
            }
        }
    };
    return py.PyCapsule_New(
        @ptrCast(c_data),
        capsule_name(T),
        @constCast(&dummy.release_capsule),
    ) orelse return Err.PyError;
}

const ArrowError = error{MissingBuffer};
const Err = error{PyError};
const Exceptions = enum { Exception, NotImplemented, TypeError, ValueError };

fn raise_args(exc: Exceptions, comptime msg: []const u8, args: anytype) Err {
    @setCold(true);
    const pyexc = switch (exc) {
        .Exception => py.PyExc_Exception,
        .NotImplemented => py.PyExc_NotImplementedError,
        .TypeError => py.PyExc_TypeError,
        .ValueError => py.PyExc_ValueError,
    };
    const formatted = std.fmt.allocPrintZ(allocator, msg, args) catch "Error formatting error message";
    defer allocator.free(formatted);
    py.PyErr_SetString(pyexc, formatted.ptr);
    return Err.PyError;
}

fn raise(exc: Exceptions, comptime msg: []const u8) Err {
    return raise_args(exc, msg, .{});
}

// I think this is required because of arrow's data moving behavior
const malloc = std.heap.raw_c_allocator;

var gpa = std.heap.GeneralPurposeAllocator(.{
    .safety = true,
    // .never_unmap = true,
    // .retain_metadata = true,
}){};
const allocator = gpa.allocator();

const BcpInfo = struct {
    writer: writer_type,
    format: formats,
    dtype_name: []u8,
    decimal_size: u8 = 0,
    decimal_precision: u8 = 0,
    timestamp_timezone_offset: i16 = 0,
    timestamp_factor_ns: i64 = 0,

    fn init(
        format: formats,
        comptime dtype_name: []const u8,
    ) !BcpInfo {
        return BcpInfo{
            .writer = writers.get(format),
            .format = format,
            .dtype_name = try std.fmt.allocPrint(allocator, dtype_name, .{}),
        };
    }

    fn deinit(self: BcpInfo) void {
        allocator.free(self.dtype_name);
    }

    fn from_format(fmt: []const u8) !BcpInfo {
        if (fmt.len == 1) {
            return switch (fmt[0]) {
                'b' => try BcpInfo.init(.boolean, "SQLBIT"),
                'c' => try BcpInfo.init(.int8, "SQLSMALLINT"),
                'C' => try BcpInfo.init(.uint8, "SQLTINYINT"),
                's' => try BcpInfo.init(.int16, "SQLSMALLINT"),
                'S' => try BcpInfo.init(.uint16, "SQLINT"),
                'i' => try BcpInfo.init(.int32, "SQLINT"),
                'I' => try BcpInfo.init(.uint32, "SQLBIGINT"),
                'l' => try BcpInfo.init(.int64, "SQLBIGINT"),
                'L' => try BcpInfo.init(.uint64, "SQLDECIMAL"),
                'e' => try BcpInfo.init(.float16, "SQLFLT4"),
                'f' => try BcpInfo.init(.float32, "SQLFLT4"),
                'g' => try BcpInfo.init(.float64, "SQLFLT8"),
                'z' => try BcpInfo.init(.bytes, "SQLBINARY"),
                'u' => try BcpInfo.init(.bytes, "SQLCHAR"),
                else => raise_args(.NotImplemented, "Format '{s}' not implemented", .{fmt}),
            };
        } else {
            if (fmt[0] == 'd') {
                // Decimal seems to always have the indicator byte
                var bcp_info = try BcpInfo.init(.decimal, "SQLDECIMAL");
                if (fmt[1] != ':') {
                    return raise_args(.TypeError, "Expecting ':' as second character of decimal format string '{s}'", .{fmt});
                }
                var iter = std.mem.tokenizeScalar(u8, fmt[2..], ',');
                bcp_info.decimal_size = try std.fmt.parseInt(u8, iter.next() orelse {
                    return raise_args(.TypeError, "Incomplete decimal format string '{s}'", .{fmt});
                }, 10);
                bcp_info.decimal_precision = try std.fmt.parseInt(u8, iter.next() orelse {
                    return raise_args(.TypeError, "Incomplete decimal format string '{s}'", .{fmt});
                }, 10);
                if (iter.next() != null) {
                    return raise(.NotImplemented, "Non 128 bit decimals are not supported");
                }
                return bcp_info;
            }
            if (std.mem.eql(u8, fmt, "tdD")) {
                return try BcpInfo.init(.date, "SQLDATE");
            }
            if (std.mem.eql(u8, fmt, "tdm")) {
                return try BcpInfo.init(.datetime, "SQLDATETIME2");
            }
            if (std.mem.eql(u8, fmt[0..2], "ts")) {
                if (fmt[3] != ':') {
                    return raise_args(.TypeError, "Expecting ':' as fourth character of timestamp format string '{s}'", .{fmt});
                }
                const timezone = fmt[4..];
                const factor_ns: i64 = switch (fmt[2]) {
                    'n' => 1,
                    'u' => 1000,
                    'm' => 1000 * 1000,
                    's' => 1000 * 1000 * 1000,
                    else => {
                        return raise(.TypeError, "Expected timestamp with seconds/ms/us/ns as precision");
                    },
                };
                if (timezone.len == 0) {
                    var bcp_info = try BcpInfo.init(.timestamp, "SQLDATETIME2");
                    bcp_info.timestamp_factor_ns = factor_ns;
                    return bcp_info;
                } else {
                    var bcp_info = try BcpInfo.init(.timestamp_timezone, "SQLDATETIMEOFFSET");
                    bcp_info.timestamp_factor_ns = factor_ns;
                    const sign: i16 = switch (timezone[0]) {
                        '+' => 1,
                        '-' => -1,
                        else => {
                            return raise_args(.TypeError, "Invalid timezone sign for format string '{s}'", .{fmt});
                        },
                    };
                    var iter = std.mem.tokenizeScalar(u8, timezone[1..], ':');
                    const hours = try std.fmt.parseInt(i16, iter.next() orelse {
                        return raise_args(.TypeError, "Error parsing timezone hour for format string '{s}'", .{fmt});
                    }, 10);
                    const minutes = try std.fmt.parseInt(i16, iter.next() orelse {
                        return raise_args(.TypeError, "Error parsing timezone minute for format string '{s}'", .{fmt});
                    }, 10);
                    if (iter.next() != null) {
                        return raise_args(.TypeError, "Invalid timestamp format string '{s}'", .{fmt});
                    }
                    bcp_info.timestamp_timezone_offset = sign * (hours * 60 + minutes);
                    return bcp_info;
                }
            }
            return raise_args(.NotImplemented, "Format '{s}' not implemented", .{fmt});
        }
    }
};

const Column = struct {
    schema: ArrowSchema,
    current_array: ArrowArray,
    next_index: u32,
    _chunk_generator: *PyObject,

    // Arrow memory is freed when capsules get garbage collected
    _schema_capsule: *PyObject,
    _current_array_capsule: ?*PyObject,
    bcp_info: BcpInfo,

    fn deinit(self: Column) void {
        py.Py_DECREF(self._schema_capsule);
        py.Py_DECREF(self._chunk_generator);
        py.Py_XDECREF(self._current_array_capsule);
        self.bcp_info.deinit(); // TODO ??
    }

    fn get_next_array(self: *Column) !bool {
        // return false if no more data
        if (self._current_array_capsule) |capsule| {
            defer py.Py_DECREF(capsule);
            self._current_array_capsule = null;
        }
        const array_capsule = py.PyIter_Next(self._chunk_generator) orelse {
            if (py.PyErr_Occurred() != null) {
                return Err.PyError;
            }
            return false;
        };
        defer py.Py_DECREF(array_capsule);
        const array_ptr = py.PyCapsule_GetPointer(array_capsule, "arrow_array") orelse return Err.PyError;
        const current_array_ptr: *ArrowArray = @alignCast(@ptrCast(array_ptr));
        if (current_array_ptr.offset != 0) {
            return raise(.NotImplemented, "ArrowArray offset field is not supported");
        }
        if (current_array_ptr.n_buffers < 2 and current_array_ptr.length > 0) {
            // TODO add check for data buffer when needed
            return raise(.Exception, "Too few buffers");
        }
        self.next_index = 0;
        self.current_array = current_array_ptr.*;
        self._current_array_capsule = py.Py_NewRef(array_capsule);
        return true;
    }

    inline fn valid_buffer(self: *Column) ?[*]bool {
        return @alignCast(@ptrCast(self.current_array.buffers[0]));
    }

    inline fn main_buffer(self: *Column, tp: type) ![*]tp {
        return @alignCast(@ptrCast(self.current_array.buffers[1] orelse return WriteError.missing_buffer));
    }

    inline fn data_buffer(self: *Column) ![*]u8 {
        return @alignCast(@ptrCast(self.current_array.buffers[2] orelse return WriteError.missing_buffer));
    }
};

const formats = enum(i64) {
    boolean,
    int8,
    uint8,
    int16,
    uint16,
    int32,
    uint32,
    int64,
    uint64,
    float16,
    float32,
    float64,
    bytes,
    decimal,
    date,
    datetime,
    timestamp,
    timestamp_timezone,
};

inline fn format_types(comptime format: formats) struct { prefix: type, arrow: type, bcp: type } {
    const types = switch (format) {
        inline formats.boolean => .{ i8, bool, u8 },
        inline formats.int8 => .{ i8, i8, i16 },
        inline formats.uint8 => .{ i8, u8, u8 },
        inline formats.int16 => .{ i8, i16, i16 },
        inline formats.uint16 => .{ i8, u16, i32 },
        inline formats.int32 => .{ i8, i32, i32 },
        inline formats.uint32 => .{ i8, u32, i64 },
        inline formats.int64 => .{ i8, i64, i64 },
        inline formats.uint64 => .{ i8, u64, Decimal },
        inline formats.float16 => .{ i8, f16, f32 },
        inline formats.float32 => .{ i8, f32, f32 },
        inline formats.float64 => .{ i8, f64, f64 },
        inline formats.bytes => .{ i64, u32, u32 },
        inline formats.decimal => .{ i8, i128, Decimal },
        inline formats.date => .{ i8, i32, u24 },
        inline formats.datetime => .{ i8, i64, DateTime64 },
        inline formats.timestamp => .{ i8, i64, DateTime64 },
        inline formats.timestamp_timezone => .{ i8, i64, DateTimeOffset },
    };
    return .{
        .prefix = types[0],
        .arrow = types[1],
        .bcp = types[2],
    };
}

const format_sizes = blk: {
    const size = struct { prefix: usize, bcp: usize };

    var arr = std.EnumArray(formats, size).initUndefined();
    for (std.enums.values(formats)) |fmt| {
        const types = format_types(fmt);
        arr.set(fmt, size{
            .prefix = @divExact(@bitSizeOf(types.prefix), 8),
            .bcp = @divExact(@bitSizeOf(types.bcp), 8),
        });
    }

    break :blk arr;
};

inline fn bit_get(ptr: anytype, index: anytype) bool {
    const ptr_cast: [*]u8 = @alignCast(@ptrCast(ptr));
    const selector: u3 = @intCast(index % 8);
    return 0 == (ptr_cast[@divFloor(index, 8)] & (@as(u8, 1) << selector));
}

inline fn bit_set(ptr: anytype, index: anytype, comptime value: bool) void {
    const ptr_cast: [*]u8 = @alignCast(@ptrCast(ptr));
    const selector: u3 = @intCast(index % 8);
    if (comptime value) {
        ptr_cast[@divFloor(index, 8)] |= @as(u8, 1) << selector;
    } else {
        ptr_cast[@divFloor(index, 8)] &= 0xFF ^ (@as(u8, 1) << selector);
    }
}

const WriteError = error{ write_error, missing_buffer, int_cast };
inline fn write(self: *Column, file: *std.fs.File, comptime format: formats) WriteError!void {
    const types = format_types(format);
    const types_size = comptime format_sizes.get(format);
    const main_buffer = try self.main_buffer(types.arrow);
    const bytes_bcp: usize = switch (format) {
        inline .bytes => main_buffer[self.next_index + 1] - main_buffer[self.next_index],
        inline else => types_size.bcp,
    };

    const is_null = if (self.valid_buffer()) |buf| bit_get(buf, self.next_index) else false;

    _ = file.write(blk: {
        const val: types.prefix = if (is_null) -1 else @intCast(bytes_bcp);
        const bytes: [*]u8 = @constCast(@ptrCast(&val));
        break :blk bytes[0..types_size.prefix];
    }) catch return WriteError.write_error;

    if (is_null) {
        return;
    }

    if (format == .bytes) {
        const data_buffer = try self.data_buffer();
        _ = file.write(data_buffer[main_buffer[self.next_index]..main_buffer[self.next_index + 1]]) catch return WriteError.write_error;
    } else {
        const val_arrow = if (format == .boolean)
            bit_get(main_buffer, self.next_index)
        else
            main_buffer[self.next_index];
        const val_bcp = switch (format) {
            inline .decimal => Decimal{
                .size = self.bcp_info.decimal_size,
                .precision = self.bcp_info.decimal_precision,
                .sign = if (val_arrow >= 0) 1 else 0,
                .int_data = if (val_arrow >= 0) val_arrow else -val_arrow,
            },
            inline .date => try DateTime64.date_arrow_to_bcp(val_arrow),
            inline .datetime => try DateTime64.from_ns_factor(val_arrow, 1000 * 1000),
            inline .timestamp => try DateTime64.from_ns_factor(val_arrow, self.bcp_info.timestamp_factor_ns),
            inline .timestamp_timezone => try DateTimeOffset.from_ns_factor(val_arrow, self.bcp_info.timestamp_factor_ns, self.bcp_info.timestamp_timezone_offset),
            inline .boolean => blk: {
                const val: types.bcp = @intFromBool(val_arrow);
                break :blk val;
            },
            inline .uint64 => Decimal{
                .size = 20,
                .precision = 0,
                .sign = 1,
                .int_data = val_arrow,
            },
            inline else => @as(types.bcp, val_arrow),
        };
        _ = file.write(blk: {
            const bytes: [*]u8 = @constCast(@ptrCast(&val_bcp));
            break :blk bytes[0..bytes_bcp];
        }) catch return WriteError.write_error;
    }
}

const writer_type = *fn (*Column, *std.fs.File) @typeInfo(@TypeOf(write)).Fn.return_type.?;

const writers = blk: {
    var arr = std.EnumArray(formats, writer_type).initUndefined();
    for (std.enums.values(formats)) |fmt| {
        const dummy = struct {
            fn write_fmt(self: *Column, file: *std.fs.File) !void {
                try write(self, file, fmt);
            }
        };
        arr.set(fmt, @constCast(&dummy.write_fmt));
    }
    break :blk arr;
};

/// Parse Python value into Zig type. Memory management for strings is handled by Python.
/// This also means that once the original Python string is garbage collected the pointer is dangling.
fn py_to_zig(zig_type: type, py_value: *py.PyObject) !zig_type {
    switch (@typeInfo(zig_type)) {
        .Int => |info| {
            const val = if (info.signedness == .signed) py.PyLong_AsLongLong(py_value) else py.PyLong_AsUnsignedLongLong(py_value);
            if (py.PyErr_Occurred() != null) {
                return Err.PyError;
            }
            return std.math.cast(zig_type, val) orelse return raise(.ValueError, "Expected smaller integer");
        },
        .Pointer => |info| {
            if (info.child == u8) {
                var size: py.Py_ssize_t = -1;
                const char_ptr = py.PyUnicode_AsUTF8AndSize(py_value, &size) orelse return Err.PyError;
                // _ = char_ptr;
                if (size < 0) {
                    return Err.PyError;
                }
                return char_ptr[0..@intCast(size)];
            }
            if (info.child == py.PyObject) {
                return py.Py_NewRef(py_value);
            }
        },
        .Struct => |info| {
            _ = info;
            var zig_value: zig_type = undefined;
            const py_value_iter = py.PyObject_GetIter(py_value) orelse return Err.PyError;
            defer py.Py_DECREF(py_value_iter);
            inline for (std.meta.fields(zig_type), 0..) |field, i_field| {
                _ = i_field;
                const py_value_inner = py.PyIter_Next(py_value_iter) orelse {
                    if (py.PyErr_Occurred() != null) {
                        return Err.PyError;
                    }
                    return raise(.TypeError, "Expected more values");
                };
                defer py.Py_DECREF(py_value_inner);
                @field(zig_value, field.name) = try py_to_zig(
                    @TypeOf(@field(zig_value, field.name)),
                    py_value_inner,
                );
            }
            const should_not_be_a_value = py.PyIter_Next(py_value_iter) orelse {
                if (py.PyErr_Occurred() != null) {
                    return Err.PyError;
                }
                return zig_value;
            };
            py.Py_DECREF(should_not_be_a_value);
            return raise(.TypeError, "Expected less values");
        },
        else => @compileLog("unsupported conversion from py to zig", @typeInfo(zig_type)),
    }
    @compileLog("unsupported conversion from py to zig", @typeInfo(zig_type));
}

fn zig_to_py(value: anytype) !*py.PyObject {
    const info = @typeInfo(@TypeOf(value));
    return switch (info) {
        .Int => if (info.Int.signedness == .signed) py.PyLong_FromLongLong(@as(c_longlong, value)) else py.PyLong_FromUnsignedLongLong(@as(c_ulonglong, value)),
        .ComptimeInt => if (value < 0) py.PyLong_FromLongLong(@as(c_longlong, value)) else py.PyLong_FromUnsignedLongLong(@as(c_ulonglong, value)),
        // .Pointer => ,
        .Pointer => |pinfo| if (pinfo.child == u8)
            py.PyUnicode_FromStringAndSize(value.ptr, @intCast(value.len))
        else if (pinfo.child == py.PyObject)
            py.Py_NewRef(value)
        else
            unreachable,
        .Struct => blk: {
            const tuple = py.PyTuple_New(value.len) orelse return Err.PyError;
            errdefer py.Py_DECREF(tuple);
            inline for (std.meta.fields(@TypeOf(value)), 0..) |field, i_field| {
                const inner_value = @field(value, field.name);
                const py_value = try zig_to_py(inner_value);
                if (py.PyTuple_SetItem(tuple, @intCast(i_field), py_value) == -1) {
                    py.Py_DECREF(py_value);
                    return Err.PyError;
                }
            }
            break :blk tuple;
        },
        else => @compileLog("unsupported py-type conversion", info),
    } orelse return Err.PyError;
}

fn write_arrow(args: ?*PyObject) !?*PyObject {
    const list_schema_capsules = py.PySequence_GetItem(args, 0) orelse return Err.PyError;
    defer py.Py_DECREF(list_schema_capsules);
    const list_array_capsule_generators = py.PySequence_GetItem(args, 1) orelse return Err.PyError;
    defer py.Py_DECREF(list_array_capsule_generators);
    const nr_columns: usize = blk: {
        const len = py.PyObject_Length(list_schema_capsules);
        break :blk if (len == -1) return Err.PyError else @intCast(len);
    };
    var columns = allocator.alloc(Column, nr_columns) catch {
        _ = py.PyErr_NoMemory();
        return Err.PyError;
    };
    defer allocator.free(columns);
    var n_allocated_columns: usize = 0;
    defer for (columns[0..n_allocated_columns]) |col| {
        col.deinit();
    };
    const columns_slice = columns[0..nr_columns];
    for (columns_slice, 0..) |*col, i_col| {
        const capsule_schema = py.PySequence_GetItem(list_schema_capsules, @intCast(i_col)) orelse return Err.PyError;
        defer py.Py_DECREF(capsule_schema);
        const chunk_generator = py.PySequence_GetItem(list_array_capsule_generators, @intCast(i_col)) orelse return Err.PyError;
        defer py.Py_DECREF(chunk_generator);
        const schema_ptr = py.PyCapsule_GetPointer(capsule_schema, "arrow_schema") orelse return Err.PyError;
        const schema: *ArrowSchema = @alignCast(@ptrCast(schema_ptr));

        col.* = Column{
            ._chunk_generator = py.Py_NewRef(chunk_generator),
            .current_array = undefined,
            .schema = schema.*,
            ._schema_capsule = py.Py_NewRef(capsule_schema),
            ._current_array_capsule = null,
            .next_index = 0,
            .bcp_info = undefined,
        };
        n_allocated_columns += 1;

        if (!try col.get_next_array()) {
            return raise(.Exception, "Expecting at least one array chunk");
        }

        const fmt = col.schema.format[0..std.mem.len(col.schema.format)];
        col.bcp_info = try BcpInfo.from_format(fmt);
    }
    var file = std.fs.createFileAbsoluteZ("/tmp/arrowwrite.dat", .{}) catch {
        return raise(.Exception, "Error opening file");
    };
    defer file.close();
    main_loop: while (true) {
        for (columns_slice, 0..) |*col, i_col| {
            if (col.next_index >= col.current_array.length and !try col.get_next_array()) {
                for (columns_slice[i_col + 1 .. columns_slice.len]) |*col_| {
                    if (i_col != 0 or try col_.get_next_array()) {
                        return raise(.Exception, "Arrays don't have equal length");
                    }
                }
                break :main_loop;
            }
            col.bcp_info.writer(col, &file) catch unreachable;
            col.next_index += 1;
        }
    }

    const format_list = py.PyList_New(0) orelse return Err.PyError;
    errdefer py.Py_DECREF(format_list);
    for (columns_slice) |*col| {
        const sizes = format_sizes.get(col.bcp_info.format);
        const item = try zig_to_py(.{
            col.bcp_info.dtype_name,
            sizes.prefix,
            sizes.bcp,
        });
        defer py.Py_DECREF(item);
        if (py.PyList_Append(format_list, item) == -1) {
            return Err.PyError;
        }
    }
    return format_list;
}

fn ext_write_arrow(module: ?*PyObject, args: ?*PyObject) callconv(.C) ?*PyObject {
    _ = module;
    return write_arrow(args) catch |err| switch (err) {
        Err.PyError => return null,
        else => unreachable,
    };
}

const formats_sql = enum(u8) {
    bit,
    tiny,
    smallint,
    int,
    bigint,
    float,
    real,
    decimal,
    date,
    datetime2,
    datetimeoffset,
    uniqueidentifier,
    char,
    binary,
};

const type_read_cell = *fn (usize, *ReaderState, *ArrowArray) ReadError!void;

const format_info_sql = blk: {
    var kvs_bcp_format: [std.enums.values(formats_sql).len]struct { []const u8, formats_sql } = undefined;
    var format_strings = std.EnumArray(formats_sql, []const u8).initUndefined();
    var readers = std.EnumArray(formats_sql, type_read_cell).initUndefined();
    var types = std.EnumArray(formats_sql, struct { prefix: type, bcp: type, arrow: type }).initUndefined();
    var bit_sizes = std.EnumArray(formats_sql, struct { prefix: u15, bcp: u15, arrow: u15 }).initUndefined();
    for (std.enums.values(formats_sql), 0..) |fmt, i_fmt| {
        const info = switch (fmt) {
            // scale/precision and timezone are unknown until first row is read => mark as null type initially
            formats_sql.bit => .{ i8, u8, u1, "b", "SQLBIT" },
            formats_sql.tiny => .{ i8, u8, u8, "C", "SQLTINYINT" },
            formats_sql.smallint => .{ i8, i16, i16, "s", "SQLSMALLINT" },
            formats_sql.int => .{ i8, i32, i32, "i", "SQLINT" },
            formats_sql.bigint => .{ i8, i64, i64, "l", "SQLBIGINT" },
            formats_sql.float => .{ i8, f32, f32, "f", "SQLFLT4" },
            formats_sql.real => .{ i8, f64, f64, "g", "SQLFLT8" },
            formats_sql.decimal => .{ i8, Decimal, i128, "n", "SQLDECIMAL" },
            formats_sql.date => .{ i8, u24, i32, "tdD", "SQLDATE" },
            formats_sql.datetime2 => .{ i8, DateTime64, i64, "tsn:", "SQLDATETIME2" },
            formats_sql.datetimeoffset => .{ i8, DateTimeOffset, i64, "n", "SQLDATETIMEOFFSET" },
            formats_sql.uniqueidentifier => .{ i8, [16]u8, [16]u8, "w:16", "SQLUNIQUEID" },
            formats_sql.char => .{ i64, u0, u32, "u", "SQLCHAR" },
            formats_sql.binary => .{ i64, u0, u32, "z", "SQLBINARY" },
        };
        format_strings.set(fmt, info[3] ++ "\x00");
        const dummy = struct {
            fn read_cell_fmt(i_row: usize, state: *ReaderState, arr: *ArrowArray) ReadError!void {
                return try read_cell(i_row, state, arr, fmt);
            }
        };
        readers.set(fmt, @constCast(&dummy.read_cell_fmt));
        types.set(fmt, .{
            .prefix = info[0],
            .bcp = info[1],
            .arrow = info[2],
        });
        bit_sizes.set(fmt, .{
            .prefix = @bitSizeOf(info[0]),
            .bcp = @bitSizeOf(info[1]),
            .arrow = @bitSizeOf(info[2]),
        });
        kvs_bcp_format[i_fmt] = .{ info[4], fmt };
    }
    const enum_from_bcp = std.StaticStringMap(formats_sql).initComptime(kvs_bcp_format);

    const T = struct {
        format_strings: @TypeOf(format_strings),
        readers: @TypeOf(readers),
        types: @TypeOf(types),
        bit_sizes: @TypeOf(bit_sizes),
        enum_from_bcp: @TypeOf(enum_from_bcp),
    };
    break :blk T{
        .format_strings = format_strings,
        .readers = readers,
        .types = types,
        .bit_sizes = bit_sizes,
        .enum_from_bcp = enum_from_bcp,
    };
};

fn init_reader(py_args: ?*PyObject) !*PyObject {
    const args = try py_to_zig(
        struct { bcp_columns: *PyObject },
        py_args orelse return raise(.Exception, "No arguments passed"),
    );
    defer py.Py_DECREF(args.bcp_columns);

    const nr_columns: usize = blk: {
        const len = py.PyObject_Length(args.bcp_columns);
        break :blk if (len == -1) return Err.PyError else @intCast(len);
    };

    var capsule_has_state_ownership = false;
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer if (!capsule_has_state_ownership) arena.deinit();
    var arena_alloc = arena.allocator();
    const states = try arena_alloc.alloc(ReaderState, nr_columns);
    const container = try malloc.create(StateContainer);
    errdefer if (!capsule_has_state_ownership) malloc.destroy(container);
    var file = std.fs.openFileAbsoluteZ("/tmp/arrowwrite.dat", .{}) catch {
        return raise(.Exception, "Error opening file");
    };
    errdefer if (!capsule_has_state_ownership) file.close();
    container.* = .{
        .arena = arena,
        .columns = states,
        .file = file,
    };

    const schema_capsules = py.PyTuple_New(@intCast(nr_columns)) orelse return Err.PyError;
    defer py.Py_DECREF(schema_capsules);

    for (states, 0..) |*state, i_col| {
        const capsule = blk: {
            const py_bcp_column = py.PySequence_GetItem(args.bcp_columns, @intCast(i_col)) orelse return Err.PyError;
            defer py.Py_DECREF(py_bcp_column);

            const unpacked = try py_to_zig(
                struct { sql_type: []const u8, size_prefix: u32, size_data: u32 },
                py_bcp_column,
            );

            const format_sql = format_info_sql.enum_from_bcp.get(unpacked.sql_type) orelse return raise_args(.TypeError, "Unsupported SQL type {s}", .{unpacked.sql_type});
            const bit_sizes = format_info_sql.bit_sizes.get(format_sql);
            if (format_sql == .binary or format_sql == .char) {
                if (unpacked.size_data != 0)
                    return raise_args(.TypeError, "Expected size 0 indicating varbinary/varchar(max), got {}", .{unpacked.size_data});
            } else {
                if (unpacked.size_data != @divExact(bit_sizes.bcp, 8))
                    return raise_args(.TypeError, "Unexpected data size: got {}, expected {}", .{ unpacked.size_data, @divExact(bit_sizes.bcp, 8) });
            }
            if (unpacked.size_prefix != @divExact(bit_sizes.prefix, 8))
                return raise_args(.TypeError, "Unexpected prefix size: got {}, expected {}", .{ unpacked.size_prefix, @divExact(bit_sizes.prefix, 8) });

            const schema = try malloc.create(ArrowSchema);
            errdefer malloc.destroy(schema);
            schema.* = .{
                .format = @ptrCast(format_info_sql.format_strings.get(format_sql).ptr),
            };

            state.* = .{
                .parent = container,
                .schema = schema,
                .format = format_sql,
                .read_cell = format_info_sql.readers.get(format_sql),
            };

            print("col {any}\n", .{state.*});

            break :blk try to_capsule(schema);
        };
        errdefer py.Py_DECREF(capsule);
        if (py.PyTuple_SetItem(schema_capsules, @intCast(i_col), capsule) == -1) {
            return Err.PyError;
        }
    }

    const state_capsule = try to_capsule(container);
    defer py.Py_DECREF(state_capsule);
    capsule_has_state_ownership = true;

    return try zig_to_py(.{ schema_capsules, state_capsule });
}

const malloc_error = error{mem};

fn read_batch(py_args: ?*PyObject) !*PyObject {
    const args = try py_to_zig(
        struct { state_capsule: *PyObject, rows_max: u32 },
        py_args orelse return raise(.Exception, "No arguments passed"),
    );
    const rows_max_rounded: u32 = 512 * try std.math.divCeil(u32, args.rows_max + 1, 512);
    defer py.Py_DECREF(args.state_capsule);
    const state: *StateContainer = from_capsule(StateContainer, args.state_capsule).?;
    print("hhfjklad\n{any}\n", .{state});
    print("hhfjklad\n{any}\n", .{state.columns[0]});

    const nr_columns = state.columns.len;

    var arrays = malloc.alloc(*ArrowArray, nr_columns) catch {
        _ = py.PyErr_NoMemory();
        return Err.PyError;
    };
    defer malloc.free(arrays);
    var n_allocated_columns: usize = 0;
    errdefer for (arrays[0..n_allocated_columns]) |array| {
        array.release.?(array);
        malloc.destroy(array);
    };

    for (arrays[0..nr_columns], state.columns) |*arr_ptr, state_col| {
        const has_data_buffer = state_col.has_data_buffer();
        const n_buffers: u7 = if (has_data_buffer) 3 else 2;
        const buffers = try malloc.alloc(*anyopaque, n_buffers);
        errdefer malloc.free(buffers);

        const valid_buffer = try malloc.alloc(u8, @divExact(rows_max_rounded, 8));
        errdefer malloc.free(valid_buffer);
        @memset(valid_buffer, 0xFF);
        buffers[0] = valid_buffer.ptr;

        const value_buffer = try malloc.alloc(u8, format_info_sql.bit_sizes.get(state_col.format).arrow * @divExact(rows_max_rounded, 8));
        errdefer malloc.free(value_buffer);
        buffers[1] = value_buffer.ptr;

        const data_buffer: ?[]u8 = if (has_data_buffer)
            try malloc.alloc(u8, args.rows_max * 42)
        else
            null;
        errdefer if (data_buffer) |buf| malloc.free(buf);
        if (data_buffer) |buf| {
            @memset(value_buffer[0..4], 0);
            buffers[2] = buf.ptr;
        }

        const array = try malloc.create(ArrowArray);
        errdefer malloc.destroy(array);
        array.* = .{
            .buffers = @alignCast(@ptrCast(buffers.ptr)),
            .length = 0,
            .n_buffers = @intCast(buffers.len),
            .null_count = 0,
            .length_data_buffer = if (data_buffer) |buf| buf.len else 0,
        };

        // pass ownership, do not run into errdefer afterwards
        arr_ptr.* = array;
        n_allocated_columns += 1;
        print("col {any}\n", .{arr_ptr.*});
    }

    main_loop: for (0..args.rows_max) |i_row| {
        for (arrays, state.columns, 0..) |arr, *st, i_col| {
            print("i_col {}\n", .{i_col});
            st.read_cell(i_row, st, arr) catch |err| switch (err) {
                ReadError.EOF_expected => if (i_col != 0) return ReadError.EOF_unexpected else break :main_loop,
                else => {
                    print("{any}\n", .{err});
                    unreachable;
                },
            };
        }
    }

    const capsule_tuple = py.PyTuple_New(@intCast(nr_columns)) orelse return Err.PyError;
    errdefer py.Py_DECREF(capsule_tuple);
    for (0..nr_columns) |i_col| {
        const i_col_reverse = nr_columns - 1 - i_col;
        const capsule = try to_capsule(arrays[i_col_reverse]);
        n_allocated_columns -= 1; // transfer ownership
        if (py.PyTuple_SetItem(capsule_tuple, @intCast(i_col_reverse), capsule) == -1) {
            py.Py_DECREF(capsule);
            return Err.PyError;
        }
    }

    return capsule_tuple;
}

const ReadError = error{ DecimalChanged, TimezoneChanged, EOF_unexpected, EOF_expected, file_error, malformed_value, no_memory };

inline fn read_cell(i_row: usize, state: *ReaderState, arr: *ArrowArray, comptime format: formats_sql) !void {
    const types = format_info_sql.types.get(format);
    var prefix: types.prefix = undefined;
    if (!try state.read(&prefix)) {
        return ReadError.EOF_expected;
    }
    print("prefix: {}\n", .{prefix});

    arr.length += 1;
    if (prefix == -1) {
        bit_set(arr.buffers[0], i_row, false);
        arr.null_count += 1;
        return;
    }

    if (comptime format == .binary or format == .char) {
        const data_buffer_ptr: [*]u8 = @alignCast(@ptrCast(arr.buffers[2].?));
        const main_buffer_ptr: [*]u32 = @alignCast(@ptrCast(arr.buffers[1].?));
        const last_index = main_buffer_ptr[i_row];
        const target_index = last_index + (std.math.cast(u32, prefix) orelse return ReadError.malformed_value);
        main_buffer_ptr[i_row + 1] = target_index;
        print("data buffer {} {} {}\n", .{ last_index, target_index, arr.length_data_buffer });
        if (target_index > arr.length_data_buffer) {
            // TODO realloc
            unreachable;
        }
        if (!try state.read(data_buffer_ptr[last_index..target_index])) {
            return ReadError.EOF_unexpected;
        }
        return;
    }

    var bcp_value: types.bcp = undefined;
    if (!try state.read(&bcp_value)) {
        return ReadError.EOF_unexpected;
    }

    if (comptime format == .bit) {
        // TODO maybe sanity check if there are funny values
        if (bcp_value == 0) {
            bit_set(arr.buffers[1].?, i_row, true);
        } else {
            bit_set(arr.buffers[1].?, i_row, false);
        }
        return;
    }

    const arrow_value: types.arrow = switch (format) {
        inline .decimal => blk: {
            const val = switch (bcp_value.sign) {
                1 => @as(i128, 1),
                0 => @as(i128, -1),
                else => return ReadError.malformed_value,
            } * bcp_value.int_data;
            try state.validate_decimal(bcp_value.size, bcp_value.precision);
            break :blk val;
        },
        inline .date => DateTime64.date_bcp_to_arrow(bcp_value),
        inline .datetime2 => bcp_value.to_ns(),
        inline .datetimeoffset => (DateTime64{ .date = bcp_value.date, .time = bcp_value.time }).to_ns(),
        inline else => @as(types.arrow, bcp_value),
    };

    const main_buffer: [*]types.arrow = @alignCast(@ptrCast(arr.buffers[1].?));
    main_buffer[i_row] = arrow_value;
}

fn ext_init_reader(module: ?*PyObject, args: ?*PyObject) callconv(.C) ?*PyObject {
    _ = module;
    return init_reader(args) catch |err| switch (err) {
        Err.PyError => return null,
        else => unreachable,
    };
}

fn ext_read_batch(module: ?*PyObject, args: ?*PyObject) callconv(.C) ?*PyObject {
    _ = module;
    return read_batch(args) catch |err| switch (err) {
        Err.PyError => return null,
        else => unreachable,
    };
}

var ZamlMethods = [_]PyMethodDef{
    PyMethodDef{
        .ml_name = "init_reader",
        .ml_meth = ext_init_reader,
        .ml_flags = py.METH_VARARGS,
        .ml_doc = "Prepare reader.",
    },
    PyMethodDef{
        .ml_name = "read_batch",
        .ml_meth = ext_read_batch,
        .ml_flags = py.METH_VARARGS,
        .ml_doc = "Read from disk to arrow capsules.",
    },
    PyMethodDef{
        .ml_name = "write_arrow",
        .ml_meth = ext_write_arrow,
        .ml_flags = py.METH_VARARGS,
        .ml_doc = "Write arrow capsules to disk.",
    },
    PyMethodDef{
        .ml_name = null,
        .ml_meth = null,
        .ml_flags = 0,
        .ml_doc = null,
    },
};

var zamlmodule = PyModuleDef{
    .m_base = PyModuleDef_Base{
        .ob_base = PyObject{
            // .ob_refcnt = 1,
            .ob_type = null,
        },
        .m_init = null,
        .m_index = 0,
        .m_copy = null,
    },
    // { {  { 1 }, (nullptr) }, nullptr, 0, nullptr, }
    .m_name = "zaml",
    .m_doc = null,
    .m_size = -1,
    .m_methods = &ZamlMethods,
    .m_slots = null,
    .m_traverse = null,
    .m_clear = null,
    .m_free = null,
};

pub export fn PyInit_zaml() ?*PyObject {
    return PyModule_Create(&zamlmodule);
}
