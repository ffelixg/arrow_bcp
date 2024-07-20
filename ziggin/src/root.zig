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
    time: u40,
    date: u24,

    inline fn from_ns_factor(val: i64, ns_factor: i64) DateTime64 {
        const as_ns = val * ns_factor;
        const ns_in_day = 1000 * 1000 * 1000 * 60 * 60 * 24;
        return DateTime64{
            .date = @intCast(@divFloor(as_ns, ns_in_day) + 719162),
            .time = @intCast(@divFloor(@mod(as_ns, ns_in_day), 100)),
        };
    }
};

const DateTimeOffset = packed struct {
    time: u40,
    date: u24,
    offset: i16,

    inline fn from_ns_factor(val: i64, ns_factor: i64, offset: i16) DateTimeOffset {
        const dt64 = DateTime64.from_ns_factor(val, ns_factor);
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
    private_data: *SchemaProducer,
};

const SchemaProducer = struct {
    schema: *ArrowSchema,
    decimal: ?struct { size: u8, precision: u8 } = null,
    offset: ?i16 = null,
    arena: std.heap.ArenaAllocator,
    sql: struct {
        format: formats_sql,
        size_prefix: u32,
        size_data: u32,
    },

    fn deinit(self: SchemaProducer) void {
        self.arena.deinit();
    }

    fn validate_decimal(self: *SchemaProducer, size: u8, precision: u8) !void {
        if (self.decimal) |dec| {
            if (size != dec.size or precision != dec.precision) {
                return ReadError.DecimalChanged;
            }
        } else {
            self.decimal = .{ .size = size, .precision = precision };
            self.schema.format = try std.fmt.allocPrintZ(
                self.arena.allocator(),
                "d:{}:{}",
                .{ precision, size },
            );
        }
    }

    fn validate_timezone(self: *SchemaProducer, offset: i16) !void {
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
            self.schema.format = try std.fmt.allocPrintZ(
                self.arena.allocator(),
                "tsn:{c}{}{}",
                .{ sign, hours, minutes },
            );
        }
    }

    fn from_capsule(capsule: *PyObject) ?*SchemaProducer {
        const ptr = py.PyCapsule_GetPointer(capsule, "arrow_schema") orelse return null;
        const schema: *ArrowSchema = @alignCast(@ptrCast(ptr));
        return schema.private_data;
    }

    fn release_capsule(capsule: ?*PyObject) callconv(.C) void {
        if (capsule) |c| {
            if (from_capsule(c)) |schema| {
                schema.deinit();
            }
            unreachable;
        }
        unreachable;
    }

    fn to_capsule(self: *SchemaProducer) !*PyObject {
        return py.PyCapsule_New(
            @ptrCast(self.schema),
            "arrow_schema",
            @constCast(&SchemaProducer.release_capsule),
        ) orelse return Err.PyError;
    }
};

fn dummy_release_array(self: *ArrowArray) void {
    _ = self;
    unreachable; // handled by capsule
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
    release: ?*fn (*ArrowArray) void = @constCast(&dummy_release_array),
    // Opaque producer-specific data
    producer: *ArrayProducer,
};

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
            // TODO raise PyError when it fails
            inline .date => br: {
                const x = std.math.cast(types.bcp, val_arrow + 719162) orelse return WriteError.int_cast;
                break :br x;
            },
            inline .datetime => DateTime64.from_ns_factor(val_arrow, 1000 * 1000),
            inline .timestamp => DateTime64.from_ns_factor(val_arrow, self.bcp_info.timestamp_factor_ns),
            inline .timestamp_timezone => DateTimeOffset.from_ns_factor(val_arrow, self.bcp_info.timestamp_factor_ns, self.bcp_info.timestamp_timezone_offset),
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
        .Pointer => py.PyUnicode_FromStringAndSize(value.ptr, @intCast(value.len)),
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

const formatinfo_sql = blk: {
    var format_strings = std.EnumArray(formats_sql, []const u8).initUndefined();
    for (std.enums.values(formats_sql)) |fmt| {
        const info = switch (fmt) {
            formats_sql.bit => .{ u8, u1, "b" },
            formats_sql.tiny => .{ u8, u8, "C" },
            formats_sql.smallint => .{ i16, i16, "s" },
            formats_sql.int => .{ i32, i32, "i" },
            formats_sql.bigint => .{ i64, i64, "l" },
            formats_sql.float => .{ f32, f32, "f" },
            formats_sql.real => .{ f64, f64, "g" },
            formats_sql.decimal => .{ Decimal, i128, "n" }, // scale/precision unknown until first row is read
            formats_sql.date => .{ u24, i32, "tdD" },
            formats_sql.datetime2 => .{ DateTime64, i64, "tsn:" },
            formats_sql.datetimeoffset => .{ DateTimeOffset, i64, "n" }, // timezone unknown until first row is read
            formats_sql.uniqueidentifier => .{ [16]u8, [16]u8, "w:16" },
            formats_sql.char => .{ noreturn, u32, "u" },
            formats_sql.binary => .{ noreturn, u32, "z" },
        };
        format_strings.set(fmt, info[2] ++ "\x00");
    }
    const T = struct { format_strings: @TypeOf(format_strings) };
    break :blk T{ .format_strings = format_strings };
};

const ArrayProducer = struct {
    array: *ArrowArray,
    buffer_prefix: []u8,
    buffer_data: []u8,
    arena: std.heap.ArenaAllocator,
    has_data_buffer: bool,
    fn deinit(self: ArrayProducer) void {
        _ = self;
    }
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

    const ret = py.PyTuple_New(@intCast(nr_columns)) orelse return Err.PyError;
    errdefer py.Py_DECREF(ret);

    for (0..nr_columns) |i_col| {
        const py_bcp_column = py.PySequence_GetItem(args.bcp_columns, @intCast(i_col)) orelse return Err.PyError;
        defer py.Py_DECREF(py_bcp_column);

        const unpacked = try py_to_zig(
            struct { sql_type: *py.PyObject, size_prefix: u32, size_data: u32 },
            py_bcp_column,
        );
        defer py.Py_DECREF(unpacked.sql_type);

        const py_sql_type_int = py.PyDict_GetItem(sql_type_mapping, unpacked.sql_type) orelse return Err.PyError;
        defer py.Py_DECREF(py_sql_type_int);
        const format_sql: formats_sql = @enumFromInt(try py_to_zig(c_ulonglong, py_sql_type_int));

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        var arena_alloc = arena.allocator();

        const schema = try arena_alloc.create(ArrowSchema);
        schema.* = .{
            .format = @ptrCast(formatinfo_sql.format_strings.get(format_sql).ptr),
            .private_data = undefined,
        };

        const producer_data = try arena_alloc.create(SchemaProducer);
        producer_data.* = .{
            .schema = schema,
            .sql = .{
                .format = format_sql,
                .size_data = unpacked.size_data,
                .size_prefix = unpacked.size_prefix,
            },
            .arena = arena,
        };

        schema.private_data = producer_data;

        print("col {any}\n", .{producer_data.*});

        const capsule = try producer_data.to_capsule();
        errdefer py.Py_DECREF(capsule);
        if (py.PyTuple_SetItem(ret, @intCast(i_col), capsule) == -1) {
            return Err.PyError;
        }
    }

    return ret;
}

fn read_batch(py_args: ?*PyObject) !*PyObject {
    const args = try py_to_zig(
        struct { schema_capsules: *PyObject, rows_max: u32 },
        py_args orelse return raise(.Exception, "No arguments passed"),
    );
    defer py.Py_DECREF(args.schema_capsules);

    const nr_columns: usize = blk: {
        const len = py.PyObject_Length(args.schema_capsules);
        break :blk if (len == -1) return Err.PyError else @intCast(len);
    };

    const schemas = allocator.alloc(*SchemaProducer, nr_columns) catch {
        _ = py.PyErr_NoMemory();
        return Err.PyError;
    };
    defer allocator.free(schemas);

    for (schemas, 0..) |*schema, i_schema| {
        const capsule = py.PySequence_GetItem(args.schema_capsules, @intCast(i_schema)) orelse return Err.PyError;
        defer py.Py_DECREF(capsule);
        schema.* = SchemaProducer.from_capsule(capsule) orelse return raise(.Exception, "Could not read schema capsule");
    }

    var arrays = allocator.alloc(*ArrayProducer, nr_columns) catch {
        _ = py.PyErr_NoMemory();
        return Err.PyError;
    };
    defer allocator.free(arrays);
    var n_allocated_columns: usize = 0;
    errdefer for (arrays[0..n_allocated_columns]) |array| {
        array.deinit();
    };

    var sql_read_buffer: [19]u8 = undefined;

    for (arrays[0..nr_columns], schemas) |*col, schema| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        var arena_alloc = arena.allocator();

        const producer_data = try arena_alloc.create(ArrayProducer);
        producer_data.* = .{
            .array = undefined,
            .buffer_prefix = sql_read_buffer[0..schema.sql.size_prefix],
            .buffer_data = sql_read_buffer[0..schema.sql.size_data],
            .arena = arena,
            .has_data_buffer = switch (schema.sql.format) {
                formats_sql.binary, formats_sql.char => true,
                else => false,
            },
        };

        const buffers = try arena_alloc.alloc(*anyopaque, if (producer_data.has_data_buffer) 3 else 2);

        const array = try arena_alloc.create(ArrowArray);
        array.* = .{
            .buffers = @alignCast(@ptrCast(buffers.ptr)),
            .length = args.rows_max,
            .n_buffers = @intCast(buffers.len),
            .null_count = 0,
            .producer = producer_data,
        };
        producer_data.array = array;

        // pass ownership, do not run into errdefer afterwards
        col.* = producer_data;
        n_allocated_columns += 1;
        print("col {any}\n", .{col.*});
    }
    var file = std.fs.openFileAbsoluteZ("/tmp/arrowwrite.dat", .{}) catch {
        return raise(.Exception, "Error opening file");
    };
    defer file.close();

    // main_loop: while (true) {
    for (arrays, 0..) |col, i_col| {
        _ = i_col;
        try read_cell(col, file);
    }
    // }

    return py.Py_NewRef(py.Py_None());
}

const ReadError = error{ DecimalChanged, TimezoneChanged };

// fn read_cell(arr: *ArrowArray, file: std.fs.File) !void {
fn read_cell(col: *ArrayProducer, file: std.fs.File) !void {
    // const col: *ReaderColumn = @alignCast(@ptrCast(arr.producer));
    const prefix_read = try file.read(col.buffer_prefix);
    print("col.buffer_prefix: {}, bytes: {any}\n", .{ prefix_read, col.buffer_prefix });
    const data_read = try file.read(col.buffer_data);
    print("col.buffer_data: {}, bytes: {any}\n", .{ data_read, col.buffer_data });
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
        .ml_name = "read_arrow",
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

var sql_type_mapping: *py.PyObject = undefined;

fn sql_type_mapping_set_val(key: anytype, val: formats_sql) bool {
    const py_val = py.PyLong_FromLongLong(@intCast(@intFromEnum(val))) orelse return true;
    if (py.PyDict_SetItemString(sql_type_mapping, key, py_val) == -1) return true;
    return false;
}

pub export fn PyInit_zaml() ?*PyObject {
    sql_type_mapping = py.PyDict_New() orelse return null;
    if (sql_type_mapping_set_val("SQLBIT", .bit)) return null;
    if (sql_type_mapping_set_val("SQLTINYINT", .tiny)) return null;
    if (sql_type_mapping_set_val("SQLSMALLINT", .smallint)) return null;
    if (sql_type_mapping_set_val("SQLINT", .int)) return null;
    if (sql_type_mapping_set_val("SQLBIGINT", .bigint)) return null;
    if (sql_type_mapping_set_val("SQLFLT4", .float)) return null;
    if (sql_type_mapping_set_val("SQLFLT8", .real)) return null;
    if (sql_type_mapping_set_val("SQLDECIMAL", .decimal)) return null;
    if (sql_type_mapping_set_val("SQLDATE", .date)) return null;
    if (sql_type_mapping_set_val("SQLDATETIME2", .datetime2)) return null;
    if (sql_type_mapping_set_val("SQLDATETIMEOFFSET", .datetimeoffset)) return null;
    if (sql_type_mapping_set_val("SQLUNIQUEID", .uniqueidentifier)) return null;
    if (sql_type_mapping_set_val("SQLCHAR", .char)) return null;
    if (sql_type_mapping_set_val("SQLBINARY", .binary)) return null;
    return PyModule_Create(&zamlmodule);
}
