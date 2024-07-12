const std = @import("std");
const testing = std.testing;
const print = std.debug.print;
const py = @cImport({
    @cDefine("Py_LIMITED_API", "3");
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

const ArrowSchema = packed struct {
    // Array type description
    format: [*:0]const u8,
    name: [*:0]const u8,
    metadata: [*]const u8,
    flags: i64,
    n_children: i64,
    children: [*][*]ArrowSchema,
    dictionary: [*]ArrowSchema,

    // Release callback
    release: ?*fn (*ArrowSchema) void,
    // Opaque producer-specific data
    private_data: ?*anyopaque,
};

const ArrowArray = packed struct {
    // Array data description
    length: i64,
    null_count: i64,
    offset: i64,
    n_buffers: i64,
    n_children: i64,
    buffers: [*]?*anyopaque,
    children: [*][*]ArrowArray,
    dictionary: [*]ArrowArray,

    // Release callback
    release: ?*fn (*ArrowArray) void,
    // Opaque producer-specific data
    private_data: ?*anyopaque,
};

const ArrowError = error{MissingBuffer};
const Err = error{PyError};
const Exceptions = enum { Exception, NotImplemented, TypeError };

fn raise_args(exc: Exceptions, comptime msg: []const u8, args: anytype) Err {
    @setCold(true);
    const pyexc = switch (exc) {
        .Exception => py.PyExc_Exception,
        .NotImplemented => py.PyExc_NotImplementedError,
        .TypeError => py.PyExc_TypeError,
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
    bytes_prefix: u16,
    bytes_data: u16,
    dtype_name: []u8,
    decimal_size: u8 = 0,
    decimal_precision: u8 = 0,
    timestamp_timezone_offset: i16 = 0,
    timestamp_factor_ns: i64 = 0,

    fn init(
        format: formats,
        bytes_prefix: anytype,
        bytes_data: u16,
        comptime dtype_name: []const u8,
    ) !BcpInfo {
        return BcpInfo{
            .writer = @constCast(get_writer(format)),
            // .bytes_prefix = bytes_prefix,
            .bytes_prefix = if (@TypeOf(bytes_prefix) == bool) @intFromBool(bytes_prefix) else bytes_prefix,
            .bytes_data = bytes_data,
            .dtype_name = try std.fmt.allocPrint(allocator, dtype_name, .{}),
        };
    }

    fn deinit(self: BcpInfo) void {
        allocator.free(self.dtype_name);
    }

    fn from_format(fmt: []const u8, nullable: bool) !BcpInfo {
        if (fmt.len == 1) {
            return switch (fmt[0]) {
                'l' => try BcpInfo.init(.l, nullable, 64, "SQLBIGINT"),
                'z' => try BcpInfo.init(.bytes, 8, 8, "SQLBINARY"),
                'u' => try BcpInfo.init(.bytes, 8, 8, "SQLCHAR"),
                else => raise_args(.NotImplemented, "Format '{s}' not implemented", .{fmt}),
            };
        } else {
            if (fmt[0] == 'd') {
                // Decimal seems to always have the indicator byte
                var bcp_info = try BcpInfo.init(.decimal, 1, 19, "SQLDECIMAL");
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
                return try BcpInfo.init(.date, nullable, 3, "SQLDATE");
            }
            if (std.mem.eql(u8, fmt, "tdm")) {
                return try BcpInfo.init(.datetime, nullable, 8, "SQLDATETIME2");
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
                    var bcp_info = try BcpInfo.init(.timestamp, nullable, 8, "SQLDATETIME2");
                    bcp_info.timestamp_factor_ns = factor_ns;
                    return bcp_info;
                } else {
                    var bcp_info = try BcpInfo.init(.timestamp_timezone, nullable, 10, "SQLDATETIMEOFFSET");
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

    inline fn nullable(self: *Column) bool {
        // no null buffer or null_count = 0 is likely not enough
        // would need to be the same for every ArrowArray chunk
        _ = self;
        return true;
        // return self.current_array.buffers[0] != null;
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

const formats = enum(i64) { l, bytes, decimal, date, datetime, timestamp, timestamp_timezone };
const WriteError = error{ write_error, missing_buffer };

inline fn write(self: *Column, file: *std.fs.File, comptime format: formats) WriteError!void {
    const types = switch (format) {
        inline formats.l => .{ i8, i64, i64 },
        inline formats.bytes => .{ i64, u32, u32 },
        inline formats.decimal => .{ i8, i128, Decimal },
        inline formats.date => .{ i8, i32, u24 },
        inline formats.datetime => .{ i8, i64, DateTime64 },
        inline formats.timestamp => .{ i8, i64, DateTime64 },
        inline formats.timestamp_timezone => .{ i8, i64, DateTimeOffset },
    };
    const type_prefix = types[0];
    const type_arrow = types[1];
    const type_bcp = types[2];
    var is_null: bool = false;
    const main_buffer = try self.main_buffer(type_arrow);
    const bytes_bcp: usize = switch (format) {
        inline .bytes => main_buffer[self.next_index + 1] - main_buffer[self.next_index],
        inline else => @bitSizeOf(type_bcp) / 8,
    };

    if (self.nullable() or format == .bytes or format == .decimal) {
        if (self.valid_buffer()) |valid_buffer| {
            is_null = !valid_buffer[self.next_index];
        }
        const val_null: type_prefix = if (is_null) -1 else @intCast(bytes_bcp);
        const asbytes: [*]u8 = @constCast(@ptrCast(&val_null));
        print("writing null\n", .{});
        _ = file.write(asbytes[0..@sizeOf(type_prefix)]) catch return WriteError.write_error;
    }

    if (is_null) {
        return;
    }

    if (format == .bytes) {
        const data_buffer = try self.data_buffer();
        print("writing string >{s}<\n", .{data_buffer[main_buffer[self.next_index]..main_buffer[self.next_index + 1]]});
        _ = file.write(data_buffer[main_buffer[self.next_index]..main_buffer[self.next_index + 1]]) catch return WriteError.write_error;
    } else {
        const val_arrow = main_buffer[self.next_index];
        const val_bcp = switch (format) {
            .decimal => Decimal{
                .size = self.bcp_info.decimal_size,
                .precision = self.bcp_info.decimal_precision,
                .sign = if (val_arrow >= 0) 1 else 0,
                .int_data = if (val_arrow >= 0) val_arrow else -val_arrow,
            },
            // TODO raise PyError when it fails
            .date => br: {
                const x: type_bcp = @intCast(val_arrow + 719162);
                break :br x;
            },
            .datetime => DateTime64.from_ns_factor(val_arrow, 1000 * 1000),
            .timestamp => DateTime64.from_ns_factor(val_arrow, self.bcp_info.timestamp_factor_ns),
            .timestamp_timezone => DateTimeOffset.from_ns_factor(val_arrow, self.bcp_info.timestamp_factor_ns, self.bcp_info.timestamp_timezone_offset),
            else => val_arrow,
        };
        print("writing value >{}< at index {} with {} bytes\n", .{ val_bcp, self.next_index, bytes_bcp });
        const asbytes: [*]u8 = @constCast(@ptrCast(&val_bcp));
        _ = file.write(asbytes[0..bytes_bcp]) catch return WriteError.write_error;
    }
}

const writer_type = *fn (*Column, *std.fs.File) @typeInfo(@TypeOf(write)).Fn.return_type.?;

var writers = blk: {
    const fields = @typeInfo(formats).Enum.fields;
    var arr: [fields.len]writer_struct = .{undefined} ** fields.len;
    for (fields, 0..) |fmt_name, i_field| {
        const fmt: formats = @enumFromInt(fmt_name.value);
        const dummy = struct {
            fn write_fmt(self: *Column, file: *std.fs.File) !void {
                try write(self, file, fmt);
            }
        };
        arr[i_field] = writer_struct{ .format = fmt, .writer = @constCast(&dummy.write_fmt) };
    }
    break :blk arr;
};

fn get_writer(fmt: formats) writer_type {
    for (writers) |w| {
        if (w.format == fmt) {
            return w.writer;
        }
    }
    unreachable;
}

const writer_struct = struct {
    format: formats,
    writer: writer_type,
};

fn write_arrow(module: ?*PyObject, args: ?*PyObject) callconv(.C) ?*PyObject {
    _ = module;
    return _write_arrow(args) catch |err| switch (err) {
        Err.PyError => return null,
        else => unreachable,
    };
}

fn _write_arrow(args: ?*PyObject) !?*PyObject {
    const list_schema_capsules = py.PySequence_GetItem(args, 0) orelse return Err.PyError;
    defer py.Py_DECREF(list_schema_capsules);
    const list_array_capsule_generators = py.PySequence_GetItem(args, 1) orelse return Err.PyError;
    defer py.Py_DECREF(list_array_capsule_generators);
    const nr_columns = py.PyObject_Length(list_schema_capsules);
    if (nr_columns == -1) {
        return null;
    }
    var columns = allocator.alloc(Column, @intCast(nr_columns)) catch {
        _ = py.PyErr_NoMemory();
        return Err.PyError;
    };
    defer allocator.free(columns);
    var n_allocated_columns: usize = 0;
    defer for (columns[0..n_allocated_columns]) |col| {
        col.deinit();
    };
    const columns_slice = columns[0..@intCast(nr_columns)];
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
        col.bcp_info = try BcpInfo.from_format(fmt, col.nullable());
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
    // _ = file.write("hello");

    // return py.PyLong_FromSize_t(columns_slice.len);
    return py.PyLong_FromSize_t(columns.len);
    // return py.Py_NewRef(py.Py_None());
}

// fn zaml_load(self: [*c]PyObject, args: [*c]PyObject) callconv(.C) [*c]PyObject {
fn zaml_load(self: ?*PyObject, args: ?*PyObject) callconv(.C) ?*PyObject {
    _ = self;
    // _ = args;
    // const capsule_schema: *PyObject = undefined;
    // py.PyArg_ParseTuple(args, "O", &capsule_schema);
    const capsule_schema = py.PyTuple_GetItem(args, 0) orelse return null;
    const schema_ptr = py.PyCapsule_GetPointer(capsule_schema, "arrow_schema") orelse return null;
    const schema: *ArrowSchema = @alignCast(@ptrCast(schema_ptr));
    print("format {s}\n", .{schema.format});
    return py.Py_NewRef(capsule_schema);
    // return Py_BuildValue("i", @as(c_int, 1));
}

var ZamlMethods = [_]PyMethodDef{
    PyMethodDef{
        .ml_name = "load",
        .ml_meth = zaml_load,
        .ml_flags = py.METH_VARARGS,
        .ml_doc = "Load some tasty YAML.",
    },
    PyMethodDef{
        .ml_name = "write_arrow",
        .ml_meth = write_arrow,
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

pub export fn PyInit_zaml() [*]PyObject {
    return PyModule_Create(&zamlmodule);
}
