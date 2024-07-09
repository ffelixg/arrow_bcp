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
// const Err = error{ PyError, StopIteration };

var gpa = std.heap.GeneralPurposeAllocator(.{
    .safety = true,
    // .never_unmap = true,
    // .retain_metadata = true,
}){};
const allocator = gpa.allocator();

const BcpInfo = struct {
    writer: @TypeOf(&write_l),
    bytes_prefix: u16,
    bytes_data: u16,
    dtype_name: [*:0]u8,
    decimal_size: u8 = 0,
    decimal_precision: u8 = 0,

    fn init(
        writer: @TypeOf(write_l),
        bytes_prefix: anytype,
        bytes_data: u16,
        comptime dtype_name: []const u8,
    ) !BcpInfo {
        return BcpInfo{
            .writer = @constCast(&writer),
            // .bytes_prefix = bytes_prefix,
            .bytes_prefix = if (@TypeOf(bytes_prefix) == bool) @intFromBool(bytes_prefix) else bytes_prefix,
            .bytes_data = bytes_data,
            .dtype_name = try std.fmt.allocPrintZ(allocator, dtype_name, .{}),
        };
    }

    fn deinit(self: BcpInfo) void {
        allocator.free(self.dtype_name);
    }

    fn from_format(fmt: []const u8, nullable: bool) !BcpInfo {
        if (fmt.len == 1) {
            return switch (fmt[0]) {
                'l' => try BcpInfo.init(write_l, nullable, 64, "SQLBIGINT"),
                'z' => try BcpInfo.init(write_bytes, 8, 8, "SQLBINARY"),
                'u' => try BcpInfo.init(write_bytes, 8, 8, "SQLCHAR"),
                else => unreachable,
            };
        } else {
            if (fmt[0] == 'd') {
                // Decimal seems to always have the indicator byte
                var bcp_col = try BcpInfo.init(write_decimal, 1, 19, "SQLDECIMAL");
                if (fmt[1] != ':') {
                    py.PyErr_SetString(py.PyExc_Exception, "Expecting ':' as second character of format string whens starting with 'd'");
                    return Err.PyError;
                }
                var iter = std.mem.tokenizeScalar(u8, fmt[2..], ',');
                bcp_col.decimal_size = try std.fmt.parseInt(u8, iter.next() orelse {
                    py.PyErr_SetString(py.PyExc_Exception, "Incomplete decimal formatting string");
                    return Err.PyError;
                }, 10);
                bcp_col.decimal_precision = try std.fmt.parseInt(u8, iter.next() orelse {
                    py.PyErr_SetString(py.PyExc_Exception, "Incomplete decimal formatting string");
                    return Err.PyError;
                }, 10);
                if (iter.next() != null) {
                    py.PyErr_SetString(py.PyExc_Exception, "Custom bitwidth decimals are not supported.");
                    return Err.PyError;
                }
                print("size {} precision {}\n", .{ bcp_col.decimal_size, bcp_col.decimal_precision });
                return bcp_col;
            }
            if (std.mem.eql(u8, fmt, "tdD")) {
                return try BcpInfo.init(write_date, nullable, 3, "SQLDATE");
            }
            print("unreachable format {s}\n", .{fmt});
            // 'u' => try BcpInfo.init(write_bytes, 8, 8, "SQLCHAR"),
            unreachable;
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
        // self.bcp_info.deinit(); // TODO ??
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
            py.PyErr_SetString(py.PyExc_Exception, "Offset field is not supported");
            return Err.PyError;
        }
        if (current_array_ptr.n_buffers < 2) {
            // TODO add check for data buffer when needed
            py.PyErr_SetString(py.PyExc_Exception, "Too few buffers");
            return Err.PyError;
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
        return @alignCast(@ptrCast(self.current_array.buffers[1] orelse return ArrowError.MissingBuffer));
    }

    inline fn data_buffer(self: *Column) ![*]u8 {
        return @alignCast(@ptrCast(self.current_array.buffers[2] orelse return ArrowError.MissingBuffer));
    }
};

const formats = enum { l, d, bytes, decimal, date };

inline fn write(self: *Column, file: *std.fs.File, comptime format: formats) !void {
    const types = switch (format) {
        inline formats.l => .{ i8, i64, i64 },
        inline formats.bytes => .{ i64, u32, u32 },
        inline formats.decimal => .{ i8, i128, Decimal },
        inline formats.date => .{ i8, i32, i24 },
        else => comptime unreachable,
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
        _ = try file.write(asbytes[0..@sizeOf(type_prefix)]);
    }

    if (is_null) {
        return;
    }

    if (format == .bytes) {
        const data_buffer = try self.data_buffer();
        print("writing string >{s}<\n", .{data_buffer[main_buffer[self.next_index]..main_buffer[self.next_index + 1]]});
        _ = try file.write(data_buffer[main_buffer[self.next_index]..main_buffer[self.next_index + 1]]);
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
                const x: type_bcp = @intCast(val_arrow + 719163 - 1);
                // @as(type_bcp, val_arrow + 719163 - 1),
                break :br x;
            },
            else => val_arrow,
        };
        print("writing value >{}< at index {} with {} bytes\n", .{ val_bcp, self.next_index, bytes_bcp });
        const asbytes: [*]u8 = @constCast(@ptrCast(&val_bcp));
        _ = try file.write(asbytes[0..bytes_bcp]);
    }
}

fn write_l(self: *Column, file: *std.fs.File) !void {
    try write(self, file, formats.l);
}
fn write_d(self: *Column, file: *std.fs.File) !void {
    try write(self, file, formats.d);
}
fn write_bytes(self: *Column, file: *std.fs.File) !void {
    try write(self, file, formats.bytes);
}
fn write_decimal(self: *Column, file: *std.fs.File) !void {
    try write(self, file, formats.decimal);
}
fn write_date(self: *Column, file: *std.fs.File) !void {
    try write(self, file, formats.date);
}

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
            py.PyErr_SetString(py.PyExc_Exception, "Expecting at least one array chunk");
            return Err.PyError;
        }

        const fmt = col.schema.format[0..std.mem.len(col.schema.format)];
        col.bcp_info = try BcpInfo.from_format(fmt, col.nullable());
    }
    var file = std.fs.createFileAbsoluteZ("/tmp/arrowwrite.dat", .{}) catch {
        py.PyErr_SetString(py.PyExc_Exception, "Error opening file");
        return Err.PyError;
    };
    defer file.close();
    main_loop: while (true) {
        for (columns_slice, 0..) |*col, i_col| {
            if (col.next_index >= col.current_array.length and !try col.get_next_array()) {
                for (columns_slice[i_col + 1 .. columns_slice.len]) |*col_| {
                    if (i_col != 0 or try col_.get_next_array()) {
                        py.PyErr_SetString(py.PyExc_Exception, "Arrays don't have equal length");
                        return Err.PyError;
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
