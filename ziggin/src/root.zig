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

// const ArrowBuffers = packed struct {
//     null_buffer: ?[*]bool,
//     main_buffer: ?[*]anyopaque,

// }

const ArrowArray = packed struct {
    // Array data description
    length: i64,
    null_count: i64,
    offset: i64,
    n_buffers: i64,
    n_children: i64,
    buffers: [*]?[*]u8,
    children: [*][*]ArrowArray,
    dictionary: [*]ArrowArray,

    // Release callback
    release: ?*fn (*ArrowArray) void,
    // Opaque producer-specific data
    private_data: ?*anyopaque,
};

const Err = error{PyError};
// const Err = error{ PyError, StopIteration };

var gpa = std.heap.GeneralPurposeAllocator(.{
    .safety = true,
    // .never_unmap = true,
    // .retain_metadata = true,
}){};
const allocator = gpa.allocator();

const BcpInfo = struct {
    writer: *fn (self: *Column, file: *std.fs.File) void,
    bytes_prefix: u16,
    bytes_data: u16,
    dtype_name: [*:0]u8,

    fn init(
        // self: *BcpInfo,
        writer: fn (self: *Column, file: *std.fs.File) void,
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
            switch (fmt[0]) {
                'l' => {
                    return try BcpInfo.init(write_l, nullable, 64, "SQLBIGINT");
                },
                else => unreachable,
            }
        } else {
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
        // print("so clean", .{});
        py.Py_DecRef(self._schema_capsule);
        py.Py_DecRef(self._chunk_generator);
        py.Py_XDECREF(self._current_array_capsule);

        // _ = self;
        // comptime std.debug.panic("fix");

        // handled by capsule garbage collection
        // if (self.schema.release) |release| {
        //     release(@constCast(&self.schema));
        // }
        // if (self.current_array.release) |release| {
        //     release(@constCast(&self.current_array));
        // }
        // self.bcp_info.deinit();
    }

    fn get_next_array(self: *Column) !bool {
        // return false if no more data
        // py.Py_XDECREF(self._current_array_capsule)
        if (self._current_array_capsule) |capsule| {
            defer py.Py_DecRef(capsule);
            self._current_array_capsule = null;
        }
        const array_capsule = py.PyIter_Next(self._chunk_generator) orelse {
            if (py.PyErr_Occurred() != null) {
                return Err.PyError;
            }
            return false;
        };
        defer py.Py_DecRef(array_capsule);
        const array_ptr = py.PyCapsule_GetPointer(array_capsule, "arrow_array") orelse return Err.PyError;
        const current_array_ptr: *ArrowArray = @alignCast(@ptrCast(array_ptr));
        self.next_index = 0;
        self.current_array = current_array_ptr.*;
        self._current_array_capsule = py.Py_NewRef(array_capsule);
        return true;
    }

    fn nullable(self: *Column) bool {
        return self.current_array.buffers[0] != null;
    }
};

const formats = enum { l, d };

inline fn write(self: *Column, file: *std.fs.File, format: formats) void {
    _ = self;
    // _ = file;
    if (format == .d) {
        print("case1\n", .{});
    } else {
        print("case2\n", .{});
    }
    const tp = switch (format) {
        inline formats.l => i64,
        else => comptime unreachable,
    };
    const val: tp = 5;
    // _ = val;
    // file.write(@as([@sizeOf(tp)]u8, val));
    const asbytes: [*]u8 = @constCast(@ptrCast(&val));
    _ = file.write(asbytes[0..@sizeOf(tp)]) catch unreachable;
}

fn write_l(self: *Column, file: *std.fs.File) void {
    write(self, file, formats.l);
}
fn write_d(self: *Column, file: *std.fs.File) void {
    write(self, file, formats.d);
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
    defer py.Py_DecRef(list_schema_capsules);
    const list_array_capsule_generators = py.PySequence_GetItem(args, 1) orelse return Err.PyError;
    defer py.Py_DecRef(list_array_capsule_generators);
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
        print("i_col {}\n", .{i_col});

        var chunk_generator: *PyObject = undefined;
        var schema: *ArrowSchema = undefined;
        var capsule_schema: *PyObject = undefined;
        {
            capsule_schema = py.PySequence_GetItem(list_schema_capsules, @intCast(i_col)) orelse return Err.PyError;
            errdefer py.Py_DecRef(capsule_schema);
            chunk_generator = py.PySequence_GetItem(list_array_capsule_generators, @intCast(i_col)) orelse return Err.PyError;
            errdefer py.Py_DecRef(chunk_generator);
            const schema_ptr = py.PyCapsule_GetPointer(capsule_schema, "arrow_schema") orelse return Err.PyError;
            schema = @alignCast(@ptrCast(schema_ptr));
        }

        // const x: comptime_int = 5;

        // const dumdum = switch (i_col) {
        //     0 => struct {
        //         fn writer(self_inner: Column, file: std.fs.File) void {
        //             print("111in write: col {}\n", .{x});
        //             print("111return from write {}\n", .{file.write(self_inner.schema.format[0..2]) catch unreachable});
        //         }
        //     },
        //     1 => struct {
        //         fn writer(self_inner: Column, file: std.fs.File) void {
        //             print("222in write: col {}\n", .{x});
        //             print("222return from write {}\n", .{file.write(self_inner.schema.format[0..2]) catch unreachable});
        //         }
        //     },
        //     else => unreachable,
        // };
        // const dummy = struct {
        //     fn writer(self_inner: Column, file: std.fs.File) void {
        //         print("in write: col {}\n", .{x});
        //         print("return from write {}\n", .{file.write(self_inner.schema.format[0..2]) catch unreachable});
        //     }
        // };

        col.* = Column{
            ._chunk_generator = chunk_generator,
            .current_array = undefined,
            .schema = schema.*,
            ._schema_capsule = capsule_schema,
            ._current_array_capsule = null,
            .next_index = 0,
            // .writer = @constCast(&dumdum.writer),
            // .writer = @constCast(switch (i_col) {
            //     0 => &write1,
            //     1 => &write2,
            //     else => unreachable,
            // }),
            .bcp_info = undefined,
        };
        n_allocated_columns += 1;

        if (!try col.get_next_array()) {
            py.PyErr_SetString(py.PyExc_Exception, "Expecting at least one array chunk");
            return Err.PyError;
        }

        // const len = std.mem.len(col.schema.format);
        // var bcp_info: BcpInfo = undefined;
        const fmt = col.schema.format[0..std.mem.len(col.schema.format)];
        col.bcp_info = try BcpInfo.from_format(fmt, col.nullable());

        print("i_col {s} {}\n", .{ col.schema.format, col.current_array.length });
    }
    var file = std.fs.createFileAbsoluteZ("/tmp/arrowwrite.dat", .{}) catch {
        py.PyErr_SetString(py.PyExc_Exception, "Error opening file");
        return Err.PyError;
    };
    defer file.close();
    for (columns_slice, 0..) |col, i_col| {
        print("i_col({}) {s} {}\n", .{ i_col, col.schema.format, col.current_array.length });
        // col.bcp_writer(@constCast(&col), &file);
        col.bcp_info.writer(@constCast(&col), &file);
        // col.deinit();
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
