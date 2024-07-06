import collections
import datetime
from decimal import Decimal
from uuid import UUID
from struct import pack
import math
import itertools
import typing


space = int.from_bytes(b' ')
offsets = (8, 28, 36, 44, 49, 55)
bcpColumn = collections.namedtuple("bcpColumn", ["type", "bytes_indicator", "bytes_data", "column_name", "collation"])
bcpVersion = b'14.0'


def format_load(format_bytes: bytes) -> list[bcpColumn]:
    version, nr_lines, *lines = format_bytes.splitlines()
    assert version == bcpVersion
    assert len(lines) == int(nr_lines.decode())
    spacers = []
    for i_line, line in enumerate(lines):
        spacers.append(set(
            i
            for i in range(len(line))
            if line[i] != space and line[i-1] == space
        ))
    spacers = set.intersection(*spacers)
    assert len(spacers) == 7
    assert line[0] != space
    assert line[-1] != space
    assert spacers - {max(spacers)} == set(offsets)
    spacers = sorted(spacers)
    columns = []
    for i_line, line in enumerate(lines):
        parts = [
            line[start:end]
            for start, end in zip([0] + spacers, spacers + [None])
        ]
        assert int(parts[0].decode().strip()) == i_line + 1
        assert int(parts[5].decode().strip()) == i_line + 1
        col_args = [i.strip().decode() for i in [parts[1], parts[2], parts[3], parts[6], parts[7]]]
        col_args[1] = int(col_args[1])
        col_args[2] = int(col_args[2])
        columns.append(bcpColumn(*col_args))
    return columns


def format_dump(bcp_columns: list[bcpColumn]) -> bytes:
    name_padding = max(len(i.column_name) for i in bcp_columns) + 16
    name_padding = int(name_padding // 4 * 4)
    just = [
        offsets[0],
        offsets[1] - offsets[0],
        offsets[2] - offsets[1],
        offsets[3] - offsets[2],
        offsets[4] - offsets[3],
        offsets[5] - offsets[4],
        name_padding,
    ]
    return b'\n'.join([bcpVersion, str(len(bcp_columns)).encode()] + [
        b"".join(
            [
                str(i_col).encode().ljust(just[0]),
                col.type.encode().ljust(just[1]),
                str(col.bytes_indicator).encode().ljust(just[2]),
                str(col.bytes_data).encode().ljust(just[3]),
                b'""'.ljust(just[4]),
                str(i_col).encode().ljust(just[5]),
                col.column_name.encode().ljust(just[6]),
                # b"LATIN1_GENERAL_100_CI_AS_SC_UTF8" if col.type == "SQLCHAR" else b'""',
                col.collation.encode(),
            ]
        )
        for i_col, col in enumerate(bcp_columns, 1)
    ] + [b""])


def format_genereate(sample_row: typing.Iterable) -> list[bcpColumn]:
    bcp_columns = []
    for i_col, col in enumerate(sample_row, 1):
        match col:
            case str():
                bcp_columns.append(bcpColumn("SQLCHAR", 8, 0, f"Column{i_col}", "LATIN1_GENERAL_100_CI_AS_SC_UTF8"))
            case bytes():
                bcp_columns.append(bcpColumn("SQLBINARY", 8, 0, f"Column{i_col}", '""'))
            case bool():
                bcp_columns.append(bcpColumn("SQLBIT", 1, 1, f"Column{i_col}", '""'))
            case int():
                bcp_columns.append(bcpColumn("SQLBIGINT", 1, 8, f"Column{i_col}", '""'))
            case float():
                bcp_columns.append(bcpColumn("SQLFLT8", 1, 8, f"Column{i_col}", '""'))
            case Decimal():
                bcp_columns.append(bcpColumn("SQLDECIMAL", 1, 19, f"Column{i_col}", '""'))
            case datetime.date():
                if not hasattr(col, "hour"):
                    bcp_columns.append(bcpColumn("SQLDATE", 1, 3, f"Column{i_col}", '""'))
                elif col.tzinfo is None:
                    bcp_columns.append(bcpColumn("SQLDATETIME2", 1, 8, f"Column{i_col}", '""'))
                else:
                    bcp_columns.append(bcpColumn("SQLDATETIMEOFFSET", 1, 10, f"Column{i_col}", '""'))
            case UUID():
                bcp_columns.append(bcpColumn("SQLUNIQUEID", 1, 16, f"Column{i_col}", '""'))
            case _:
                raise TypeError(f"Unknown type {type(col)}")
    return bcp_columns


def test_format():
    sample_row = [b"Hello", "Wörld", 1, 1.0, Decimal("1.0"),
        datetime.date.today(), datetime.datetime.now(), datetime.datetime.now(datetime.UTC), UUID(int=0)]
    bcp_columns = format_genereate(sample_row)
    fmt_bytes = format_dump(bcp_columns)
    assert format_load(fmt_bytes) == bcp_columns


def bcp_repr(dtype, data):
    if data is None:
        return None
    match dtype:
        case "SQLBIGINT" | "SQLBIT" | "SQLSMALLINT" | "SQLINT" | "SQLTINYINT":
            return int.from_bytes(data, "little")
        case "SQLBINARY":
            return data.hex()
        case "SQLCHAR":
            return data.decode() # todo read from format file like "latin1"
        case "SQLNCHAR":
            return data.decode("utf-16-le")
        case "SQLDATE":
            return datetime.date.fromordinal(int.from_bytes(data, "little") + 1)
        case "SQLDATETIME2" | "SQLDATETIMEOFFSET":
            remainder, fractional = divmod(int.from_bytes(data[:5], "little"), 10000_000)
            remainder, second = divmod(remainder, 60)
            hour, minute = divmod(remainder, 60)
            return datetime.datetime.combine(
                datetime.date.fromordinal(
                    int.from_bytes(data[5:8], "little") + 1
                ),
                datetime.time(hour=hour, minute=minute, second=second, microsecond=fractional // 10),
                tzinfo=(
                    datetime.timezone(datetime.timedelta(seconds=-int.from_bytes(data[8:], "little") * 60))
                    if dtype == "SQLDATETIMEOFFSET"
                    else None
                )
            )
        case "SQLDECIMAL" | "SQLNUMERIC":
            dec_size = data[0]
            # print(dec_size)
            dec_precision = data[1]
            dec_sign = data[2]
            # precision = int.from_bytes(data_dec[:3], "little")
            dec_data = int.from_bytes(data[3:], "little")
            return (1 if dec_sign == 1 else -1) * Decimal(dec_data) / 10**dec_precision

        case "SQLMONEY": # TODO large/negative
            ret = Decimal(int.from_bytes(data[4:], "little")) / 10_000
            # print(dtype, data, Decimal(ret))
            return ret

        case "SQLMONEY4":
            ret = Decimal(int.from_bytes(data, "little")) / 10_000
            # print(dtype, data, Decimal(ret))
            return ret

        case "SQLUNIQUEID":
            return UUID(bytes_le=data)

        case _:
            # return [*data]
            return data


def data_load(
    file: typing.BinaryIO,
    bcp_columns: list[bcpColumn]
) -> typing.Generator[list, None, None]:
    def read(n, can_be_eof=False):
        data = file.read(n)
        if len(data) != n:
            if can_be_eof and len(data) == 0:
                raise StopIteration()
            raise EOFError(f"Expected {n} bytes, got {len(data)} bytes. {can_be_eof}")
        return data

    for nr_line in itertools.count():
        line = []
        try:
            for nr_column, column in enumerate(bcp_columns):
                if column.bytes_indicator:
                    # indicator = int.from_bytes(data[idx:idx+column.bytes_indicator], "little")
                    indicator = int.from_bytes(read(column.bytes_indicator, can_be_eof=True), "little")
                    if indicator == 2**(column.bytes_indicator*8)-1: # -1
                        data_column = None
                    else:
                        data_column = read(indicator)
                else:
                    indicator = None
                    data_column = read(column.bytes_data, can_be_eof=True)
                line.append(bcp_repr(column.type, data_column))
            yield line
        except StopIteration:
            if not line:
                break
            raise


def data_write(
    file: typing.BinaryIO,
    rows: typing.Iterable[typing.Iterable],
    bcp_columns: list[bcpColumn]
) -> None:
    null = b"\xff" * 10
    nr_columns = len(bcp_columns)
    write = file.write
    for row in rows:
        assert len(row) == nr_columns, (nr_columns, row)
        for cell, bcp_col in zip(row, bcp_columns):
            if cell is None:
                write(null[:bcp_col.bytes_indicator])
                continue
            match bcp_col.type:
                case "SQLCHAR":
                    data = cell.encode()
                    write(pack(f"<q{len(data)}s", len(data), data))
                case "SQLBINARY":
                    write(pack(f"<q{len(cell)}s", len(cell), cell))
                case "SQLBIGINT":
                    write(pack("<bq", 8, cell))
                case "SQLBIT":
                    write(pack("<bb", 1, cell))
                case "SQLFLT8":
                    write(pack("<bd", 8, cell))
                case "SQLDECIMAL":
                    dec_int, dec_prec = cell.as_integer_ratio()
                    if dec_int >= 0:
                        dec_sign = 1
                    else:
                        dec_sign = 0
                        dec_int = -dec_int
                    write(pack(
                        "<bbbb16s",
                        19,
                        1 + int(math.floor(math.log10(dec_int))) if dec_int else 0,
                        int(math.log10(dec_prec)),
                        dec_sign,
                        dec_int.to_bytes(16, "little")
                    ))
                case "SQLDATE":
                    write(pack("<b3s", 3, (cell.toordinal() - 1).to_bytes(3, "little")))
                case "SQLDATETIME2":
                    write(pack(
                        "<b5s3s", 8,
                        (cell.microsecond * 10 + cell.second * 10_000_000 + cell.minute * 600_000_000 + cell.hour * 36_000_000_000).to_bytes(5, "little"),
                        (cell.toordinal() - 1).to_bytes(3, "little"),
                    ))
                case "SQLDATETIMEOFFSET":
                    write(pack(
                        "<b5s3sh", 10,
                        (cell.microsecond * 10 + cell.second * 10_000_000 + cell.minute * 600_000_000 + cell.hour * 36_000_000_000).to_bytes(5, "little"),
                        (cell.toordinal() - 1).to_bytes(3, "little"),
                        int(cell.tzinfo.utcoffset(cell).total_seconds() // 60)
                    ))
                case "SQLUNIQUEID":
                    write(pack("<b16s", 16, cell.bytes_le))


def test_write():
    from io import BytesIO
    file = BytesIO()
    sample_row = [
        b"Hello", "Wörld", 1, 1.0, Decimal("1.0"),
        datetime.date.today(), datetime.datetime.now(), datetime.datetime.now(datetime.timezone(datetime.timedelta(seconds=4000))),
        UUID(int=123456787890843254432543243254325432)
    ]
    bcp_columns = format_genereate(sample_row)
    data_write(file, [sample_row] * 10, bcp_columns)
    file.seek(0)
    data_load(file, bcp_columns)


def test_rw():
    with open("fmt_types.fmt", "rb") as file:
        fmt = format_load(file.read())
    with open("out_types", "rb") as file:
        for i, row in enumerate(data_load(file, fmt)):
            print(i, row)


def find_sample(rows: typing.Iterable[tuple]):
    rows_iter = iter(rows)
    sample = list(next(rows_iter))
    nulls = [i for i, j in enumerate(sample) if j is None]
    if not nulls:
        return sample
    for row in rows_iter:
        for i in nulls:
            if row[i] is not None:
                sample[i] = row[i]
                nulls.remove(i)
                if not nulls:
                    return sample