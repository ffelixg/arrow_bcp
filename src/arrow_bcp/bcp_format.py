import collections

space = b" "[0]
offsets = (8, 28, 36, 44, 49, 55)
bcpColumn = collections.namedtuple(
    "bcpColumn", ["type", "bytes_indicator", "bytes_data", "column_name", "collation"]
)
bcpVersion = b"14.0"
collation_utf8 = "LATIN1_GENERAL_100_CI_AS_SC_UTF8"
collation_default = '""'


def load(format_bytes: bytes) -> list[bcpColumn]:
    "Parse format and run some checks ensuring correctness."
    version, nr_lines, *lines = format_bytes.splitlines()
    float(version)
    assert len(lines) == int(nr_lines.decode())
    spacers = set.intersection(
        *[
            set(
                i for i in range(len(line)) if line[i] != space and line[i - 1] == space
            )
            for i_line, line in enumerate(lines)
        ]
    )
    assert len(spacers) == 7
    assert spacers - {max(spacers)} == set(offsets)
    spacers = sorted(spacers)
    columns = []
    for i_line, line in enumerate(lines):
        assert line[0] != space
        assert line[-1] != space
        parts = [line[start:end] for start, end in zip([0] + spacers, spacers + [None])]
        assert int(parts[0].decode().strip()) == i_line + 1
        assert int(parts[5].decode().strip()) == i_line + 1
        col_args = [
            i.strip().decode(errors="ignore")
            for i in [parts[1], parts[2], parts[3], parts[6], parts[7]]
        ]
        col_args[1] = int(col_args[1])
        col_args[2] = int(col_args[2])
        columns.append(bcpColumn(*col_args))
    return columns


def dump(bcp_columns: list[bcpColumn]) -> bytes:
    "Convert to content of a bcp format file"
    # name_padding = max(len(i.column_name) for i in bcp_columns) + 16
    name_padding = len(bcp_columns) + 16
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
    return b"\n".join(
        [bcpVersion, str(len(bcp_columns)).encode()]
        + [
            b"".join(
                [
                    str(i_col).encode().ljust(just[0]),
                    col.type.encode().ljust(just[1]),
                    str(col.bytes_indicator).encode().ljust(just[2]),
                    str(col.bytes_data).encode().ljust(just[3]),
                    b'""'.ljust(just[4]),
                    str(i_col).encode().ljust(just[5]),
                    # col.column_name.encode().ljust(just[6]),
                    (b"a" * i_col).ljust(just[6]),
                    # b"LATIN1_GENERAL_100_CI_AS_SC_UTF8" if col.type == "SQLCHAR" else b'""',
                    col.collation.encode(),
                ]
            )
            for i_col, col in enumerate(bcp_columns, 1)
        ]
        + [b""]
    )


def native_to_implemented_types(bcp_columns: list[bcpColumn]) -> list[bcpColumn]:
    "Convert SQL types to ones that are closer to arrow types"
    converted_bcp_columns = []
    for col in bcp_columns:
        new_type = col.type
        new_bytes_indicator = 1  # always request null indicator
        new_bytes_data = col.bytes_data
        new_collation = collation_default
        match col.type:
            case "SQLBINARY" | "SQLUDT":
                new_type = "SQLBINARY"
                new_bytes_data = 0  # or varbinary(max)
                new_bytes_indicator = 8
            case "SQLCHAR" | "SQLNCHAR" | "SQLVARIANT":
                new_type = "SQLCHAR"
                new_bytes_data = 0  # request as varchar(max)
                new_bytes_indicator = 8
                new_collation = collation_utf8
            case "SQLDATETIM4" | "SQLDATETIME":
                new_type = "SQLDATETIME2"
                new_bytes_data = 8
            case "SQLMONEY" | "SQLMONEY4" | "SQLNUMERIC":
                new_type = "SQLDECIMAL"
                new_bytes_data = 19
        converted_bcp_columns.append(
            bcpColumn(
                type=new_type,
                bytes_indicator=new_bytes_indicator,
                bytes_data=new_bytes_data,
                column_name=col.column_name,
                collation=new_collation,
            )
        )
    return converted_bcp_columns
