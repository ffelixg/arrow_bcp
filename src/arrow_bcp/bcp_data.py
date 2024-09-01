import pyarrow as pa
from pathlib import Path
import typing
import itertools
from . import zig_ext, bcp_format


def array_capsule_generator(batch_iter: typing.Iterable[pa.RecordBatch], i_col: int):
    dtype_prev = None
    for batch in batch_iter:
        col = batch.columns[i_col]
        assert dtype_prev is None or col.type == dtype_prev
        dtype_prev = col.type
        _, capsule_array = col.__arrow_c_array__()
        yield capsule_array


def dump(
    batches: typing.Iterable[pa.RecordBatch], path_format: Path, path_data: Path
) -> bool:
    """
    Write arrow data to bcp files. It is assumed that each batch has the same schema.
    Return True if any data was written and False if no batches got submitted.
    """
    batch_iter = iter(batches)
    try:
        first_batch = next(batch_iter)
    except StopIteration:
        return False
    names = first_batch.column_names
    schema_capsules = [arr.__arrow_c_array__()[0] for arr in first_batch.columns]
    batch_iterators = itertools.tee(
        itertools.chain([first_batch], batch_iter), len(names)
    )
    array_capsules = [
        array_capsule_generator(it, i_col) for i_col, it in enumerate(batch_iterators)
    ]

    path_data = path_data.absolute()
    assert path_data.parent.exists()
    sql_info = zig_ext.write_arrow(schema_capsules, array_capsules, str(path_data))

    bcp_columns = [
        bcp_format.bcpColumn(
            type=tp,
            bytes_indicator=bi,
            bytes_data=bd,
            column_name=name,
            collation=(
                bcp_format.collation_utf8
                if tp == "SQLCHAR"
                else bcp_format.collation_default
            ),
        )
        for (tp, bi, bd), name in zip(sql_info, names, strict=True)
    ]
    with path_format.open("wb") as f:
        f.write(bcp_format.dump(bcp_columns=bcp_columns))
    return True


def load(
    bcp_columns: list[bcp_format.bcpColumn], path_data: Path, max_rows: int
) -> typing.Generator[pa.RecordBatch, None, None]:
    "Load a bcp data file into arrow batches according to the specified format."
    names = [col.column_name for col in bcp_columns]

    reader_state = zig_ext.init_reader(
        [(col.type, col.bytes_indicator, col.bytes_data) for col in bcp_columns],
        str(path_data.absolute()),
    )

    go_again = True
    while go_again:
        capsules = zig_ext.read_batch(reader_state, max_rows)
        arrays = [
            pa.Array._import_from_c_capsule(schema, array) for schema, array in capsules
        ]
        batch = pa.record_batch(arrays, names=names)
        go_again = len(batch) == max_rows
        yield batch
