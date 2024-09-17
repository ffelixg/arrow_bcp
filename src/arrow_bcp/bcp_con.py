import typing
import tempfile
from pathlib import Path
import subprocess
import pyarrow as pa

from . import bcp_format, bcp_data

bcp_exe = "bcp"


def set_bcp_executable(location: str):
    global bcp_exe
    bcp_exe = location


class BcpError(subprocess.SubprocessError):
    "Raised when a bcp subprocess fails"
    pass


class BcpReader:
    "Used by fetch_iter, don't invoke directly"

    def __init__(
        self,
        path_data: Path,
        tempdir_read: tempfile.TemporaryDirectory,
        bcp_columns: list[bcp_format.bcpColumn],
        batch_size: int,
    ):
        self.path_data = path_data
        self.tempdir_read = tempdir_read
        self.bcp_columns = bcp_columns
        self.has_entered = False
        self.batch_size = batch_size

    def __iter__(self) -> typing.Generator[pa.RecordBatch, None, None]:
        if not self.has_entered:
            raise Exception("Must use from context manager")
        return bcp_data.load(
            path_data=self.path_data,
            bcp_columns=self.bcp_columns,
            max_rows=self.batch_size,
        )

    def __enter__(self):
        self.tempdir_read.__enter__()
        self.has_entered = True
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.tempdir_read.__exit__(exc_type, exc_value, traceback)


def _run_proc(args, operation):
    proc = subprocess.run(args, capture_output=True)
    try:
        proc.check_returncode()
    except subprocess.SubprocessError as e:
        raise BcpError(
            f"BCP process to {operation} terminated with error",
            proc.stdout,
            proc.stderr,
        ) from e
    else:
        if proc.stderr:
            raise BcpError(
                f"BCP process to {operation} received unexpected stderr",
                proc.stdout,
                proc.stderr,
            )
        return proc.stdout


class ConnectionInfo:
    """
    bcp_args gets unpacked directly into the bcp subprocess call. See Microsoft's
    official bcp.exe documentation for authentication options.

    The path to the bcp executable is defined on the package level and can be
    modified elsewhere.

    Arguments regarding table name/format like "in", "out", "format", "-f" "-n"
    are managed by arrow_bcp.

    Consider passing "-h" "TABLOCK" to potentially speed up inserts.
    """

    def __init__(self, bcp_args: typing.Iterable):
        self.bcp_args = bcp_args

    def download_format_file(self, path_format: Path, table: str) -> str:
        """
        Execute a bcp process to download the native format file for the specified table.
        Return stdout on success or stdout + stderr as part of an Exception on failure.
        """
        return _run_proc(
            [
                bcp_exe,
                table,
                "format",
                "nul",
                "-f",
                str(path_format),
                *self.bcp_args,
                "-n",
            ],
            "download a format file",
        )

    def download_data_file(self, path_format: Path, path_data: Path, table: str) -> str:
        """
        Execute a bcp process to download the data file based on the specified format file.
        Return stdout on success or stdout + stderr as part of an Exception on failure.
        """
        return _run_proc(
            [
                bcp_exe,
                table,
                "out",
                str(path_data),
                "-f",
                str(path_format),
                *self.bcp_args,
            ],
            "download data",
        )

    def insert_file(self, path_format: Path, path_data: Path, table: str) -> str:
        """
        Execute a bcp process to insert the data from the data/format files into the specified table.
        Return stdout on success or stdout + stderr as part of an Exception on failure.
        """
        return _run_proc(
            [
                bcp_exe,
                table,
                "in",
                str(path_data),
                "-f",
                str(path_format),
                *self.bcp_args,
            ],
            "insert data",
        )

    def insert_arrow(
        self, table: str, arrow_data: pa.Table | typing.Iterable[pa.RecordBatch]
    ):
        "Bulk insert arrow table or record batches into table"
        with tempfile.TemporaryDirectory(prefix="arrow_bcp_write_") as tmpdir_dl_name:
            path_fmt = Path(tmpdir_dl_name) / "bcp_download.fmt"
            path_dat = Path(tmpdir_dl_name) / "bcp_download.dat"
            if isinstance(arrow_data, pa.Table):
                arrow_data = arrow_data.to_batches()
            if bcp_data.dump(
                batches=arrow_data, path_format=path_fmt, path_data=path_dat
            ):
                self.insert_file(path_format=path_fmt, path_data=path_dat, table=table)

    def download_arrow_batches(self, table: str, batch_size: int = 500) -> BcpReader:
        """
        Download data for a table and return iterable of arrow batches to allow lazy loading.
        The returned reader object must be used from a context manager. Upon exiting the
        reader object, the temporary BCP data file will be cleaned up.
        """
        with tempfile.TemporaryDirectory(prefix="arrow_bcp_read_") as tmpdir_dl_name:
            path_fmt = Path(tmpdir_dl_name) / "bcp_download.fmt"
            self.download_format_file(path_fmt, table)
            with path_fmt.open("rb") as f:
                bcp_columns = bcp_format.load(f.read())

            bcp_columns = bcp_format.native_to_implemented_types(bcp_columns)

            with path_fmt.open("wb") as f:
                f.write(bcp_format.dump(bcp_columns))

            path_dat = Path(tmpdir_dl_name) / "bcp_download.dat"
            self.download_data_file(
                path_format=path_fmt, path_data=path_dat, table=table
            )

            tmpdir_read = tempfile.TemporaryDirectory(prefix="arrow_bcp_read_")
            path_dat.rename(Path(tmpdir_read.name) / "bcp_download.dat")
            return BcpReader(
                path_data=Path(tmpdir_read.name) / "bcp_download.dat",
                tempdir_read=tmpdir_read,
                bcp_columns=bcp_columns,
                batch_size=batch_size,
            )

    def download_arrow_table(self, table: str, batch_size: int = 500) -> pa.Table:
        """
        Wrapper around download_arrow_batches returning a singular table. The table's
        entire data is loaded at once.
        """
        with self.download_arrow_batches(table) as reader:
            batches = [*reader]
        target_schema = batches[-1].schema
        for i_batch, batch in enumerate(batches[:-1]):
            if batch.schema != target_schema:
                batches[i_batch] = batch.cast(target_schema)
            else:
                # once we figured out the schema it will not change anymore
                break
        return pa.Table.from_batches(batches)
