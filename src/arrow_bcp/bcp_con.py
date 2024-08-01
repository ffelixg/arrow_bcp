import typing
import tempfile
from pathlib import Path
import subprocess
import pyarrow as pa

from . import bcp_format, bcp_data

bcp_exe = "bcp"

class BcpReader:
    "Used by fetch_iter"
    def __init__(self, path_data: Path, tempdir_read: tempfile.TemporaryDirectory, bcp_columns: list[bcp_format.bcpColumn]):
        self.path_data = path_data
        self.tempdir_read = tempdir_read
        self.bcp_columns = bcp_columns
        self.has_entered = False

    def __iter__(self) -> typing.Generator[pa.RecordBatch, None, None]:
        if not self.has_entered:
            raise Exception("Must use from context manager")
        return bcp_data.load(path_data=self.path_data, bcp_columns=self.bcp_columns)

    def __enter__(self):
        self.tempdir_read.__enter__()
        self.has_entered = True
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.tempdir_read.__exit__(exc_type, exc_value, traceback)


class ConnectionInfo:
    def __init__(self, bcp_args):
        "bcp_args get passed directly to bcp subprocess."
        self.bcp_args = bcp_args

    def download_format_file(self, path_format: Path, table: str) -> str:
        proc = subprocess.run(
            [bcp_exe, table, "format", "nul", "-f", str(path_format), *self.bcp_args, "-n"],
            capture_output=True,
        )
        try:
            proc.check_returncode()
        except Exception as e:
            raise Exception(
                f"BCP process to download format for {table=} terminated with error",
                proc.stdout, proc.stderr,
            ) from e
        else:
            return proc.stdout

    def download_data_file(self, path_format: Path, path_data: Path, table: str) -> str:
        proc = subprocess.run(
            [bcp_exe, table, "out", str(path_data), "-f", str(path_format), *self.bcp_args],
            capture_output=True,
        )
        try:
            proc.check_returncode()
        except Exception as e:
            raise Exception(
                f"BCP process to download data for {table=} terminated with error",
                proc.stdout, proc.stderr,
            ) from e
        else:
            return proc.stdout

    def insert_file(self, path_format: Path, path_data: Path, table: str) -> str:
        proc = subprocess.run(
            [bcp_exe, table, "in", str(path_data), "-f", str(path_format), *self.bcp_args],
            capture_output=True,
        )
        try:
            proc.check_returncode()
        except Exception as e:
            raise Exception(
                f"BCP process to insert into {table=} terminated with error",
                proc.stdout, proc.stderr
            ) from e
        else:
            return proc.stdout

    def insert_arrow(self, table: str, arrow_data: pa.Table | typing.Iterable[pa.RecordBatch]):
        "Insert rows into table"
        with tempfile.TemporaryDirectory() as tmpdir_dl_name:
            path_fmt = Path(tmpdir_dl_name) / "bcp_download.fmt"
            path_dat = Path(tmpdir_dl_name) / "bcp_download.dat"
            if isinstance(arrow_data, pa.Table):
                arrow_data = arrow_data.to_batches()
            bcp_data.dump(batches=arrow_data, path_format=path_fmt, path_data=path_dat)
            print(self.insert_file(path_format=path_fmt, path_data=path_dat, table=table))

    def download_arrow_batches(self, table: str) -> BcpReader:
        with tempfile.TemporaryDirectory(prefix="arrow_bcp_") as tmpdir_dl_name:
            path_fmt = Path(tmpdir_dl_name) / "bcp_download.fmt"
            print(self.download_format_file(path_fmt, table))
            with path_fmt.open("rb") as f:
                bcp_columns = bcp_format.load(f.read())
            
            bcp_columns = bcp_format.native_to_implemented_types(bcp_columns)

            with path_fmt.open("wb") as f:
                f.write(bcp_format.dump(bcp_columns))
            
            path_dat = Path(tmpdir_dl_name) / "bcp_download.dat"
            print(self.download_data_file(path_format=path_fmt, path_data=path_dat, table=table))

            tmpdir_read = tempfile.TemporaryDirectory(prefix="arrow_bcp_")
            path_dat.rename(Path(tmpdir_read.name) / "bcp_download.dat")
            return BcpReader(path_data=Path(tmpdir_read.name) / "bcp_download.dat", tempdir_read=tmpdir_read, bcp_columns=bcp_columns)

    def download_arrow_table(self, table: str) -> pa.Table:
        with self.download_arrow_batches(table) as reader:
            return pa.Table.from_batches(reader)
