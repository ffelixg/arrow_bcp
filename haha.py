import typing
import tempfile
from pathlib import Path
import bcp
import subprocess


bcp_exe = "bcp"


class BcpReader:
    "Used by fetch_iter"
    def __init__(self, path_data: Path, tempdir_read: tempfile.TemporaryDirectory, fmt: list[bcp.bcpColumn]):
        self.path_data = path_data
        self.tempdir_read = tempdir_read
        self._file_dat = None
        self.fmt = fmt

    def __iter__(self):
        if self._file_dat is None:
            raise Exception("Must use from context manager")
        return bcp.data_load(self._file_dat, self.fmt)

    def __enter__(self):
        self.tempdir_read.__enter__()
        self._file_dat = self.path_data.open("rb")
        self._file_dat.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._file_dat.__exit__(exc_type, exc_value, traceback)
        self.tempdir_read.__exit__(exc_type, exc_value, traceback)


class ConnectionInfo:
    def __init__(self, *bcp_args):
        "bcp_args get passed directly to bcp subprocess."
        self.bcp_args = bcp_args

    def download(self, path_format: Path, path_data: Path, table: str=None, query: str=None) -> str:
        proc1 = subprocess.run(
            [bcp_exe, table, "format", "nul", "-f", str(path_format), *self.bcp_args, "-n"],
            capture_output=True,
        )
        proc2 = subprocess.run(
            [bcp_exe, table, "out", str(path_data), "-f", str(path_format), *self.bcp_args],
            capture_output=True,
        )
        try:
            proc1.check_returncode()
            proc2.check_returncode()
        except Exception as e:
            raise Exception(
                "Processes terminated with error",
                proc1.stdout, proc1.stderr, proc2.stdout, proc2.stderr
            ) from e
        else:
            return [proc1.stdout, proc2.stdout]

    def upload(self, path_format: Path, path_data: Path, table: str) -> str:
        proc = subprocess.run(
            [bcp_exe, table, "in", str(path_data), "-f", str(path_format), *self.bcp_args],
            capture_output=True,
        )
        try:
            proc.check_returncode()
        except Exception as e:
            raise Exception(
                "Processes terminated with error",
                proc.stdout, proc.stderr
            ) from e
        else:
            return proc.stdout

    def insert_pytypes(self, table: str, rows: list[tuple], sample_row: tuple = None):
        "Insert rows into table"
        if sample_row is None:
            sample_row = bcp.find_sample(rows)
        with tempfile.TemporaryDirectory() as tmpdir_dl_name:
            path_fmt = Path(tmpdir_dl_name) / "bcp_download.fmt"
            path_dat = Path(tmpdir_dl_name) / "bcp_download.dat"
            fmt = bcp.format_genereate(sample_row)
            with path_fmt.open("wb") as f:
                f.write(bcp.format_dump(fmt))
            with path_dat.open("wb") as f:
                bcp.data_write(file=f, rows=rows, bcp_columns=fmt)
            print(self.upload(path_fmt, path_dat, table))

    def arrow(self, table: str=None, query: str=None):
        "Return arrow table for table or query"
        raise NotImplementedError

    def arrow_iter(self, batch_size, table: str=None, query: str=None) -> typing.Iterator:
        "Return iterator of arrow tables for table or query"
        raise NotImplementedError

    def fetch(self, table: str=None, query: str=None) -> list[tuple]:
        "Return list of tuples for table or query"
        with self.fetch_iter(table, query) as it:
            return list(it)

    def fetch_iter(self, table: str=None, query: str=None) -> BcpReader:
        with tempfile.TemporaryDirectory() as tmpdir_dl_name:
            path_fmt = Path(tmpdir_dl_name) / "bcp_download.fmt"
            path_dat = Path(tmpdir_dl_name) / "bcp_download.dat"
            print(self.download(path_fmt, path_dat, table, query))
            with path_fmt.open("rb") as f:
                fmt = bcp.format_load(f.read())
            tmpdir_read = tempfile.TemporaryDirectory()
            path_dat.rename(Path(tmpdir_read.name) / "bcp_download.dat")
            return BcpReader(path_data=Path(tmpdir_read.name) / "bcp_download.dat", tempdir_read=tmpdir_read, fmt=fmt)

