import subprocess
import collections

bcpCon = collections.namedtuple("bcpCon", ['exe', 'con_params'])

def download(bcp_con: bcpCon, table: str, name: str):
    proc1 = subprocess.run(
        [bcp_con.exe, table, "format", "nul", "-f", f"{name}.fmt", *bcp_con.con_params, "-n"],
        capture_output=True,
    )
    proc2 = subprocess.run(
        [bcp_con.exe, table, "out", f"{name}.dat", "-f", f"{name}.fmt", *bcp_con.con_params],
        capture_output=True,
    )
    return [
        (proc1.check_returncode(), proc1.stdout, proc1.stderr),
        (proc2.check_returncode(), proc2.stdout, proc2.stderr),
    ]

def upload(bcp_con: bcpCon, table: str, name: str):
    proc1 = subprocess.run(
        [bcp_con.exe, table, "in", f"{name}.dat", "-f", f"{name}.fmt", *bcp_con.con_params],
        capture_output=True,
    )
    return (proc1.check_returncode(), proc1.stdout, proc1.stderr)
