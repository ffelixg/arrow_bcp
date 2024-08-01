from setuptools.command.build_ext import build_ext
from setuptools import Extension, setup
import sys
import subprocess
from pathlib import Path
import platform
import sysconfig

module_name = "arrow_bcp"

class ZigBuilder(build_ext):
    def build_extension(self, ext):
        source, = ext.sources
        build_path = Path(self.build_lib, module_name)
        build_path.mkdir(parents=True, exist_ok=True)

        with Path("src-zig", "include_dirs.zig").open("w") as f:
            f.write(
                f"pub const paths: [{len(self.include_dirs)}][]const u8 = .{{\n"
                + "".join(f'    "{inc}",\n' for inc in self.include_dirs)
                + "};"
            )

        subprocess.call([
            sys.executable,
            "-m",
            "ziglang",
            "build",
        ], cwd=source)

        binary, = (p for p in Path("src-zig", "zig-out").glob("**/*") if p.is_file())
        binary.rename(build_path / self.get_ext_filename(ext.name))

setup(
    ext_modules=[Extension("zig_ext", ["src-zig"])],
    cmdclass={"build_ext": ZigBuilder},
)