from setuptools.command.build_ext import build_ext
from setuptools import Extension, setup
import sys
import subprocess
from pathlib import Path
import platform
import sysconfig
import shutil

module_name = "arrow_bcp"

class ZigBuilder(build_ext):
    def build_extension(self, ext):
        source, = ext.sources
        build_path = Path(self.build_lib, module_name)
        build_path.mkdir(parents=True, exist_ok=True)

        def escape(path):
            return path.replace("\\", "\\\\")
        
        lib_paths = [str(Path(sysconfig.get_config_var('installed_base'), "Libs").absolute())]
        with Path("src-zig", "include_dirs.zig").open("w", encoding="utf-8") as f:
            f.write(
                f"pub const include: [{len(self.include_dirs)}][]const u8 = .{{\n"
                + "".join(f'    "{p}",\n' for p in map(escape, self.include_dirs))
                + "};\n"
                + f"pub const lib: [{len(lib_paths)}][]const u8 = .{{\n"
                + "".join(f'    "{p}",\n' for p in map(escape, lib_paths))
                + "};\n"
            )

        windows = platform.system() == "Windows"

        subprocess.call([
            sys.executable,
            "-m",
            "ziglang",
            "build",
            *(["-Dtarget=x86_64-windows"] if windows else []),
        ], cwd=source)

        binary, = (p for p in Path("src-zig", "zig-out").glob(f"**/*{'.dll' if windows else ''}") if p.is_file())
        shutil.copyfile(binary, build_path / self.get_ext_filename(ext.name))

setup(
    ext_modules=[Extension("zig_ext", ["src-zig"])],
    cmdclass={"build_ext": ZigBuilder},
)
