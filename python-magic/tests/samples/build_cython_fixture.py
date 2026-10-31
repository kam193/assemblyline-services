"""
Build real Cython test fixtures for the Cython compressed string table extractor.

Prerequisites:
    pip install "cython>=3.2.0"   # >=3.3.0 to build the LZSS fixture
    # Python development headers must be installed (e.g. python3-dev on Debian)

Run from the python-magic directory:
    python tests/samples/build_cython_fixture.py

This script, depending on the installed Cython:
- 3.2.x: cythonizes fixture_large.pyx and compiles
   - cython_fixture_zlib.<ext>.so  — default compression (zlib)
   - cython_fixture_bz2.<ext>.so   — bz2 compression (-DCYTHON_COMPRESS_STRINGS=2)
- 3.3+: cythonizes fixture_lzss.pyx and compiles
   - cython_fixture_lzss.<ext>.so  — default compression (LZSS, algo 90)

Notes:
- The resulting .so is specific to the host platform and Python version.
- Regenerate the fixtures after any change to the matching .pyx.

Committed fixtures:
    cython_fixture_zlib.cpython-<ver>-<arch>.so
    cython_fixture_bz2.cpython-<ver>-<arch>.so
    cython_fixture_lzss.cpython-<ver>-<arch>.so
"""

import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile

import Cython

_HERE = os.path.dirname(os.path.abspath(__file__))

_LEGACY_VARIANTS = [
    ("zlib", [], "fixture_large"),
    ("bz2", ["-DCYTHON_COMPRESS_STRINGS=2"], "fixture_large"),
]
_LZSS_VARIANTS = [("lzss", [], "fixture_lzss")]


def _cython_version() -> tuple[int, ...]:
    return tuple(int(part) for part in Cython.__version__.split(".")[:2] if part.isdigit())


def main():
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    include = sysconfig.get_path("include")
    variants = _LZSS_VARIANTS if _cython_version() >= (3, 3) else _LEGACY_VARIANTS

    with tempfile.TemporaryDirectory() as tmpdir:
        for algo_name, cflags, module in variants:
            pyx_copy = os.path.join(tmpdir, f"{module}.pyx")
            shutil.copy(os.path.join(_HERE, f"{module}.pyx"), pyx_copy)
            c_file = os.path.join(tmpdir, f"{module}.c")
            print(f"Cythonizing {module}.pyx with Cython {Cython.__version__}…")
            subprocess.check_call([sys.executable, "-m", "cython", pyx_copy, "-o", c_file])
            with open(c_file) as f:
                assert f"compression: {algo_name}" in f.read(), f"{algo_name} not emitted"

            out_name = f"cython_fixture_{algo_name}{suffix}"
            out_path = os.path.join(_HERE, out_name)
            print(f"Compiling {out_name}…")
            subprocess.check_call(
                ["gcc", "-shared", "-fPIC", "-O2", f"-I{include}", *cflags, c_file, "-o", out_path]
            )
            print(f"  Written: {out_path}  ({os.path.getsize(out_path)} bytes)")


if __name__ == "__main__":
    main()
