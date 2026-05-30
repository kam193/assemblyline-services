"""
Build real Cython test fixtures for the Cython compressed string table extractor.

Prerequisites:
    pip install "cython>=3.2.0"
    # Python development headers must be installed (e.g. python3-dev on Debian)

Run from the python-magic directory:
    python tests/samples/build_cython_fixture.py

This script:
1. Cythonizes fixture_large.pyx into C code
2. Compiles two .so variants:
   - cython_fixture_zlib.<ext>.so  — default compression (zlib)
   - cython_fixture_bz2.<ext>.so   — bz2 compression (-DCYTHON_COMPRESS_STRINGS=2)

Notes:
- The resulting .so is specific to the host platform and Python version.
- LZSS (algo 90) requires Cython.LZSS which is not yet part of Cython 3.2.x.
  LZSS support is tested via a pure round-trip test using lzss_compress from
  build_lzss_fixture.py rather than a real compiled module.
- Regenerate the fixtures after any change to fixture_large.pyx.

Committed fixtures:
    cython_fixture_zlib.cpython-<ver>-<arch>.so
    cython_fixture_bz2.cpython-<ver>-<arch>.so
"""

import os
import shutil
import subprocess
import sysconfig
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_PYX = os.path.join(_HERE, "fixture_large.pyx")


def main():
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    include = sysconfig.get_path("include")

    with tempfile.TemporaryDirectory() as tmpdir:
        pyx_copy = os.path.join(tmpdir, "fixture_large.pyx")
        shutil.copy(_PYX, pyx_copy)

        c_file = os.path.join(tmpdir, "fixture_large.c")
        print(f"Cythonizing {_PYX}…")
        subprocess.check_call(["python3", "-m", "cython", pyx_copy, "-o", c_file])

        for algo_name, cflags in [
            ("zlib", []),
            ("bz2", ["-DCYTHON_COMPRESS_STRINGS=2"]),
        ]:
            out_name = f"cython_fixture_{algo_name}{suffix}"
            out_path = os.path.join(_HERE, out_name)
            print(f"Compiling {out_name}…")
            subprocess.check_call(
                [
                    "gcc",
                    "-shared",
                    "-fPIC",
                    "-O2",
                    f"-I{include}",
                    *cflags,
                    c_file,
                    "-o",
                    out_path,
                ]
            )
            size = os.path.getsize(out_path)
            print(f"  Written: {out_path}  ({size} bytes)")


if __name__ == "__main__":
    main()
