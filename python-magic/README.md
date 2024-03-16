# Python-Magic

## Supported features

### Extracting PyInstaller executables

Extracts the content of PyInstaller executables using [pyinstxtractor-ng](https://github.com/pyinstxtractor/pyinstxtractor-ng),
and by default try to avoid extracting common files like linked libraries, additional packages, built-ins, PyInstaller hooks etc.

Submission params:

- `extract_all`: Extract all files from the PyInstaller executable (default: `False`,
  the same as performing a deep scan)
- `extract_pyz_content`: Extract the content of the `PYZ` archives (default: `False`)

Service config:

- `MAX_EXTRACTED` - limit the number of extracted files; the effective value is a limit of this and the system provided value.

### Decompyling Python bytecode

Decompyling Python bytecode (.pyc) using [Decompyle++](https://github.com/zrax/pycdc)
