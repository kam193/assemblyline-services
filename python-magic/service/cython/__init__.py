"""
Detection and decompression of Cython-compiled native modules that use the
CYTHON_COMPRESS_STRINGS compile-time directive (available since Cython 3.2).

When this directive is active, Cython concatenates every Python string the module
needs, compresses the blob with one of: LZSS (algo 90, default), zlib (1), bz2 (2),
or zstd (3, Python 3.14+), and embeds it in the native binary (.so/.pyd/Mach-O).

Reference implementation: Cython/Compiler/Code.py (generate_pystring_constants)
                          Cython/Utility/StringTools.c (__pyx_lzss_decompress)
"""

import bz2
import mmap
import os
import struct
import zlib
from dataclasses import dataclass, field

# Marker present in every CYTHON_COMPRESS_STRINGS binary (part of the error template
# "String compression was configured with the C macro 'CYTHON_COMPRESS_STRINGS=%d'").
_MARKER = b"CYTHON_COMPRESS_STRINGS"

_MIN_BLOB = 64
# Minimum printable-byte fraction for the LZSS brute-force scan only.
# Real string tables with binary bytes-constants can be as low as ~50%;
# random bytes average ~37%, so 50% safely separates the two populations.
_LZSS_MIN_PRINTABLE_RATIO = 0.50

_ZLIB_SECOND_BYTES = {0x01, 0x9C, 0xDA, 0x5E}
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# How far past the end of the compressed blob to search for str_length_index[].
_INDEX_SEARCH_WINDOW = 12 * 1024


@dataclass
class DecompressedBlob:
    algorithm: str
    file_offset: int
    compressed_size: int
    plaintext: bytes
    # Individual strings split via str_length_index[]; None when the index
    # array could not be located (splitting is best-effort).
    strings: list[bytes] | None = field(default=None)


# ---------------------------------------------------------------------------
# LZSS decoder — public, tested directly
# ---------------------------------------------------------------------------


class _LZSSEnd(Exception):
    pass


def lzss_decompress(src, dst_len: int) -> bytes:
    """
    Decompress a Cython LZSS-compressed blob when the expected output size is known.

    Accepts bytes, bytearray, or memoryview.
    Direct port of __pyx_lzss_decompress from Cython/Utility/StringTools.c.
    """
    out = bytearray()
    pos = 0
    src_len = len(src)
    try:
        while True:
            if pos >= src_len:
                break
            flags = src[pos] | 0xFF00
            pos += 1
            while flags & 0x100:
                if flags & 1:
                    if pos >= src_len:
                        raise _LZSSEnd()
                    out.append(src[pos])
                    pos += 1
                else:
                    if pos + 1 >= src_len:
                        raise _LZSSEnd()
                    lo = src[pos]
                    hi = src[pos + 1]
                    pos += 2
                    if not (lo & 0x80):
                        end_offset = lo
                        match_length = hi + 3
                    elif not (hi & 0x80):
                        end_offset = ((hi << 2) & 0x180) | (lo & 0x7F)
                        match_length = (hi & 0x1F) + 3
                    else:
                        if pos >= src_len:
                            raise _LZSSEnd()
                        length_byte = src[pos]
                        pos += 1
                        end_offset = ((hi & 0x7F) << 7) | (lo & 0x7F)
                        match_length = length_byte + 3
                    ref_pos = len(out) - end_offset - match_length
                    if ref_pos < 0:
                        raise ValueError("Invalid LZSS back-reference")
                    for _ in range(match_length):
                        out.append(out[ref_pos])
                        ref_pos += 1
                if len(out) >= dst_len:
                    return bytes(out[:dst_len])
                flags >>= 1
    except _LZSSEnd:
        pass
    return bytes(out)


# ---------------------------------------------------------------------------
# str_length_index[] search — shared logic, public entry point for tests
# ---------------------------------------------------------------------------


def _collect_runs(buf, start: int, end: int) -> list[tuple[int, list[int]]]:
    """
    Find maximal aligned uint32 sequences in buf[start:end] where every value
    lies in [1, 32767].  Works on any buffer accepted by struct.unpack_from
    (bytes, bytearray, mmap, memoryview).
    """
    _MAX = 32767
    _MIN_RUN = 2
    runs: list[tuple[int, list[int]]] = []
    # Advance i to the next 4-byte-aligned position from file start.
    i = start + (4 - start % 4) % 4
    while i + 4 <= end:
        v = struct.unpack_from("<I", buf, i)[0]
        if 1 <= v <= _MAX:
            values = [v]
            j = i + 4
            while j + 4 <= end:
                v2 = struct.unpack_from("<I", buf, j)[0]
                if 1 <= v2 <= _MAX:
                    values.append(v2)
                    j += 4
                else:
                    break
            if len(values) >= _MIN_RUN:
                runs.append((i, values))
            i = j
        else:
            i += 4
    return runs


def _match_lengths(runs: list[tuple[int, list[int]]], target: int) -> list[int] | None:
    # 1. Full run: a maximal run whose sum equals target exactly (most common).
    for _, values in runs:
        if sum(values) == target:
            return list(values)

    # 2. Embedded array: the array sits inside a longer run of plausible values.
    #    Sliding window — works because all values are positive.
    for _, values in runs:
        if sum(values) <= target:
            continue
        left = 0
        window = 0
        for right in range(len(values)):
            window += values[right]
            while window > target:
                window -= values[left]
                left += 1
            if window == target and right - left + 1 >= 2:
                return values[left : right + 1]

    # 3. Two adjacent arrays (module has both str and bytes constants).
    #    Allow up to 8 bytes of alignment padding between the two runs.
    run_by_offset = {offset: values for offset, values in runs}
    for offset, values in runs:
        end_off = offset + len(values) * 4
        for gap in (0, 4, 8):
            neighbour = run_by_offset.get(end_off + gap)
            if neighbour is not None and sum(values) + sum(neighbour) == target:
                return values + neighbour

    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_plausible_lzss(data: bytes) -> bool:
    if len(data) < _MIN_BLOB:
        return False
    printable = sum(1 for b in data if 0x09 <= b <= 0x0D or 0x20 <= b <= 0x7E)
    return printable / len(data) >= _LZSS_MIN_PRINTABLE_RATIO


def _split_blob(plaintext: bytes, lengths: list[int]) -> list[bytes]:
    parts: list[bytes] = []
    offset = 0
    for length in lengths:
        parts.append(plaintext[offset : offset + length])
        offset += length
    return parts


# ---------------------------------------------------------------------------
# _FileScanner — single mmap shared across all operations on one binary
# ---------------------------------------------------------------------------


class _FileScanner:
    """
    Wraps an mmap for one binary so the file is never copied into a Python
    bytes object in full.  struct.unpack_from, mmap.find, and bz2/zlib
    decompressors all accept mmap/memoryview directly.
    """

    def __init__(self, path: str) -> None:
        self._f = open(path, "rb")
        try:
            self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        except Exception:
            self._f.close()
            raise
        self._mv = memoryview(self._mm)
        self._size = len(self._mm)

    def close(self) -> None:
        self._mv.release()
        self._mm.close()
        self._f.close()

    def _slice(self, start: int, end: int | None = None) -> memoryview:
        """Zero-copy view into the file mapping; valid until close()."""
        return self._mv[start:] if end is None else self._mv[start:end]

    # ---- detection ----

    def is_compressed(self) -> bool:
        return self._mm.find(_MARKER) != -1

    # ---- decompression ----

    def _zlib_decompress(self, offset: int) -> tuple[bytes, int] | None:
        try:
            obj = zlib.decompressobj()
            out = bytes(obj.decompress(self._slice(offset)))
            consumed = self._size - offset - len(obj.unused_data)
            return out, consumed
        except zlib.error:
            return None

    def _bz2_decompress(self, offset: int) -> tuple[bytes, int] | None:
        try:
            obj = bz2.BZ2Decompressor()
            out = bytes(obj.decompress(self._slice(offset)))
            consumed = self._size - offset - len(obj.unused_data)
            return out, consumed
        except OSError:
            return None

    def _zstd_decompress(self, offset: int) -> tuple[bytes, int | None] | None:
        try:
            from compression.zstd import decompress  # type: ignore[import]

            out = decompress(bytes(self._slice(offset)))
            return out, None
        except (ImportError, Exception):
            return None

    def _attempt(
        self,
        offset: int,
        decompress_fn,  # () -> tuple[bytes, int | None] | None
        algo: str,
        results: list[DecompressedBlob],
        seen: set[int],
    ) -> None:
        if offset in seen:
            return
        result = decompress_fn(offset)
        if result is None:
            return
        out, consumed = result
        if len(out) < _MIN_BLOB:
            return
        seen.add(offset)
        results.append(DecompressedBlob(algo, offset, consumed or 0, out))

    def _try_zlib(self, results: list[DecompressedBlob], seen: set[int]) -> None:
        i = 0
        while True:
            i = self._mm.find(b"\x78", i)
            if i == -1:
                break
            if i + 1 < self._size and self._mm[i + 1] in _ZLIB_SECOND_BYTES:
                self._attempt(i, self._zlib_decompress, "zlib", results, seen)
            i += 1

    def _try_bz2(self, results: list[DecompressedBlob], seen: set[int]) -> None:
        i = 0
        while True:
            i = self._mm.find(b"BZh", i)
            if i == -1:
                break
            if i + 3 < self._size and 0x31 <= self._mm[i + 3] <= 0x39:
                self._attempt(i, self._bz2_decompress, "bz2", results, seen)
            i += 1

    def _try_zstd(self, results: list[DecompressedBlob], seen: set[int]) -> None:
        i = 0
        while True:
            i = self._mm.find(_ZSTD_MAGIC, i)
            if i == -1:
                break
            self._attempt(i, self._zstd_decompress, "zstd", results, seen)
            i += 1

    def _lzss_attempt(self, offset: int) -> tuple[bytes, int] | None:
        src = self._slice(offset)
        dst_len_guess = max((self._size - offset) * 20, 1024 * 1024)
        try:
            out = lzss_decompress(src, dst_len_guess)
        except (ValueError, IndexError):
            return None
        if len(out) < _MIN_BLOB:
            return None
        return out, self._size - offset

    def _try_lzss(self, results: list[DecompressedBlob], seen: set[int]) -> None:
        marker_pos = self._mm.find(_MARKER)
        if marker_pos == -1:
            return
        end = min(self._size, marker_pos + 512 * 1024)
        for offset in range(end):
            if offset in seen:
                continue
            result = self._lzss_attempt(offset)
            if result is not None:
                out, consumed = result
                if _is_plausible_lzss(out) and offset not in seen:
                    seen.add(offset)
                    results.append(DecompressedBlob("lzss", offset, consumed, out))

    # ---- str_length_index[] search ----

    def _find_lengths_for_blob(self, blob: DecompressedBlob) -> list[int] | None:
        target = len(blob.plaintext)
        if target <= 0:
            return None
        blob_end = blob.file_offset + blob.compressed_size
        scan_end = min(self._size, blob_end + _INDEX_SEARCH_WINDOW)
        # Two windows: everything before the blob, then up to 12 KB after it.
        # The blob itself is excluded — the index array cannot be inside it.
        runs = _collect_runs(self._mm, 0, blob.file_offset) + _collect_runs(
            self._mm, blob_end, scan_end
        )
        return _match_lengths(runs, target)

    # ---- main entry point ----

    def find_blobs(self) -> list[DecompressedBlob]:
        results: list[DecompressedBlob] = []
        seen: set[int] = set()
        self._try_zlib(results, seen)
        self._try_bz2(results, seen)
        self._try_zstd(results, seen)
        if not results:
            self._try_lzss(results, seen)
        for blob in results:
            try:
                lengths = self._find_lengths_for_blob(blob)
                if lengths:
                    blob.strings = _split_blob(blob.plaintext, lengths)
            except Exception:
                pass  # splitting is best-effort; blob.strings remains None
        return results

    def __enter__(self) -> "_FileScanner":
        return self

    def __exit__(self, *_) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_cython_compressed(path: str, *, max_size: int = 64 * 1024 * 1024) -> bool:
    """Return True if the file contains the CYTHON_COMPRESS_STRINGS marker."""
    if os.path.getsize(path) > max_size:
        return False
    with _FileScanner(path) as s:
        return s.is_compressed()


def decompress_string_table(path: str) -> list[DecompressedBlob]:
    """
    Scan the binary for compressed Cython string blobs and decompress them.

    Tries zlib, bz2, zstd, and LZSS in that order.  Usually returns one blob.
    blob.strings is populated with individual strings when str_length_index[]
    can be located in the binary; it remains None otherwise (best-effort).
    """
    with _FileScanner(path) as s:
        return s.find_blobs()
