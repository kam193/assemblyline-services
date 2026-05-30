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
import zlib
from dataclasses import dataclass

# Marker present in every CYTHON_COMPRESS_STRINGS binary (part of the error template
# "String compression was configured with the C macro 'CYTHON_COMPRESS_STRINGS=%d'").
_MARKER = b"CYTHON_COMPRESS_STRINGS"

# Minimum decompressed size to consider a blob plausible.
_MIN_BLOB = 64
# Minimum fraction of printable ASCII bytes used ONLY for the LZSS brute-force scan
# (where there are no magic bytes to gate on). Real Cython string tables can have
# as low as ~50% printable bytes when the module stores binary bytes-constants.
# Random bytes average ~37% printable, so 50% safely distinguishes text blobs.
_LZSS_MIN_PRINTABLE_RATIO = 0.50


@dataclass
class DecompressedBlob:
    algorithm: str
    file_offset: int
    compressed_size: int
    plaintext: bytes


def is_cython_compressed(path: str, *, max_size: int = 64 * 1024 * 1024) -> bool:
    """Return True if the file contains the CYTHON_COMPRESS_STRINGS marker."""
    if os.path.getsize(path) > max_size:
        return False
    with open(path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            return mm.find(_MARKER) != -1
        finally:
            mm.close()


# ---------------------------------------------------------------------------
# zlib
# ---------------------------------------------------------------------------

_ZLIB_SECOND_BYTES = {0x01, 0x9C, 0xDA, 0x5E}


def _zlib_decompress(data: bytes, offset: int) -> tuple[bytes, int] | None:
    try:
        obj = zlib.decompressobj()
        out = obj.decompress(data[offset:])
        consumed = len(data) - offset - len(obj.unused_data)
        return out, consumed
    except zlib.error:
        return None


# ---------------------------------------------------------------------------
# Generic helper
# ---------------------------------------------------------------------------


def _attempt(
    data: bytes,
    offset: int,
    decompress_fn,
    algo: str,
    results: list,
    seen: set,
) -> None:
    if offset in seen:
        return
    result = decompress_fn(data, offset)
    if result is None:
        return
    out, consumed = result
    if consumed is None:
        consumed = 0
    if len(out) < _MIN_BLOB:
        return
    seen.add(offset)
    results.append(DecompressedBlob(algo, offset, consumed, out))


def _try_zlib(data: bytes, results: list, seen: set) -> None:
    i = 0
    while True:
        i = data.find(b"\x78", i)
        if i == -1:
            break
        if i + 1 < len(data) and data[i + 1] in _ZLIB_SECOND_BYTES:
            _attempt(data, i, _zlib_decompress, "zlib", results, seen)
        i += 1


def _bz2_decompress(data: bytes, offset: int) -> tuple[bytes, int] | None:
    try:
        obj = bz2.BZ2Decompressor()
        out = obj.decompress(data[offset:])
        return out, len(data) - offset - len(obj.unused_data)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# bz2
# ---------------------------------------------------------------------------


def _try_bz2(data: bytes, results: list, seen: set) -> None:
    i = 0
    while True:
        i = data.find(b"BZh", i)
        if i == -1:
            break
        if i + 3 < len(data) and 0x31 <= data[i + 3] <= 0x39:  # '1'..'9'
            _attempt(data, i, _bz2_decompress, "bz2", results, seen)
        i += 1


def _zstd_decompress(data: bytes, offset: int) -> tuple[bytes, int] | None:
    try:
        from compression.zstd import decompress  # type: ignore[import]

        out = decompress(data[offset:])
        return out, None  # consumed size unknown; that's fine
    except (ImportError, Exception):
        return None


# ---------------------------------------------------------------------------
# zstd (Python 3.14+ stdlib, optional)
# ---------------------------------------------------------------------------


def _try_zstd(data: bytes, results: list, seen: set) -> None:
    _ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
    i = 0
    while True:
        i = data.find(_ZSTD_MAGIC, i)
        if i == -1:
            break
        _attempt(data, i, _zstd_decompress, "zstd", results, seen)
        i += 1


class _LZSSEnd(Exception):
    pass


def lzss_decompress(src: bytes, dst_len: int) -> bytes:
    """
    Decompress a Cython LZSS-compressed blob when the expected output size is known.

    This is a direct port of `__pyx_lzss_decompress` from Cython/Utility/StringTools.c.
    The decompressor requires `dst_len` because the LZSS format is not self-terminating.
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


def _lzss_attempt(data: bytes, offset: int) -> tuple[bytes, int] | None:
    """
    Try LZSS-decompressing from `offset` without knowing dst_len.

    We use a large upper bound and let the decoder stop on src overread.
    The LZSS format is not self-terminating, so the result may include a few
    extra garbage bytes from the flag-byte padding; these are harmless since
    we only emit the blob if it passes the printability check.
    """
    src = data[offset:]
    # Use an upper bound large enough to not truncate a real string table.
    dst_len_guess = max(len(src) * 20, 1024 * 1024)
    try:
        out = lzss_decompress(src, dst_len_guess)
    except (ValueError, IndexError):
        return None
    if len(out) < _MIN_BLOB:
        return None
    consumed = len(src)  # we consumed all of src before hitting the bound
    return out, consumed


def _is_plausible_lzss(data: bytes) -> bool:
    """Return True if data looks like a Cython string table (for LZSS brute-force only)."""
    if len(data) < _MIN_BLOB:
        return False
    printable = sum(1 for b in data if 0x09 <= b <= 0x0D or 0x20 <= b <= 0x7E)
    return printable / len(data) >= _LZSS_MIN_PRINTABLE_RATIO


# ---------------------------------------------------------------------------
# LZSS (Cython's own format, algo 90, the default)
# No magic — brute-force scan near the CYTHON_COMPRESS_STRINGS marker.
# Reference: Cython/Utility/StringTools.c  __pyx_lzss_decompress
#            Cython/LZSS.py                lzss_compress
# ---------------------------------------------------------------------------


def _try_lzss(data: bytes, results: list, seen: set) -> None:
    marker_pos = data.find(_MARKER)
    if marker_pos == -1:
        return

    # The compressed blob lives in .rodata, near the marker. Scan a generous
    # window around it (from start of file to 512 KB past the marker).
    start = 0
    end = min(len(data), marker_pos + 512 * 1024)

    for offset in range(start, end):
        if offset in seen:
            continue
        result = _lzss_attempt(data, offset)
        if result is not None:
            out, consumed = result
            if _is_plausible_lzss(out) and offset not in seen:
                seen.add(offset)
                results.append(DecompressedBlob("lzss", offset, consumed, out))


def decompress_string_table(path: str) -> list[DecompressedBlob]:
    """
    Scan the binary for compressed Cython string blobs and decompress them.

    Tries zlib, bz2, zstd, and LZSS (in that order of magic-byte discoverability).
    Returns all successfully-decompressed blobs that look like plaintext.
    Usually one blob per file.
    """
    with open(path, "rb") as f:
        data = f.read()

    results: list[DecompressedBlob] = []
    seen_offsets: set[int] = set()

    _try_zlib(data, results, seen_offsets)
    _try_bz2(data, results, seen_offsets)
    _try_zstd(data, results, seen_offsets)

    if not results:
        _try_lzss(data, results, seen_offsets)

    return results
