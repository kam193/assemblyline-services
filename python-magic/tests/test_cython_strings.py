"""Tests for the Cython compressed string table extractor.

Fixtures for zlib and bz2 are real Cython-compiled .so files in tests/samples/.
They are produced by tests/samples/build_cython_fixture.py from fixture_large.pyx.

The LZSS fixture is built from fixture_lzss.pyx with Cython >= 3.3. The LZSS decoder
is additionally covered by round-trip tests using a reference compressor.
"""

import os
import struct
import zlib

import pytest
from service.cython import (
    DecompressedBlob,
    decompress_string_table,
    is_cython_compressed,
    lzss_decompress,
)

_SAMPLES = os.path.join(os.path.dirname(__file__), "samples")

_FIXTURE_ZLIB = os.path.join(_SAMPLES, "cython_fixture_zlib.cpython-314-x86_64-linux-gnu.so")
_FIXTURE_BZ2 = os.path.join(_SAMPLES, "cython_fixture_bz2.cpython-314-x86_64-linux-gnu.so")
_FIXTURE_LZSS = os.path.join(_SAMPLES, "cython_fixture_lzss.cpython-314-x86_64-linux-gnu.so")

# ---------------------------------------------------------------------------
# is_cython_compressed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_path", [_FIXTURE_ZLIB, _FIXTURE_BZ2, _FIXTURE_LZSS])
def test_detects_marker(fixture_path: str):
    assert is_cython_compressed(fixture_path)


def test_no_false_positive_on_plain_elf(tmp_path):
    p = tmp_path / "plain.so"
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200)
    assert not is_cython_compressed(str(p))


def test_detects_lzss_only_marker(tmp_path):
    p = tmp_path / "lzss_only.so"
    p.write_bytes(b"\x7fELF" + b"\x00" * 64 + b"LZSS string data decompression failed\x00")
    assert is_cython_compressed(str(p))


def test_skips_oversize_file():
    assert not is_cython_compressed(_FIXTURE_ZLIB, max_size=10)


# ---------------------------------------------------------------------------
# decompress_string_table — per algorithm
# ---------------------------------------------------------------------------


def test_decompress_zlib_recovers_strings():
    blobs = decompress_string_table(_FIXTURE_ZLIB)
    assert blobs, "No blobs extracted from zlib fixture"
    assert all(b.algorithm == "zlib" for b in blobs)
    # The fixture contains known strings from fixture_large.pyx
    plaintext = blobs[0].plaintext.decode("utf-8", errors="replace")
    assert "EXAMPLE_API_KEY" in plaintext
    assert "https://api.example-internal.local" in plaintext
    assert "Invalid or expired token for client" in plaintext


def test_decompress_bz2_recovers_strings():
    blobs = decompress_string_table(_FIXTURE_BZ2)
    assert blobs, "No blobs extracted from bz2 fixture"
    assert all(b.algorithm == "bz2" for b in blobs)
    plaintext = blobs[0].plaintext.decode("utf-8", errors="replace")
    assert "EXAMPLE_API_KEY" in plaintext
    assert "https://api.example-internal.local" in plaintext


def test_zlib_and_bz2_same_plaintext():
    """Both fixtures compress the same .pyx — the recovered string tables should match."""
    zlib_blobs = decompress_string_table(_FIXTURE_ZLIB)
    bz2_blobs = decompress_string_table(_FIXTURE_BZ2)
    assert zlib_blobs and bz2_blobs
    assert zlib_blobs[0].plaintext == bz2_blobs[0].plaintext


def test_no_blobs_without_marker(tmp_path):
    plaintext = b"fetch_agent_response" * 50  # plausible-looking text
    compressed = zlib.compress(plaintext, level=9)
    p = tmp_path / "no_marker.bin"
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64 + compressed)
    # is_cython_compressed is the gate — no marker means no blobs
    assert not is_cython_compressed(str(p))


# ---------------------------------------------------------------------------
# lzss_decompress — pure unit test using synthetic data
# (LZSS binaries require Cython.LZSS which ships in Cython 3.3+)
# ---------------------------------------------------------------------------


def _lzss_compress_reference(data: bytes) -> bytes:
    """Minimal LZSS compressor matching Cython's format (for test use only)."""
    if not data:
        return b""
    input_size = len(data)
    output = bytearray(b"\x00")
    pos = 0
    flags_pos = 0
    flags = 0xFF0000

    def find_match(p: int):
        WINDOW = (1 << 14) + 0x80
        MAX_MATCH = min(258, input_size - p)
        best_len, best_offset = 0, 0
        for prev in range(max(0, p - WINDOW), p):
            length = 0
            while length < MAX_MATCH and data[prev + length] == data[p + length]:
                length += 1
            if length > best_len:
                best_len, best_offset = length, p - prev
        return best_offset, best_len

    while pos < input_size:
        offset, length = find_match(pos)
        enc_offset = offset - length
        flag = 0
        if length > 2 and 0 <= enc_offset <= 0x7F:
            output.append(enc_offset)
            output.append(length - 3)
        elif length > 2 and (length - 3) <= 0x1F and 0 <= enc_offset - 0x80 < (1 << 9):
            enc_offset -= 0x80
            output.append((enc_offset & 0x7F) | 0x80)
            output.append(((enc_offset & 0x180) >> 2) | (length - 3))
        elif length > 3 and 0 <= enc_offset - 0x80 < (1 << 14):
            enc_offset -= 0x80
            output.append(enc_offset & 0x7F | 0x80)
            output.append((enc_offset >> 7) & 0x7F | 0x80)
            output.append(length - 3)
        else:
            flag = 1
            length = 1
            output.append(data[pos])
        pos += length
        flags = (flag << 7) | (flags >> 1)
        if flags < 0x10000:
            output[flags_pos] = flags & 0xFF
            flags_pos = len(output)
            output.append(0)
            flags = 0xFF0000

    if flags_pos == len(output) - 1:
        output.pop()
    else:
        while flags >= 0x10000:
            flags >>= 1
        output[flags_pos] = flags & 0xFF

    return bytes(output)


_LZSS_PLAINTEXT = (
    b"fetch_agent_responseinitialize_client_sessionvalidate_token_expiry"
    b"rotate_api_credentialsdispatch_async_task"
    b"https://api.example-internal.local/v2/agents/status"
    b"https://api.example-internal.local/v2/tasks/submit"
    b"AgentNetworkErrorTokenValidationErrorClientSessionExpired"
    b"Missing required environment variable: EXAMPLE_API_KEY"
    b"Connection timed out after %d secondsRetry attempt %d of %d for task %s"
    b"Task completed successfully with result: %s"
    b"Optional[str]Optional[Any]Tuple[str, str]AsyncAgentClientSyncAgentClient"
)


def _plaintext_with_gap(gap: int) -> bytes:
    marker = b"repeated-marker-0123456789"
    filler = bytes((i * 7 + 3) % 61 + 33 for i in range(gap))
    return marker + filler + marker


@pytest.mark.parametrize(
    "plaintext",
    [
        _LZSS_PLAINTEXT,
        _plaintext_with_gap(10),
        _plaintext_with_gap(200),
        _plaintext_with_gap(1500),
        _plaintext_with_gap(9000),
    ],
    ids=["text", "short-offset", "9-bit-offset", "14-bit-offset", "far-offset"],
)
def test_lzss_roundtrip(plaintext: bytes):
    compressed = _lzss_compress_reference(plaintext)
    assert lzss_decompress(compressed, len(plaintext)) == plaintext


def test_lzss_rejects_invalid_backreference():
    with pytest.raises(ValueError):
        lzss_decompress(b"\x00\x05\x00", 64)


# ---------------------------------------------------------------------------
# DecompressedBlob fields
# ---------------------------------------------------------------------------


def test_blob_fields_populated():
    blobs = decompress_string_table(_FIXTURE_ZLIB)
    assert blobs
    b = blobs[0]
    assert isinstance(b, DecompressedBlob)
    assert b.algorithm == "zlib"
    assert b.file_offset > 0
    assert b.compressed_size > 0
    assert len(b.plaintext) > 0


# ---------------------------------------------------------------------------
# blob.strings splitting
# ---------------------------------------------------------------------------


def test_strings_split_from_zlib_fixture():
    """decompress_string_table should populate blob.strings for the zlib fixture."""
    blobs = decompress_string_table(_FIXTURE_ZLIB)
    assert blobs
    blob = blobs[0]
    assert blob.strings is not None, "str_length_index[] not found in zlib fixture"
    # sum of lengths must equal the decompressed blob size
    assert sum(len(s) for s in blob.strings) == len(blob.plaintext)
    # known strings must appear individually, not merged across lines
    texts = [s.decode("utf-8", errors="replace") for s in blob.strings]
    assert any("EXAMPLE_API_KEY" in t for t in texts)
    assert any("https://api.example-internal.local" in t for t in texts)


# ---------------------------------------------------------------------------
# LZSS fixture (Cython 3.3 default compression)
# ---------------------------------------------------------------------------


class TestLzssFixture:
    def test_single_lzss_blob_with_split_strings(self):
        blobs = decompress_string_table(_FIXTURE_LZSS)
        assert [b.algorithm for b in blobs] == ["lzss"]
        blob = blobs[0]
        assert blob.strings is not None
        assert sum(len(s) for s in blob.strings) == len(blob.plaintext)

    @pytest.mark.parametrize(
        "expected",
        [
            "kilo echo mike fixture message 0 for endpoint %s / ünïcode-0".encode(),
            b"https://fixture-host-0.example.invalid/api/v0/",
            b"/opt/fixture/",
            b"handler_29 requires a value",
        ],
    )
    def test_known_strings_recovered(self, expected: bytes):
        blob = decompress_string_table(_FIXTURE_LZSS)[0]
        assert expected in blob.plaintext

    def test_string_constants_split_individually(self):
        blob = decompress_string_table(_FIXTURE_LZSS)[0]
        strings = [s.decode("utf-8") for s in blob.strings]
        assert any(s.startswith("https://fixture-host-") for s in strings)
        assert any(s.startswith("handler_29 requires") for s in strings)


class TestLzssIndexLayout:
    _STRINGS = [f"synthetic string number {i} with some padding text".encode() for i in range(40)]
    _BYTES = [bytes((i * 37 + j * 11) % 256 for j in range(24)) for i in range(12)]

    def _build(self, tmp_path, str_gap: bool = True):
        plaintext = b"".join(self._STRINGS + self._BYTES)
        compressed = _lzss_compress_reference(plaintext)
        str_index = struct.pack(f"<{len(self._STRINGS)}I", *map(len, self._STRINGS))
        bytes_index = struct.pack(f"<{len(self._BYTES)}I", *map(len, self._BYTES))
        gap = b"\x00" * 4 if str_gap else b""
        data = (
            b"\x7fELF"
            + b"\x00" * 60
            + str_index
            + gap
            + bytes_index
            + b"\x00" * 40
            + compressed
            + b"\x00" * 8
            + b"LZSS string data decompression failed\x00"
            + b"\x00" * 64
        )
        path = tmp_path / "synthetic.so"
        path.write_bytes(data)
        return str(path), plaintext, len(compressed)

    @pytest.mark.parametrize("str_gap", [True, False])
    def test_str_and_bytes_arrays_are_paired(self, tmp_path, str_gap):
        path, plaintext, compressed_size = self._build(tmp_path, str_gap)
        (blob,) = decompress_string_table(path)
        assert blob.algorithm == "lzss"
        assert blob.plaintext == plaintext
        assert blob.compressed_size == compressed_size
        assert blob.strings == self._STRINGS + self._BYTES
