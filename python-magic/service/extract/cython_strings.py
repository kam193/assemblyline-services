import hashlib
import os

from assemblyline_v4_service.common.result import ResultTextSection

from ..cython import DecompressedBlob, decompress_string_table, is_cython_compressed
from . import ExtractorBase

_SECTION_TITLE = "Cython binary with compressed string table"


class CythonStringExtractor(ExtractorBase):
    def _write_blob(self, blob: DecompressedBlob) -> str:
        digest = hashlib.sha256(blob.plaintext).hexdigest()[:16]
        filename = f"{digest}.cython_strings.{blob.algorithm}.txt"
        path = os.path.join(self.unpack_dir, filename)
        os.makedirs(self.unpack_dir, exist_ok=True)
        with open(path, "wb") as f:
            f.write(blob.plaintext)
        return path

    def extract(self) -> ResultTextSection | None:
        max_size: int = self.config.get(
            "CYTHON_MAX_FILE_SIZE", 64 * 1024 * 1024)
        heuristic_score: int = int(
            self.config.get("CYTHON_HEURISTIC_SCORE", 100))

        if not is_cython_compressed(self.request.file_path, max_size=max_size):
            return None

        self.log.debug(
            "Cython compressed string table marker found in %s", self.request.file_path)

        blobs = decompress_string_table(self.request.file_path)

        section = ResultTextSection(_SECTION_TITLE)
        _SIG = "cython_compressed_string_table"
        section.set_heuristic(5, signature=_SIG)
        section.heuristic._score_map[_SIG] = heuristic_score

        if not blobs:
            section.add_line(
                "Marker CYTHON_COMPRESS_STRINGS is present but no decompressible blob was found. "
                "The binary may use an unsupported compression algorithm (e.g. zstd requires Python 3.14+) "
                "or the blob may be stripped."
            )
            return section

        extracted_count = 0
        for blob in blobs:
            if extracted_count >= self.max_extracted_config:
                break
            out_path = self._write_blob(blob)
            name = f".cython_strings.{blob.algorithm}.txt"
            self.request.add_extracted(
                out_path,
                name,
                "Decompressed Cython string table",
                safelist_interface=self.safelist_interface,
            )
            extracted_count += 1

            sub = ResultTextSection(
                f"String table ({blob.algorithm})",
                auto_collapse=True,
                parent=section,
            )
            sub.add_line(f"Algorithm : {blob.algorithm}")
            sub.add_line(
                f"Blob offset in file : {blob.file_offset} (0x{blob.file_offset:x})")
            sub.add_line(f"Compressed size     : {blob.compressed_size} bytes")
            sub.add_line(f"Decompressed size   : {len(blob.plaintext)} bytes")

        return section
