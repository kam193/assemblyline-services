"""Regenerate golden results. `make gentests` (tox) or `make docker-gentests`.
Create tests/results/<sha256>[_variant]/ dirs before running — never mkdir'd here.
"""

import os
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
os.environ.setdefault("SERVICE_MANIFEST_PATH", str(_ROOT / "service_manifest.yml"))
sys.path.insert(0, str(_ROOT))

from tests.al import build_test_helper  # noqa: E402

th = build_test_helper()

if __name__ == "__main__":
    th.regenerate_results(save_files=True, sample_sha256=sys.argv[1] if len(sys.argv) > 1 else "")
