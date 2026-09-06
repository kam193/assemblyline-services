"""Regenerate golden results. `make gentests` (tox) or `make docker-gentests`.
Create tests/results/<sha256>[_variant]/ dirs before running — never mkdir'd here.
"""

import os
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
os.environ.setdefault("SERVICE_MANIFEST_PATH", str(_ROOT / "service_manifest.yml"))
sys.path.insert(0, str(_ROOT))

from assemblyline.common.importing import load_module_by_path  # noqa: E402
from assemblyline_service_utilities.testing.helper import TestHelper  # noqa: E402

th = TestHelper(
    load_module_by_path("service.al_run.AssemblylineService", str(_ROOT)),
    str(_ROOT / "tests" / "results"),
    str(_ROOT / "tests" / "samples"),
)

if __name__ == "__main__":
    th.regenerate_results(save_files=True, sample_sha256=sys.argv[1] if len(sys.argv) > 1 else "")
