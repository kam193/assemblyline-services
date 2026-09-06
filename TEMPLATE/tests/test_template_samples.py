"""TestHelper golden-file regression.

Add a sample: mkdir tests/results/<sha256>/ (optionally with params.json), put
tests/samples/<sha256>.cart in place, then `make gentests`.
"""

import pathlib

import pytest
from assemblyline.common.importing import load_module_by_path
from assemblyline_service_utilities.testing.helper import TestHelper

_ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = str(_ROOT / "tests" / "results")
SAMPLES = str(_ROOT / "tests" / "samples")

th = TestHelper(
    load_module_by_path("service.al_run.AssemblylineService", str(_ROOT)), RESULTS, SAMPLES
)


def _cases():
    found = th.result_list()
    return found or [pytest.param("<none>", marks=pytest.mark.skip(reason="no results/ dirs yet"))]


@pytest.mark.sample
@pytest.mark.parametrize("sample", _cases())
def test_sample(sample):
    th.run_test_comparison(sample)
