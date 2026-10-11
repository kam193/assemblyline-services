"""TestHelper golden-file regression.

Add a sample: put the plain file in tests/data/<name>.data, mkdir tests/results/<sha256>_<lsp|cli>/
with a params.json, then `make gentests`.
"""

import pytest

from tests.al import build_test_helper

th = build_test_helper()


def _cases():
    found = th.result_list()
    return found or [pytest.param("<none>", marks=pytest.mark.skip(reason="no results/ dirs yet"))]


@pytest.mark.parametrize("sample", _cases())
def test_sample(sample):
    th.run_test_comparison(sample, test_extra=True)
