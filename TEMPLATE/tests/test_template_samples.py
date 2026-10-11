"""TestHelper golden-file regression.

Add a sample: mkdir tests/results/<sha256>/ (optionally with params.json), put the
plain file or its <sha256>.cart in tests/samples/, then `make gentests`.
"""

import pytest

from tests.al import build_test_helper

th = build_test_helper()


def _cases():
    found = th.result_list()
    return found or [pytest.param("<none>", marks=pytest.mark.skip(reason="no results/ dirs yet"))]


@pytest.mark.sample
@pytest.mark.parametrize("sample", _cases())
def test_sample(sample):
    th.run_test_comparison(sample)
