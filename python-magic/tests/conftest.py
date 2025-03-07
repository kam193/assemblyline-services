import pytest
from service.package import identify_python_package
from service.package.opener import OPENER_MAP, PackageOpener


@pytest.fixture
def open_pkg():
    def _open_pkg(path) -> PackageOpener:
        pkg_type = identify_python_package(path)
        opener: PackageOpener = OPENER_MAP[pkg_type](path)
        return opener

    return _open_pkg


SAMPLE1_SDIST = "tests/samples/examplepkg-2.0.0.tar.gz"
SAMPLE1_WHEEL = "tests/samples/examplepkg-2.0.0-py3-none-any.whl"
