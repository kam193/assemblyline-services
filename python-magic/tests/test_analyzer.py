import pytest
from service.package import identify_python_package
from service.package.analyzer import Analyzer

from .conftest import SAMPLE1_SDIST, SAMPLE1_WHEEL


@pytest.fixture
def get_analyzer():
    def _analyzer(path, requirements_blocklist=None, top_package_paths=None) -> Analyzer:
        package_type = identify_python_package(path)
        return Analyzer(path, package_type, requirements_blocklist, top_package_paths)

    return _analyzer


@pytest.mark.parametrize("path", [SAMPLE1_SDIST, SAMPLE1_WHEEL])
def test_analyzer_get_non_package_paths(get_analyzer, open_pkg, path):
    analyzer: Analyzer = get_analyzer(path)
    assert analyzer.get_suspicious_install_paths(open_pkg(path)) == (
        ["example/__init__.py", "example/console.py"],
        [],
    )


@pytest.mark.parametrize("path", [SAMPLE1_SDIST, SAMPLE1_WHEEL])
def test_analyzer_get_overwrite_top_package_paths(get_analyzer, open_pkg, path):
    analyzer: Analyzer = get_analyzer(path, top_package_paths={"example": ["veryimportantpackage"]})
    assert analyzer.get_suspicious_install_paths(open_pkg(path)) == (
        ["example/__init__.py", "example/console.py"],
        [
            ("example/__init__.py", ["veryimportantpackage"]),
            ("example/console.py", ["veryimportantpackage"]),
        ],
    )


@pytest.mark.parametrize("path", [SAMPLE1_SDIST, SAMPLE1_WHEEL])
def test_analyzer_no_overwrite_top_package_paths_when_package_matches_wheel(
    get_analyzer, open_pkg, path
):
    analyzer: Analyzer = get_analyzer(path, top_package_paths={"example": ["examplepkg"]})
    assert analyzer.get_suspicious_install_paths(open_pkg(path)) == (
        ["example/__init__.py", "example/console.py"],
        [],
    )
