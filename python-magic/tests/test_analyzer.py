import pytest
from service.package import identify_python_package
from service.package.analyzer import Analyzer

from .conftest import SAMPLE1_SDIST, SAMPLE1_WHEEL, STUBS1_SDIST, STUBS1_WHEEL


@pytest.fixture
def get_analyzer():
    def _analyzer(
        path, requirements_blocklist=None, top_package_paths=None, paths_to_ignore=None
    ) -> Analyzer:
        package_type = identify_python_package(path)
        return Analyzer(
            path,
            package_type,
            True,
            requirements_blocklist,
            top_package_paths,
            paths_to_ignore=paths_to_ignore or ["src"],
        )

    return _analyzer


@pytest.mark.parametrize("path", [SAMPLE1_SDIST, SAMPLE1_WHEEL])
def test_analyzer_get_non_package_paths(get_analyzer, open_pkg, path):
    analyzer: Analyzer = get_analyzer(path)
    assert analyzer.get_suspicious_install_paths(open_pkg(path)) == (
        ["example/__init__.py", "example/console.py"],
        [],
    )


@pytest.mark.parametrize(
    "path",
    [
        SAMPLE1_SDIST,
        SAMPLE1_WHEEL,
    ],
)
def test_analyzer_suspicious_paths_respects_ignored_paths(get_analyzer, open_pkg, path):
    analyzer: Analyzer = get_analyzer(path, paths_to_ignore=["example"])
    assert analyzer.get_suspicious_install_paths(open_pkg(path)) == (
        [],
        [],
    )


@pytest.mark.parametrize("path", [SAMPLE1_SDIST, SAMPLE1_WHEEL])
def test_analyzer_get_overwrite_top_package_paths(get_analyzer, open_pkg, path):
    analyzer: Analyzer = get_analyzer(
        path,
        top_package_paths={
            "example": {"packages": set(["veryimportantpackage"]), "max_popularity": 100}
        },
    )
    assert analyzer.get_suspicious_install_paths(open_pkg(path)) == (
        ["example/__init__.py", "example/console.py"],
        [
            (
                "example/__init__.py",
                {"packages": set(["veryimportantpackage"]), "max_popularity": 100},
            ),
            (
                "example/console.py",
                {"packages": set(["veryimportantpackage"]), "max_popularity": 100},
            ),
        ],
    )


@pytest.mark.parametrize("path", [SAMPLE1_SDIST, SAMPLE1_WHEEL])
def test_analyzer_no_overwrite_top_package_paths_when_package_matches_wheel(
    get_analyzer, open_pkg, path
):
    analyzer: Analyzer = get_analyzer(
        path,
        top_package_paths={"example": {"packages": set(["examplepkg"]), "max_popularity": 100}},
    )
    assert analyzer.get_suspicious_install_paths(open_pkg(path)) == (
        ["example/__init__.py", "example/console.py"],
        [],
    )


@pytest.mark.parametrize("path", [STUBS1_SDIST, STUBS1_WHEEL])
def test_analyzer_ignore_overwriting_paths_stubs(get_analyzer, open_pkg, path):
    analyzer: Analyzer = get_analyzer(
        path,
        top_package_paths={
            "example": {"packages": set(["veryimportantpackage"]), "max_popularity": 100}
        },
    )
    assert analyzer.get_suspicious_install_paths(open_pkg(path)) == (
        ["example/__init__.pyi", "example/console.pyi"],
        [],
    )
