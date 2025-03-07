import pytest
from service.package import identify_python_package

from .conftest import SAMPLE1_SDIST, SAMPLE1_WHEEL


@pytest.mark.parametrize(
    "path, expected",
    [
        (SAMPLE1_SDIST, "sdist"),
        (SAMPLE1_WHEEL, "bdist_wheel"),
    ],
)
def test_identify_python_package(path, expected):
    assert identify_python_package(path) == expected


@pytest.mark.parametrize(
    "path",
    [
        SAMPLE1_SDIST,
        SAMPLE1_WHEEL,
    ],
)
def test_opener_returns_requirements(open_pkg, path):
    with open_pkg(path) as pkg:
        assert pkg.get_requirements() == set(
            [
                "gunicorn[all]",
                "requests",
            ]
        )


def test_opener_get_records_sdist(open_pkg):
    with open_pkg(SAMPLE1_SDIST) as pkg:
        assert pkg.get_records() == [
            "example/__init__.py",
            "example/console.py",
            "examplepkg.egg-info/PKG-INFO",
            "examplepkg.egg-info/SOURCES.txt",
            "examplepkg.egg-info/dependency_links.txt",
            "examplepkg.egg-info/entry_points.txt",
            "examplepkg.egg-info/requires.txt",
            "examplepkg.egg-info/top_level.txt",
        ]


def test_opener_get_records_wheel(open_pkg):
    with open_pkg(SAMPLE1_WHEEL) as pkg:
        assert pkg.get_records() == [
            "example/__init__.py",
            "example/console.py",
            "examplepkg-2.0.0.dist-info/METADATA",
            "examplepkg-2.0.0.dist-info/WHEEL",
            "examplepkg-2.0.0.dist-info/entry_points.txt",
            "examplepkg-2.0.0.dist-info/top_level.txt",
            "examplepkg-2.0.0.dist-info/RECORD",
        ]
