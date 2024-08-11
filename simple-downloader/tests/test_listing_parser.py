import pytest
from service.listing_parser import ListingParser


@pytest.fixture
def listing():
    def _listing(name: str):
        with open(f"tests/examples/{name}.html", "r") as f:
            return f.read()

    return _listing


@pytest.mark.parametrize(
    "name, expected",
    [
        ("apache", 12),
        ("nginx", 1434),
        ("vlc", 156),
        ("cern", 3826),
        ("five-sh", 52),
        ("maven", 27),
        ("ul", 7),
    ],
)
def test_parse(listing, name, expected):
    parser = ListingParser(listing(name))
    assert len(parser.parse()) == expected


@pytest.mark.parametrize(
    "data",
    [
        b"aaaa",
        b"<html></html>",
        "this is not htmląęþ".encode("utf-8"),
        "<html><body><a href='https://example.com/a'>not a listing</a></body></html>",
        "<html><body><table><tr><td><a href='https://example.com/a'>not a listing</a></td></tr></table></body></html>",
    ],
)
def test_parse_incorrect(data):
    parser = ListingParser(data)
    assert parser.parse() == []


def test_parse_wikipedia(listing):
    parser = ListingParser(listing("wikipedia"))
    assert parser.parse() == []


def test_skip_directories(listing):
    parser = ListingParser(listing("maven"), extract_dirs=False)
    extracted = parser.parse()
    assert len(extracted) == 2
    assert "KEYS" in extracted
    assert "KEYS.bak" in extracted
