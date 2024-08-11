import logging
from typing import Generator, Iterable

import bs4


class ListingParser:
    def __init__(self, listing, extract_dirs: bool = True, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger(__name__)
        self._extract_dirs = extract_dirs
        try:
            self._listing = bs4.BeautifulSoup(listing, "lxml")
        except Exception as e:
            # Treat incorrect files as not listings
            self.logger.debug(f"Failed to parse listing: {e}")
            self._listing = None

    def _filter_paths(self, paths: Iterable[str]) -> Generator[str, None, None]:
        for path in paths:
            path = path.strip()
            if path.strip() in [".", "..", "/", "/.", "./"]:
                continue
            if any(path.startswith(p) for p in ["..", "/..", "#", "/#", "?", "/?"]):
                continue
            if "://" in path:
                # TODO: better filtering?
                continue
            if path.endswith("/") and not self._extract_dirs:
                continue
            yield path

    def parse(self) -> list[str]:
        if not self._listing:
            return []

        try:
            paths = set()

            if self._listing.find("table"):
                paths.update(list(self.table_extractor()))

            if self._listing.find("pre"):
                paths.update(list(self.pre_extractor()))

            # This is very generic catch, so try only when no other extractors worked
            if self._listing.find("ul"):
                paths.update(list(self.ul_extractor()))

            return list(self._filter_paths(paths))
        except Exception as e:
            # Treat incorrect files as not listings
            self.logger.debug(f"Failed to parse listing: {e}")
            return None

    def table_extractor(self):
        for table in self._listing.find_all("table"):
            for row in table.find_all("tr"):
                for cell in row.find_all("td"):
                    for href in cell.findChildren("a", recursive=False):
                        yield href.get("href")

    def pre_extractor(self):
        for pre in self._listing.find_all("pre"):
            for href in pre.find_all("a"):
                yield href.get("href")

    def ul_extractor(self):
        for ul in self._listing.find_all("ul"):
            for li in ul.find_all("li"):
                for href in li.findChildren("a", recursive=False):
                    path = href.get("href")
                    name = href.get_text().strip()
                    if name == path.strip():
                        yield path
