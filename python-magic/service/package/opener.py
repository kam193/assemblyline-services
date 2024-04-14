import abc
import configparser
import tarfile
import zipfile
from functools import lru_cache
from itertools import chain

from pkginfo import Distribution

# TODO: Refactor!


class CaseSensitiveConfigParser(configparser.ConfigParser):
    optionxform = staticmethod(str)


class AnyDistribution(Distribution):
    def __init__(self, opener: "PackageOpener") -> None:
        self.__opener = opener

    @lru_cache(maxsize=1)
    def read(self):
        return self.__opener.get_distribution_file(
            "METADATA"
        ) or self.__opener.get_distribution_file("PKG-INFO")


class PackageOpener(abc.ABC):
    @abc.abstractmethod
    def _load(self, package_file: str):
        pass

    def __init__(self, package_file: str = None, package_type: str = "any"):
        if package_file:
            self._load(package_file)
        self._package_type = package_type
        self.distribution = AnyDistribution(self)
        if package_file:
            self.distribution.extractMetadata()

    @property
    def package_type(self):
        return self._package_type

    @abc.abstractmethod
    def _close(self):
        pass

    @abc.abstractmethod
    def get_file(self, file_name: str, max_size=-1):
        pass

    @abc.abstractmethod
    def get_file_names(self):
        pass

    def get_file_relative(self, file_name: str):
        for name in self.get_file_names():
            if name.endswith(file_name):
                return self.get_file(name)
        return None

    @lru_cache(maxsize=1)
    def get_distribution_files(self):
        files = []
        for name in self.get_file_names():
            parts = name.split("/")
            if (
                len(parts) >= 2
                and "site-packages" not in parts
                and "." in parts[0]
                and parts[-2].split(".")[-1] in ("dist-info", "egg-info")
            ):
                files.append(name)
        files = sorted(files, key=lambda x: x.count("/"))
        return files

    def get_distribution_file(self, file_name: str):
        for name in self.get_distribution_files():
            if name.endswith(file_name):
                return self.get_file(name)
        return None

    def get_package_name(self) -> str:
        return self.distribution.name

    def get_console_scripts(self):
        if entry_points := self.get_distribution_file("entry_points.txt"):
            parser = CaseSensitiveConfigParser()
            parser.read_string(entry_points)
            return (k for k, _ in parser.items("console_scripts"))
        return None

    def get_requirements(self):
        required = set()
        for req in chain(self.distribution.requires, self.distribution.requires_dist):
            if any(op in req for op in ("<", ">", "=", " ")):
                for op in ("<", ">", "!", "~", "=", " "):
                    req = req.split(op, 1)[0]
            required.add(req.strip())
        return required

    def get_top_level_modules(self):
        if top_level := self.get_distribution_file("top_level.txt"):
            return (module.replace("-", "_") for module in filter(None, top_level.splitlines()))

    @abc.abstractmethod
    def get_file_size(self, name):
        pass

    @abc.abstractmethod
    def get_file_lines(self, name):
        pass

    def __enter__(self, package_file: str = None):
        if package_file:
            self._load(package_file)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._close()


class ZipPackageOpener(PackageOpener):
    def _load(self, package_file: str):
        self._zipf = zipfile.ZipFile(package_file, "r")

    def _close(self):
        self._zipf.close()

    def get_file(self, file_name: str, max_size=-1):
        try:
            with self._zipf.open(file_name) as f:
                return f.read(max_size).decode("utf-8")
        except KeyError:
            return None

    def get_file_names(self):
        return self._zipf.namelist()

    def get_file_size(self, name):
        return self._zipf.getinfo(name).file_size

    def get_file_lines(self, name):
        with self._zipf.open(name) as f:
            for line in f:
                yield line.decode("utf-8")


class TarPackageOpener(PackageOpener):
    def _load(self, package_file: str):
        self._tar = tarfile.open(package_file, "r:*")

    def _close(self):
        self._tar.close()

    def get_file(self, file_name: str, max_size=-1):
        try:
            with self._tar.extractfile(file_name) as f:
                return f.read(max_size).decode("utf-8")
        except KeyError:
            return None

    def get_file_names(self):
        return self._tar.getnames()

    def get_file_size(self, name):
        return self._tar.getmember(name).size

    def get_file_lines(self, name):
        with self._tar.extractfile(name) as f:
            for line in f:
                yield line.decode("utf-8")


OPENER_MAP: dict[str, PackageOpener] = {
    "sdist": TarPackageOpener,
    "sdist_zip": ZipPackageOpener,
    "bdist_wheel": ZipPackageOpener,
    "bdist_egg": ZipPackageOpener,
}
