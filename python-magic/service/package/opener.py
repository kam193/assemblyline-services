import abc
import configparser
import inspect
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

    def _retrieve_top_module_from_path(self, path):
        if "/site-packages/" in path:
            return None

        extension = path.split(".")[-1]
        # Do we need all of them? How about native extensions? Can so/dll be a module?
        if extension not in (
            "py",
            "pyc",
            "pyo",
            "pyd",
            "so",
            "dll",
            "dylib",
            "cpp",
            "c",
        ):
            return None

        possible_module = None
        top, *rest = path.split("/")
        # special case like "pkg-1.0.0./pkg/__init__.py"
        if any(digit in top for digit in "0123456789"):
            top, *rest = rest
        # special case like "pkg-1.0.0./src/pkg/__init__.py"
        # FIXME: this can potentially hide packages exposing module "src"
        if top == "src":
            top, *rest = rest

        if rest:
            possible_module = top
        elif name := inspect.getmodulename(path):
            possible_module = name
        else:
            possible_module = path

        if "." not in possible_module:
            return possible_module.replace("-", "_") or None
        return None

    def get_top_level_modules(self):
        if top_level := self.get_distribution_file("top_level.txt"):
            return (module.replace("-", "_") for module in filter(None, top_level.splitlines()))

        paths = None
        # No declaration, retrieve based on record files
        if record := self.get_distribution_file("RECORD"):
            paths = (line.split(",", 1)[0] for line in record.splitlines())
        elif installed_files := self.get_distribution_file("installed-files.txt"):
            paths = installed_files.splitlines()
        elif sources := self.get_distribution_file("SOURCES.txt"):
            paths = sources.splitlines()

        # last resort, use all files
        if paths is None:
            paths = [path for path in self.get_file_names() if "site-packages" not in path]
        return set(
            filter(
                None,
                map(
                    self._retrieve_top_module_from_path,
                    paths,
                ),
            )
        )

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

