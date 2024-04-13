import tarfile
import zipfile

_PACKAGE_INDICATORS = ("setup.py", "setup.cfg", "pyproject.toml", "PKG-INFO")


def identify_python_package(path: str):
    """Identify the type of Python package from the given path.

    Currently supported: sdist (tar, zip), bdist_wheel, bdist_egg

    TODO: Support more package types, see: https://docs.python.org/3/distutils/builtdist.html
    """
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as tar:
            for member in tar.getmembers():
                if any(member.name.endswith(name) for name in _PACKAGE_INDICATORS):
                    return "sdist"
        return None
    elif zipfile.is_zipfile(path):
        is_package = False
        with zipfile.ZipFile(path) as zip:
            for name in zip.namelist():
                if name.endswith("WHEEL"):
                    return "bdist_wheel"
                elif "EGG-INFO" in name:
                    return "bdist_egg"
                elif any(name.endswith(indicator) for indicator in _PACKAGE_INDICATORS):
                    is_package = True
        return "sdist_zip" if is_package else None

    return None
