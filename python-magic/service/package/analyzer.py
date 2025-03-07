import re

from assemblyline_v4_service.common.result import ResultTextSection

from .opener import OPENER_MAP, PackageOpener

HEURISTICS_MAP = {
    "malicious": 1,
    "suspicious": 2,
}
PATHS_TO_IGNORE = set(
    [
        "tests",
        "docs",
        "examples",
        "test",
        "data",
        "scripts",
        "example",
        "license",
        "licence",
        "include",
        "authors",
        "doc",
        "bin",
        "etc",
        "src",
    ]
)

_separator_replace = re.compile(r"([._-])+")
_cleanup_replace = re.compile(r"([^a-z0-9-])")
_cleanup_extras = re.compile(r"\[[a-zA-Z0-9-]*\]")


class Analyzer:
    def __init__(
        self,
        path: str,
        package_type: str,
        requirements_blocklist: dict[str, set[str]] = None,
        top_package_paths: dict[str, set[str]] = None,
        paths_to_ignore: list[str] = None,
    ):
        self.path = path
        self.package_type = package_type
        self.requirements_blocklist = requirements_blocklist or {
            "malicious": set(),
            "suspicious": set(),
        }
        self.top_package_paths = top_package_paths or {}
        self.paths_to_ignore = paths_to_ignore or PATHS_TO_IGNORE

    @staticmethod
    def _normalize_pypi_name(name):
        name = _separator_replace.sub("-", name)
        name = name.lower().strip()
        name = _cleanup_extras.sub("", name)
        return _cleanup_replace.sub("", name)

    def analyze(self):
        section = ResultTextSection("Python package analysis")
        with OPENER_MAP[self.package_type](self.path) as opener:
            opener: PackageOpener
            section.add_line(f"Package type: {self.package_type.upper()}")
            section.add_line(f"Package name: {opener.distribution.name}")
            section.add_line(f"Package version: {opener.distribution.version}")
            section.add_line(f"Package author: {opener.distribution.author}")
            section.add_line(f"Package author email: {opener.distribution.author_email}")

            requirements = opener.get_requirements()
            if requirements:
                req_section = ResultTextSection("Dependencies")
                req_section.add_line("This package declares following dependencies:")
                heur_sections = {}
                for req in requirements:
                    normalized = self._normalize_pypi_name(req)
                    req_section.add_line(f"{req} ({normalized})")
                    section.add_tag("file.lib", f"pypi.{normalized}")
                    if normalized in self.requirements_blocklist["malicious"]:
                        heur_sections.setdefault("malicious", []).append(normalized)
                    elif normalized in self.requirements_blocklist["suspicious"]:
                        heur_sections.setdefault("suspicious", []).append(normalized)
                for heur_type, heur_reqs in heur_sections.items():
                    heur_section = ResultTextSection(
                        f"{heur_type.capitalize()} dependencies ({len(heur_reqs)})"
                    )
                    heur_section.set_heuristic(HEURISTICS_MAP[heur_type])
                    heur_section.add_line(
                        "Following dependencies were marked as suspicious by one or more sources:"
                    )
                    for req in heur_reqs:
                        heur_section.add_line(req)
                        heur_section.heuristic.add_signature_id(
                            f"PythonMagic.{heur_type.lower()}_dependencies.{req}"
                        )
                    req_section.add_subsection(heur_section)
                section.add_subsection(req_section)

            scripts = opener.get_console_scripts()
            if scripts:
                script_section = ResultTextSection("Console scripts", auto_collapse=True)
                script_section.add_line("This package declares following console scripts:")
                for script in scripts:
                    script_section.add_line(script)
                section.add_subsection(script_section)

            top_level_modules = opener.get_top_level_modules()
            if top_level_modules:
                module_section = ResultTextSection("Top-level modules", auto_collapse=True)
                module_section.add_line("This package declares following top-level modules:")
                for module in top_level_modules:
                    module_section.add_line(module)
                section.add_subsection(module_section)

            non_package_paths, overwrite_top_packages_paths = self.get_suspicious_install_paths(
                opener
            )
            if non_package_paths:
                paths_section = ResultTextSection("Files in untypical paths", auto_collapse=True)
                paths_section.set_heuristic(4)
                paths_section.add_line(
                    "The following paths are installed by this package and do not match the package name. "
                    "This is not necessarily a malicious activity. \n"
                )
                for path in non_package_paths:
                    paths_section.add_line(path)
                section.add_subsection(paths_section)

            if overwrite_top_packages_paths:
                overwrite_section = ResultTextSection(
                    "Overwriting popular packages paths",
                    auto_collapse=False,
                    zeroize_on_tag_safe=True,
                    zeroize_on_sig_safe=True,
                )
                overwrite_section.set_heuristic(3)
                overwrite_section.add_line(
                    "The following paths are installed by this package and placed in directories used by some "
                    "popular PyPI packages. This may indicate malicious activity by overwriting source code. \n"
                )
                conflicts = dict()
                for path, top_packages in overwrite_top_packages_paths:
                    overwrite_section.add_line(path)
                    base = path.split("/")[0]
                    if base not in conflicts:
                        conflicts[base] = top_packages
                        overwrite_section.heuristic.add_signature_id(
                            f"PythonMagic.override_popular_path.{base}"
                        )

                conflicts_section = ResultTextSection("Conflicts with...", auto_collapse=True)
                for base, top_packages in conflicts.items():
                    conflicts_section.add_line(
                        f"DIRECTORY {base} has {len(top_packages)} conflicting package(s):"
                    )
                    conflicts_section.add_line(", ".join(top_packages))
                overwrite_section.add_subsection(conflicts_section)
                section.add_subsection(overwrite_section)
            return section

    def get_suspicious_install_paths(self, opener: PackageOpener):
        overwrite_top_packages_paths = []
        non_package_paths = []
        normalized_package_name = self._normalize_pypi_name(opener.get_package_name()).lower()
        for record in opener.get_records():
            first_dir = record.split("/")[0].lower()
            if first_dir in self.paths_to_ignore:
                continue
            if first_dir.endswith(".dist-info") or first_dir.endswith(".egg-info"):
                continue
            if first_dir != normalized_package_name:
                non_package_paths.append(record)

            if first_dir in self.top_package_paths:
                if normalized_package_name not in self.top_package_paths[first_dir]:
                    overwrite_top_packages_paths.append((record, self.top_package_paths[first_dir]))

        return non_package_paths, overwrite_top_packages_paths
