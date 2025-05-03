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
        check_conflicting_paths: bool = True,
        requirements_blocklist: dict[str, set[str]] = None,
        top_package_paths: dict[str, dict[str, set[str] | int]] = None,
        paths_to_ignore: list[str] = None,
        min_popularity_to_warn: int = 100000,
    ):
        self.path = path
        self.package_type = package_type
        self.requirements_blocklist = requirements_blocklist or {
            "malicious": set(),
            "suspicious": set(),
        }
        self.top_package_paths = top_package_paths or {}
        self.paths_to_ignore = paths_to_ignore or PATHS_TO_IGNORE
        self.min_popularity_to_warn = min_popularity_to_warn
        self.check_conflicting_paths = check_conflicting_paths

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

            non_package_paths = overwrite_paths = None
            if self.check_conflicting_paths:
                non_package_paths, overwrite_paths = self.get_suspicious_install_paths(opener)

            if non_package_paths:
                paths_section = ResultTextSection("Files in untypical paths", auto_collapse=True)
                paths_section.add_line(
                    "The following paths are installed by this package and do not match the package name. "
                    "This is not necessarily a malicious activity. \n"
                )
                for path in non_package_paths:
                    paths_section.add_line(path)
                section.add_subsection(paths_section)

            if overwrite_paths:
                overwrite_section = ResultTextSection(
                    "Conflict with other package paths",
                    auto_collapse=False,
                    zeroize_on_tag_safe=True,
                    zeroize_on_sig_safe=True,
                )
                overwrite_section.add_line(
                    "The following directories are installed by this package and may conflict with directories "
                    "used by some other PyPI packages. This may indicate malicious activity by overwriting source"
                    " code. This heuristic is prone to false positives especially by source packages, where finding"
                    " determined paths may be incorrect.\n"
                )
                conflicts = dict()
                heuristic_id = 3  # overwrite any analysed package

                detailed_paths_section = ResultTextSection(
                    "Paths in conflicting directories", auto_collapse=True
                )
                overwrite_section.add_subsection(detailed_paths_section)

                signatures = set()
                for path, data in overwrite_paths:
                    detailed_paths_section.add_line(path)
                    base = path.split("/")[0]
                    if base not in conflicts:
                        overwrite_section.add_line(base)
                        conflicts[base] = data.get("packages", set())
                        if data.get("max_popularity", 0) >= self.min_popularity_to_warn:
                            heuristic_id = 4
                        # Add to safelist to allow this one package to use this path without warnings
                        signatures.add(
                            f"PythonMagic.override_popular_path.{base}.{self._normalize_pypi_name(opener.get_package_name())}"
                        )

                overwrite_section.set_heuristic(heuristic_id)
                for sig in signatures:
                    overwrite_section.heuristic.add_signature_id(sig)

                conflicts_section = ResultTextSection("Conflicts with...", auto_collapse=True)
                for base, data in conflicts.items():
                    conflicts_section.add_line(
                        f"DIRECTORY {base} has {len(data)} conflicting package(s):"
                    )
                    conflicts_section.add_line(", ".join(list(data)[:10]))
                    if len(data) > 10:
                        conflicts_section.add_line(f"... and {len(data) - 10} more")

                overwrite_section.add_subsection(conflicts_section)
                section.add_subsection(overwrite_section)
            return section

    def get_suspicious_install_paths(self, opener: PackageOpener):
        overwrite_paths: list[tuple[str, dict]] = []
        non_package_paths = []
        normalized_package_name = self._normalize_pypi_name(opener.get_package_name()).lower()
        expected_dir = normalized_package_name.replace("-", "_")
        for record in opener.get_records():
            first_dir = record.split("/")[0].lower()
            if first_dir in self.paths_to_ignore:
                continue
            if first_dir.endswith(".dist-info") or first_dir.endswith(".egg-info"):
                continue
            if first_dir != expected_dir:
                non_package_paths.append(record)

            if first_dir in self.top_package_paths:
                if normalized_package_name not in self.top_package_paths[first_dir].get(
                    "packages", set()
                ):
                    overwrite_paths.append((record, self.top_package_paths[first_dir]))

        return non_package_paths, overwrite_paths
