from assemblyline_v4_service.common.result import ResultTextSection

from .opener import OPENER_MAP, PackageOpener

HEURISTICS_MAP = {
    "malicious": 1,
    "suspicious": 2,
}


class Analyzer:
    def __init__(
        self, path: str, package_type: str, requirements_blocklist: dict[str, set[str]] = None
    ):
        self.path = path
        self.package_type = package_type
        self.requirements_blocklist = requirements_blocklist or {
            "malicious": set(),
            "suspicious": set(),
        }

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
                    req_section.add_line(req)
                    if req.lower() in self.requirements_blocklist["malicious"]:
                        heur_sections.setdefault("malicious", []).append(req)
                    elif req.lower() in self.requirements_blocklist["suspicious"]:
                        heur_sections.setdefault("suspicious", []).append(req)
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
                            f"PythonMagic.{heur_type.lower()}_dependencies.{req.lower()}"
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
            return section
