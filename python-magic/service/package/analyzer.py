from assemblyline_v4_service.common.result import ResultTextSection

from .opener import OPENER_MAP, PackageOpener


class Analyzer:
    def __init__(self, path: str, package_type: str):
        self.path = path
        self.package_type = package_type

    def analyze(self):
        section = ResultTextSection("Python package analysis")
        with OPENER_MAP[self.package_type](self.path) as opener:
            opener: PackageOpener
            section.add_line(f"Package type: {self.package_type.upper()}")
            section.add_line(f"Package name: {opener.distribution.name}")
            section.add_line(f"Package version: {opener.distribution.version}")
            section.add_line(f"Package author: {opener.distribution.author}")
            section.add_line(f"Package author email: {opener.distribution.author_email}")

            requirements = list(opener.get_requirements())
            if requirements:
                req_section = ResultTextSection(f"Requirements ({len(requirements)})")
                for req in requirements:
                    req_section.add_line(req)
                section.add_subsection(req_section)

            scripts = list(opener.get_console_scripts())
            if scripts:
                script_section = ResultTextSection(f"Scripts ({len(scripts)})", auto_collapse=True)
                for script in scripts:
                    script_section.add_line(script)
                section.add_subsection(script_section)

            top_level_modules = list(opener.get_top_level_modules())
            if top_level_modules:
                module_section = ResultTextSection(
                    f"Top-level modules ({len(top_level_modules)})", auto_collapse=True
                )
                for module in top_level_modules:
                    module_section.add_line(module)
                section.add_subsection(module_section)
            return section
