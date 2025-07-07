"""Hermes bytecode treemap element builder."""

from __future__ import annotations

from pathlib import Path
from typing import List

from launchpad.size.hermes.parser import HermesBytecodeParser
from launchpad.size.hermes.reporter import HermesReport, HermesSizeReporter
from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapType
from launchpad.size.treemap.treemap_element_builder import TreemapElementBuilder
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class HermesElementBuilder(TreemapElementBuilder):
    """Builder for Hermes bytecode treemap elements."""

    def __init__(
        self,
        download_compression_ratio: float,
        filesystem_block_size: int,
    ) -> None:
        super().__init__(
            download_compression_ratio=download_compression_ratio,
            filesystem_block_size=filesystem_block_size,
        )

    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement | None:
        """Build a TreemapElement for a Hermes bytecode file."""
        try:
            file_path = Path(file_info.absolute_path)
            data = file_path.read_bytes()

            if not HermesBytecodeParser.is_hermes_file(data):
                logger.warning("File %s is not a valid Hermes bytecode file", file_info.path)
                return None

            parser = HermesBytecodeParser(data)
            if not parser.parse():
                logger.warning("Failed to parse Hermes bytecode file %s", file_info.path)
                return None

            reporter = HermesSizeReporter(parser)
            report = reporter.report()

            return self._build_hermes_treemap(
                name=display_name,
                file_path=str(file_info.path),
                report=report,
            )

        except Exception as e:
            logger.error("Error building Hermes treemap element for %s: %s", file_info.path, e)
            return None

    def _build_hermes_treemap(
        self,
        name: str,
        file_path: str,
        report: HermesReport,
    ) -> TreemapElement:
        """Build treemap element for Hermes bytecode sections."""
        section_children: List[TreemapElement] = []

        # Group sections by category for better organization
        string_sections: List[TreemapElement] = []
        function_sections: List[TreemapElement] = []
        other_sections: List[TreemapElement] = []

        for section_name, section_info in report["sections"].items():
            if section_info["bytes"] <= 0:
                continue

            treemap_type = self._get_treemap_type_for_section(section_name)

            element = TreemapElement(
                name=section_name,
                install_size=section_info["bytes"],
                download_size=section_info["bytes"],
                element_type=treemap_type,
                path=None,
                is_directory=False,
                children=[],
                details={
                    "percentage": section_info["percentage"],
                    "section_type": section_name,
                },
            )

            if "string" in section_name.lower() or "identifier" in section_name.lower():
                string_sections.append(element)
            elif "function" in section_name.lower():
                function_sections.append(element)
            else:
                other_sections.append(element)

        # Create category groups if we have multiple sections
        if len(string_sections) > 1:
            string_total = sum(s.install_size for s in string_sections)
            section_children.append(
                TreemapElement(
                    name="Strings & Identifiers",
                    install_size=string_total,
                    download_size=string_total,
                    element_type=TreemapType.STRINGS,
                    path=None,
                    is_directory=True,
                    children=string_sections,
                    details={"category": "strings"},
                )
            )
        else:
            section_children.extend(string_sections)

        if len(function_sections) > 1:
            function_total = sum(f.install_size for f in function_sections)
            section_children.append(
                TreemapElement(
                    name="Functions",
                    install_size=function_total,
                    download_size=function_total,
                    element_type=TreemapType.METHODS,
                    path=None,
                    is_directory=True,
                    children=function_sections,
                    details={"category": "functions"},
                )
            )
        else:
            section_children.extend(function_sections)

        # Add other sections directly
        section_children.extend(other_sections)

        # Add unattributed section only if present
        if report["unattributed"]["bytes"] > 0:
            section_children.append(
                TreemapElement(
                    name="Unattributed",
                    install_size=report["unattributed"]["bytes"],
                    download_size=report["unattributed"]["bytes"],
                    element_type=TreemapType.BINARY,
                    path=None,
                    is_directory=False,
                    children=[],
                    details={
                        "percentage": report["unattributed"]["percentage"],
                        "section_type": "unattributed",
                    },
                )
            )

        total_size = sum(c.install_size for c in section_children)

        return TreemapElement(
            name=name,
            install_size=total_size,
            download_size=total_size,
            element_type=TreemapType.BINARY,
            path=file_path,
            is_directory=True,
            children=section_children,
            details={
                "file_size": report["file_size"],
                "bytecode_type": "hermes",
            },
        )

    def _get_treemap_type_for_section(self, section_name: str) -> TreemapType:
        """Map Hermes section names to treemap types."""
        section_type_map = {
            "Header": TreemapType.BINARY,
            "Function table": TreemapType.METHODS,
            "String Kinds": TreemapType.STRINGS,
            "Identifier hashes": TreemapType.SYMBOLS,
            "String table": TreemapType.STRINGS,
            "Overflow String table": TreemapType.STRINGS,
            "String storage": TreemapType.STRINGS,
            "Array buffer": TreemapType.BINARY,
            "Object key buffer": TreemapType.BINARY,
            "Object value buffer": TreemapType.BINARY,
            "BigInt storage": TreemapType.BINARY,
            "Regular expression table": TreemapType.STRINGS,
            "Regular expression storage": TreemapType.STRINGS,
            "CommonJS module table": TreemapType.MODULES,
            "Function body": TreemapType.METHODS,
            "Function info": TreemapType.METHODS,
            "Debug info": TreemapType.BINARY,
            "Function Source table": TreemapType.METHODS,
        }

        return section_type_map.get(section_name, TreemapType.BINARY)
