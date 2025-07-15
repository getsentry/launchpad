"""Binary analyzer for Mach-O binaries that extracts component size information."""

from __future__ import annotations

from typing import Any

import lief

from launchpad.parsers.apple.macho_parser import MachOParser
from launchpad.size.models.binary_component import BinaryAnalysis, BinaryTag
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class MachOSizeAnalyzer:
    """Analyzes Mach-O binaries to extract sections size information."""

    def __init__(self, parser: MachOParser, file_size: int, file_path: str) -> None:
        self.parser = parser
        self.file_size = file_size
        self.file_path = file_path

    def analyze(self) -> BinaryAnalysis:
        """Analyze the binary and extract sections information.

        Returns:
            Complete binary analysis with all detected sectionss
        """
        logger.debug(f"Analyzing binary: {self.file_path}")

        analysis = BinaryAnalysis(file_path=self.file_path, total_size=self.file_size)

        try:
            # Analyze sectionss in order of priority
            self._analyze_mach_o_header(analysis)
            self._analyze_load_commands(analysis)
            self._analyze_segments_and_sections(analysis)

            logger.debug(f"Analysis complete: {len(analysis.components)} components found")
            logger.info(
                f"Binary coverage: {analysis.coverage_percentage:.1f}%, "
                f"analyzed: {analysis.analyzed_size} bytes, "
                f"unanalyzed: {analysis.unanalyzed_size} bytes"
            )

        except Exception as e:
            logger.warning(f"Failed to complete binary analysis: {e}")

        return analysis

    def _analyze_mach_o_header(self, analysis: BinaryAnalysis) -> None:
        """Analyze the Mach-O header."""
        header_size = self.parser.get_header_size()
        analysis.add_component("mach_o_header", header_size, BinaryTag.HEADERS, "Mach-O file header")

    def _analyze_load_commands(self, analysis: BinaryAnalysis) -> None:
        """Analyze load commands in the binary."""
        commands: list[lief.MachO.LoadCommand] = list(self.parser.binary.commands)
        if not commands:
            logger.warning("No load commands found")
            return

        for i, command in enumerate(commands):
            cmd_size = command.size
            cmd_name = command.command.name
            cmd_type = command.command

            # Add the load command itself
            analysis.add_component(
                f"lc_{cmd_name.lower()}", cmd_size, BinaryTag.LOAD_COMMANDS, f"Load command: {cmd_name}"
            )

            try:
                # Analyze command-specific data
                if cmd_type == lief.MachO.LoadCommand.TYPE.SYMTAB:
                    if cast_command := self._cast_command(command, lief.MachO.SymbolCommand):
                        self._analyze_symtab_command(analysis, cast_command)
                elif cmd_type in [
                    lief.MachO.LoadCommand.TYPE.DYLD_INFO,
                    lief.MachO.LoadCommand.TYPE.DYLD_INFO_ONLY,
                ]:
                    if cast_command := self._cast_command(command, lief.MachO.DyldInfo):
                        self._analyze_dyld_info_command(analysis, cast_command)
                elif cmd_type == lief.MachO.LoadCommand.TYPE.FUNCTION_STARTS:
                    if cast_command := self._cast_command(command, lief.MachO.FunctionStarts):
                        self._analyze_function_starts_command(analysis, cast_command)
                elif cmd_type == lief.MachO.LoadCommand.TYPE.CODE_SIGNATURE:
                    if cast_command := self._cast_command(command, lief.MachO.CodeSignature):
                        self._analyze_code_signature_command(analysis, cast_command)
                elif cmd_type == lief.MachO.LoadCommand.TYPE.DATA_IN_CODE:
                    if cast_command := self._cast_command(command, lief.MachO.DataInCode):
                        self._analyze_data_in_code_command(analysis, cast_command)
                elif cmd_type == lief.MachO.LoadCommand.TYPE.DYLD_CHAINED_FIXUPS:
                    if cast_command := self._cast_command(command, lief.MachO.DyldChainedFixups):
                        self._analyze_dyld_chained_fixups_command(analysis, cast_command)

            except Exception as e:
                logger.debug(f"Failed to analyze command {i} {cmd_name}: {e}")

    def _cast_command(self, command: lief.MachO.LoadCommand, expected_type: type) -> Any | None:
        """Safely cast a load command to the expected type."""
        if isinstance(command, expected_type):
            return command
        else:
            logger.warning(f"Expected {expected_type.__name__}, got {type(command).__name__}")
            return None

    def _analyze_symtab_command(self, analysis: BinaryAnalysis, command: lief.MachO.SymbolCommand) -> None:
        """Analyze symbol table and string table from LC_SYMTAB command."""
        # Symbol table
        if command.symbol_offset > 0 and command.numberof_symbols > 0:
            # Each symbol entry is typically 16 bytes (64-bit)
            symbol_size = command.numberof_symbols * 16
            analysis.add_component(
                "symbol_table", symbol_size, BinaryTag.DEBUG_INFO, f"Symbol table ({command.numberof_symbols} symbols)"
            )

        # String table
        if command.strings_offset > 0 and command.strings_size > 0:
            analysis.add_component(
                "string_table", command.strings_size, BinaryTag.DYLD_STRING_TABLE, "String table for symbols"
            )

    def _analyze_dyld_info_command(self, analysis: BinaryAnalysis, command: lief.MachO.DyldInfo) -> None:
        """Analyze DYLD info sections from LC_DYLD_INFO command."""
        # Rebase information
        rebase_offset, rebase_size = command.rebase
        if rebase_offset > 0 and rebase_size > 0:
            analysis.add_component("dyld_rebase_info", rebase_size, BinaryTag.DYLD_REBASE, "DYLD rebase information")

        # Bind information
        bind_offset, bind_size = command.bind
        if bind_offset > 0 and bind_size > 0:
            analysis.add_component("dyld_bind_info", bind_size, BinaryTag.DYLD_BIND, "DYLD bind information")

        # Weak bind information
        weak_bind_offset, weak_bind_size = command.weak_bind
        if weak_bind_offset > 0 and weak_bind_size > 0:
            analysis.add_component(
                "dyld_weak_bind_info", weak_bind_size, BinaryTag.DYLD_BIND, "DYLD weak bind information"
            )

        # Lazy bind information
        lazy_bind_offset, lazy_bind_size = command.lazy_bind
        if lazy_bind_offset > 0 and lazy_bind_size > 0:
            analysis.add_component(
                "dyld_lazy_bind_info", lazy_bind_size, BinaryTag.DYLD_LAZY_BIND, "DYLD lazy bind information"
            )

        # Export information
        export_offset, export_size = command.export_info
        if export_offset > 0 and export_size > 0:
            analysis.add_component("dyld_export_info", export_size, BinaryTag.DYLD_EXPORTS, "DYLD export information")

    def _analyze_function_starts_command(self, analysis: BinaryAnalysis, command: lief.MachO.FunctionStarts) -> None:
        """Analyze function starts information from LC_FUNCTION_STARTS command."""
        analysis.add_component(
            "function_starts", command.data_size, BinaryTag.FUNCTION_STARTS, "Function start addresses"
        )

    def _analyze_code_signature_command(self, analysis: BinaryAnalysis, command: lief.MachO.CodeSignature) -> None:
        """Analyze code signature from LC_CODE_SIGNATURE command."""
        analysis.add_component("code_signature", command.data_size, BinaryTag.CODE_SIGNATURE, "Code signature data")

    def _analyze_data_in_code_command(self, analysis: BinaryAnalysis, command: lief.MachO.DataInCode) -> None:
        """Analyze data-in-code information from LC_DATA_IN_CODE command."""
        analysis.add_component("data_in_code", command.data_size, BinaryTag.DEBUG_INFO, "Data-in-code entries")

    def _analyze_dyld_chained_fixups_command(
        self, analysis: BinaryAnalysis, command: lief.MachO.DyldChainedFixups
    ) -> None:
        """Analyze chained fixups from LC_DYLD_CHAINED_FIXUPS command."""
        analysis.add_component("dyld_chained_fixups", command.data_size, BinaryTag.DYLD_FIXUPS, "DYLD chained fixups")

    def _analyze_segments_and_sections(self, analysis: BinaryAnalysis) -> None:
        """Analyze segments and sections."""
        sections = self.parser.binary.sections

        for section in sections:
            section_name = (
                section.name.decode("utf-8", errors="replace") if isinstance(section.name, bytes) else str(section.name)
            )

            try:
                if section.size == 0:
                    logger.debug(f"Skipping section {section_name} with zero size")
                    continue

                tag = self._categorize_section(section_name)
                analysis.add_component(section_name, section.size, tag, None)

            except Exception as e:
                logger.debug(f"Failed to analyze section {section_name}: {e}")

    def _categorize_section(self, section_name: str) -> BinaryTag:
        """Categorize a section based on its name."""
        name_lower = section_name.lower()

        # Text segment sections
        if any(text_name in name_lower for text_name in ["__text", "__stubs", "__stub_helper"]):
            return BinaryTag.TEXT_SEGMENT

        # Swift metadata sections
        if "swift" in name_lower:
            return BinaryTag.SWIFT_METADATA

        # Objective-C sections
        if "objc" in name_lower:
            return BinaryTag.OBJC_CLASSES

        # String sections
        if any(str_name in name_lower for str_name in ["__cstring", "__cfstring", "__ustring"]):
            return BinaryTag.C_STRINGS

        # Data sections
        if any(data_name in name_lower for data_name in ["__data", "__bss", "__common"]):
            return BinaryTag.DATA_SEGMENT

        # Const sections
        if "const" in name_lower:
            return BinaryTag.CONST_DATA

        # Unwind info
        if "unwind" in name_lower or "eh_frame" in name_lower:
            return BinaryTag.UNWIND_INFO

        # Default to data segment
        return BinaryTag.DATA_SEGMENT
