"""Range mapping builder for iOS binaries."""

from __future__ import annotations

from typing import Any

import lief

from ..models import BinaryTag, RangeMap
from ..utils.logging import get_logger
from .macho_parser import MachOParser

logger = get_logger(__name__)


class RangeMappingBuilder:
    """Builds range mappings for iOS binaries."""

    def __init__(self, parser: MachOParser, file_size: int) -> None:
        """Initialize the builder.

        Args:
            parser: MachO parser instance
            file_size: Total file size
        """
        self.parser = parser
        self.file_size = file_size

    def build_range_mapping(self) -> RangeMap:
        """Build complete range mapping for the binary.

        Returns:
            Complete range mapping with all detected ranges
        """
        logger.debug("Creating range mapping for binary content")

        range_map = RangeMap(total_file_size=self.file_size)

        try:
            # Map components in order of priority
            self._map_mach_o_header(range_map)
            self._map_load_commands(range_map)
            self._map_segments_and_sections(range_map)

            logger.debug(f"Range mapping created with {len(range_map.ranges)} ranges")

            coverage_report = range_map.get_coverage_report()
            logger.info(
                f"Binary coverage: {coverage_report['coverage_percentage']}%, "
                f"unmapped: {coverage_report['unmapped_size']} bytes, "
                f"conflicts: {coverage_report['conflict_count']}"
            )

        except Exception as e:
            logger.warning(f"Failed to create complete range mapping: {e}")

        return range_map

    def _map_mach_o_header(self, range_map: RangeMap) -> None:
        """Map the Mach-O header."""
        header_size = self.parser.get_header_size()
        range_map.add_range(0, header_size, BinaryTag.HEADERS, "mach_o_header")

    def _map_load_commands(self, range_map: RangeMap) -> None:
        """Map load commands in the binary."""
        commands: list[lief.MachO.LoadCommand] = list(self.parser.binary.commands)
        if not commands:
            logger.debug("No load commands found")
            return

        current_offset = self.parser.get_header_size()

        for i, command in enumerate(commands):
            cmd_size = command.size
            cmd_name = command.command.name
            cmd_type = command.command
            range_map.add_range(
                command.command_offset,
                command.command_offset + cmd_size,
                BinaryTag.LOAD_COMMANDS,
                f"load_command_{i}_{cmd_name}",
            )

            try:
                if cmd_type == lief.MachO.LoadCommand.TYPE.SYMTAB:
                    self._map_symtab_command(range_map, command)
                elif cmd_type in [
                    lief.MachO.LoadCommand.TYPE.DYLD_INFO,
                    lief.MachO.LoadCommand.TYPE.DYLD_INFO_ONLY,
                ]:
                    self._map_dyld_info_command(range_map, command)
                elif cmd_type == lief.MachO.LoadCommand.TYPE.FUNCTION_STARTS:
                    self._map_function_starts_command(range_map, command)
                elif cmd_type == lief.MachO.LoadCommand.TYPE.CODE_SIGNATURE:
                    self._map_code_signature_command(range_map, command)
                elif cmd_type == lief.MachO.LoadCommand.TYPE.DATA_IN_CODE:
                    self._map_data_in_code_command(range_map, command)
                elif cmd_type == lief.MachO.LoadCommand.TYPE.DYLIB_CODE_SIGN_DRS:
                    self._map_dylib_code_sign_drs_command(range_map, command)
                elif cmd_type == lief.MachO.LoadCommand.TYPE.LINKER_OPTIMIZATION_HINT:
                    self._map_linker_optimization_hint_command(range_map, command)
                elif cmd_type == lief.MachO.LoadCommand.TYPE.DYLD_EXPORTS_TRIE:
                    self._map_dyld_exports_trie_command(range_map, command)
                elif cmd_type == lief.MachO.LoadCommand.TYPE.DYLD_CHAINED_FIXUPS:
                    self._map_dyld_chained_fixups_command(range_map, command)
            except Exception as e:
                logger.debug(f"Failed to process command {i} {command.command.name}: {e}")

            current_offset += cmd_size

    def _map_symtab_command(self, range_map: RangeMap, command: Any) -> None:
        """Map symbol table and string table from LC_SYMTAB command."""
        try:
            if command.symbol_offset > 0 and command.nb_symbols > 0:
                # Each symbol entry is typically 16 bytes (64-bit)
                symbol_size = command.nb_symbols * 16
                range_map.add_range(
                    command.symbol_offset, command.symbol_offset + symbol_size, BinaryTag.DEBUG_INFO, "symbol_table"
                )

            if command.string_offset > 0 and command.string_size > 0:
                range_map.add_range(
                    command.string_offset,
                    command.string_offset + command.string_size,
                    BinaryTag.C_STRINGS,
                    "string_table",
                )
        except Exception as e:
            logger.error(f"Failed to map symtab command: {e}")

    def _map_dyld_info_command(self, range_map: RangeMap, command: Any) -> None:
        """Map DYLD info sections from LC_DYLD_INFO command."""
        try:
            if hasattr(command, "rebase_off") and command.rebase_off > 0 and command.rebase_size > 0:
                range_map.add_range(
                    command.rebase_off,
                    command.rebase_off + command.rebase_size,
                    BinaryTag.DYLD_REBASE,
                    "dyld_rebase_info",
                )

            if hasattr(command, "bind_off") and command.bind_off > 0 and command.bind_size > 0:
                range_map.add_range(
                    command.bind_off, command.bind_off + command.bind_size, BinaryTag.DYLD_BIND, "dyld_bind_info"
                )

            if hasattr(command, "lazy_bind_off") and command.lazy_bind_off > 0 and command.lazy_bind_size > 0:
                range_map.add_range(
                    command.lazy_bind_off,
                    command.lazy_bind_off + command.lazy_bind_size,
                    BinaryTag.DYLD_LAZY_BIND,
                    "dyld_lazy_bind_info",
                )

            if hasattr(command, "export_off") and command.export_off > 0 and command.export_size > 0:
                range_map.add_range(
                    command.export_off,
                    command.export_off + command.export_size,
                    BinaryTag.DYLD_EXPORTS,
                    "dyld_export_info",
                )
        except Exception as e:
            logger.debug(f"Failed to map DYLD info command: {e}")

    def _map_function_starts_command(self, range_map: RangeMap, command: Any) -> None:
        """Map function starts information from LC_FUNCTION_STARTS command."""
        try:
            if hasattr(command, "data_offset") and command.data_offset > 0 and command.data_size > 0:
                range_map.add_range(
                    command.data_offset,
                    command.data_offset + command.data_size,
                    BinaryTag.FUNCTION_STARTS,
                    "function_starts",
                )
        except Exception as e:
            logger.debug(f"Failed to map function starts command: {e}")

    def _map_code_signature_command(self, range_map: RangeMap, command: Any) -> None:
        """Map code signature from LC_CODE_SIGNATURE command."""
        try:
            if hasattr(command, "data_offset") and command.data_offset > 0 and command.data_size > 0:
                range_map.add_range(
                    command.data_offset,
                    command.data_offset + command.data_size,
                    BinaryTag.CODE_SIGNATURE,
                    "code_signature",
                )
        except Exception as e:
            logger.debug(f"Failed to map code signature command: {e}")

    def _map_data_in_code_command(self, range_map: RangeMap, command: Any) -> None:
        """Map data-in-code information from LC_DATA_IN_CODE command."""
        try:
            if hasattr(command, "data_offset") and command.data_offset > 0 and command.data_size > 0:
                range_map.add_range(
                    command.data_offset,
                    command.data_offset + command.data_size,
                    BinaryTag.DEBUG_INFO,
                    "data_in_code",
                )
        except Exception as e:
            logger.debug(f"Failed to map data-in-code command: {e}")

    def _map_dylib_code_sign_drs_command(self, range_map: RangeMap, command: Any) -> None:
        """Map code signature DRs from LC_DYLIB_CODE_SIGN_DRS command."""
        try:
            if hasattr(command, "data_offset") and command.data_offset > 0 and command.data_size > 0:
                range_map.add_range(
                    command.data_offset,
                    command.data_offset + command.data_size,
                    BinaryTag.CODE_SIGNATURE,
                    "dylib_code_sign_drs",
                )
        except Exception as e:
            logger.debug(f"Failed to map dylib code sign DRs command: {e}")

    def _map_linker_optimization_hint_command(self, range_map: RangeMap, command: Any) -> None:
        """Map linker optimization hints from LC_LINKER_OPTIMIZATION_HINT command."""
        try:
            if hasattr(command, "data_offset") and command.data_offset > 0 and command.data_size > 0:
                range_map.add_range(
                    command.data_offset,
                    command.data_offset + command.data_size,
                    BinaryTag.DEBUG_INFO,
                    "linker_optimization_hints",
                )
        except Exception as e:
            logger.debug(f"Failed to map linker optimization hint command: {e}")

    def _map_dyld_exports_trie_command(self, range_map: RangeMap, command: Any) -> None:
        """Map exports trie from LC_DYLD_EXPORTS_TRIE command."""
        try:
            if hasattr(command, "data_offset") and command.data_offset > 0 and command.data_size > 0:
                range_map.add_range(
                    command.data_offset,
                    command.data_offset + command.data_size,
                    BinaryTag.DYLD_EXPORTS,
                    "dyld_exports_trie",
                )
        except Exception as e:
            logger.debug(f"Failed to map exports trie command: {e}")

    def _map_dyld_chained_fixups_command(self, range_map: RangeMap, command: Any) -> None:
        """Map chained fixups from LC_DYLD_CHAINED_FIXUPS command."""
        range_map.add_range(
            command.data_offset,
            command.data_offset + command.data_size,
            BinaryTag.DYLD_BIND,
            "dyld_chained_fixups",
        )

    def _map_segments_and_sections(self, range_map: RangeMap) -> None:
        """Map segments and sections."""
        sections = self.parser.binary.sections

        for section in sections:
            section_name = (
                section.name.decode("utf-8", errors="replace") if isinstance(section.name, bytes) else str(section.name)
            )

            try:
                if section.size == 0 or section.offset == 0:
                    logger.debug(f"Skipping section {section_name} with no file presence")
                    continue

                tag = self._categorize_section(section_name)
                range_map.add_range(section.offset, section.offset + section.size, tag, f"section_{section_name}")

            except Exception as e:
                logger.debug(f"Failed to map section {section_name}: {e}")

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
