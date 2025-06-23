"""Range mapping builder for Mach-O binaries."""

from __future__ import annotations

from typing import Any

import lief

from ...models.range_mapping import BinaryTag, RangeMap
from ...utils.logging import get_logger
from .macho_parser import MachOParser

logger = get_logger(__name__)


class RangeMappingBuilder:
    """Builds range mappings for Mach-O binaries."""

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
                    if isinstance(command, lief.MachO.DyldInfo):
                        self._map_dyld_info_command(range_map, command)
                    else:
                        logger.warning(f"Expected DyldInfo, got {type(command).__name__}")
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
                    if isinstance(command, lief.MachO.DyldChainedFixups):
                        self._map_dyld_chained_fixups_command(range_map, command)
                    else:
                        logger.warning(f"Expected DyldChainedFixups, got {type(command).__name__}")
                elif cmd_type == lief.MachO.LoadCommand.TYPE.RPATH:
                    self._map_rpath_command(range_map, command)
                elif cmd_type in [
                    lief.MachO.LoadCommand.TYPE.LOAD_DYLIB,
                    lief.MachO.LoadCommand.TYPE.LOAD_WEAK_DYLIB,
                    lief.MachO.LoadCommand.TYPE.REEXPORT_DYLIB,
                ]:
                    self._map_dylib_command(range_map, command)
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

    def _map_dyld_info_command(self, range_map: RangeMap, command: lief.MachO.DyldInfo) -> None:
        """Map DYLD info sections from LC_DYLD_INFO command."""
        try:
            # Rebase information
            rebase_offset, rebase_size = command.rebase
            if rebase_offset > 0 and rebase_size > 0:
                range_map.add_range(
                    rebase_offset,
                    rebase_offset + rebase_size,
                    BinaryTag.DYLD_REBASE,
                    "dyld_rebase_info",
                )

            # Bind information
            bind_offset, bind_size = command.bind
            if bind_offset > 0 and bind_size > 0:
                range_map.add_range(bind_offset, bind_offset + bind_size, BinaryTag.DYLD_BIND, "dyld_bind_info")

            # Weak bind information
            weak_bind_offset, weak_bind_size = command.weak_bind
            if weak_bind_offset > 0 and weak_bind_size > 0:
                range_map.add_range(
                    weak_bind_offset,
                    weak_bind_offset + weak_bind_size,
                    BinaryTag.DYLD_BIND,
                    "dyld_weak_bind_info",
                )

            # Lazy bind information
            lazy_bind_offset, lazy_bind_size = command.lazy_bind
            if lazy_bind_offset > 0 and lazy_bind_size > 0:
                range_map.add_range(
                    lazy_bind_offset,
                    lazy_bind_offset + lazy_bind_size,
                    BinaryTag.DYLD_LAZY_BIND,
                    "dyld_lazy_bind_info",
                )

            # Export information
            export_offset, export_size = command.export_info
            if export_offset > 0 and export_size > 0:
                range_map.add_range(
                    export_offset,
                    export_offset + export_size,
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
                # Map the overall data-in-code section
                range_map.add_range(
                    command.data_offset,
                    command.data_offset + command.data_size,
                    BinaryTag.DEBUG_INFO,
                    "data_in_code",
                )

                # Parse individual data-in-code entries
                self._map_data_in_code_entries(range_map, command)
        except Exception as e:
            logger.debug(f"Failed to map data-in-code command: {e}")

    def _map_data_in_code_entries(self, range_map: RangeMap, command: Any) -> None:
        """Map individual data-in-code entries."""
        try:
            # Each data_in_code_entry is typically 8 bytes:
            # - offset: UInt32 (offset from start of function)
            # - length: UInt16 (length of data)
            # - kind: UInt16 (type of data)
            entry_size = 8
            num_entries = command.data_size // entry_size

            if num_entries > 0:
                # Map the entries table
                range_map.add_range(
                    command.data_offset,
                    command.data_offset + (num_entries * entry_size),
                    BinaryTag.DEBUG_INFO,
                    "data_in_code_entries",
                )
        except Exception as e:
            logger.debug(f"Failed to map data-in-code entries: {e}")

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

    def _map_dyld_chained_fixups_command(self, range_map: RangeMap, command: lief.MachO.DyldChainedFixups) -> None:
        """Map chained fixups from LC_DYLD_CHAINED_FIXUPS command."""
        try:
            range_map.add_range(
                command.data_offset,
                command.data_offset + command.data_size,
                BinaryTag.DYLD_FIXUPS,
                "dyld_chained_fixups",
            )

            # Extract imported symbols from chained fixups
            self._extract_imported_symbols_from_fixups(range_map, command)
        except Exception as e:
            logger.debug(f"Failed to map chained fixups command: {e}")

    def _extract_imported_symbols_from_fixups(self, range_map: RangeMap, command: lief.MachO.DyldChainedFixups) -> None:
        """Extract imported symbols from chained fixups command.

        This maps the external methods/symbols that are imported by the binary.
        Uses LIEF's built-in imported_symbols property for simplicity.
        """
        try:
            # Use LIEF's built-in imported symbols functionality
            imported_symbols = self.parser.binary.imported_symbols
            if imported_symbols:
                # Map the entire fixups data as external methods
                # The individual symbol names are available via imported_symbols
                range_map.add_range(
                    command.data_offset,
                    command.data_offset + command.data_size,
                    BinaryTag.EXTERNAL_METHODS,
                    "imported_symbols",
                )

                logger.debug(f"Found {len(imported_symbols)} imported symbols")

        except Exception as e:
            logger.debug(f"Failed to extract imported symbols from fixups: {e}")

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

    def _map_rpath_command(self, range_map: RangeMap, command: Any) -> None:
        """Map RPATH command data."""
        try:
            if hasattr(command, "path") and hasattr(command.path, "offset"):
                # The path string is embedded in the command
                path_offset = command.command_offset + command.path.offset
                path_size = command.size - command.path.offset
                if path_size > 0:
                    range_map.add_range(
                        path_offset,
                        path_offset + path_size,
                        BinaryTag.C_STRINGS,
                        "rpath_string",
                    )
        except Exception as e:
            logger.debug(f"Failed to map RPATH command: {e}")

    def _map_dylib_command(self, range_map: RangeMap, command: Any) -> None:
        """Map dylib loading command data (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB)."""
        try:
            if (
                hasattr(command, "library")
                and hasattr(command.library, "name")
                and hasattr(command.library.name, "offset")
            ):
                # The dylib name string is embedded in the command
                name_offset = command.command_offset + command.library.name.offset
                name_size = command.size - command.library.name.offset
                if name_size > 0:
                    range_map.add_range(
                        name_offset,
                        name_offset + name_size,
                        BinaryTag.C_STRINGS,
                        "dylib_name",
                    )
        except Exception as e:
            logger.debug(f"Failed to map dylib command: {e}")
