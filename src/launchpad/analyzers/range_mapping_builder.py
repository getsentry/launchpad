"""Range mapping builder for iOS binaries."""

from __future__ import annotations

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
            self._map_dyld_info(range_map)
            self._map_symbol_table(range_map)
            self._map_string_table(range_map)
            self._map_function_starts(range_map)
            self._map_code_signature(range_map)

            # Map any remaining LINKEDIT gaps that weren't captured by specific load commands
            self._map_linkedit_gaps(range_map)

            # Map any remaining gaps as padding/alignment
            self._map_remaining_gaps(range_map)

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
        commands = self.parser.get_load_commands()
        if not commands:
            return

        # Load commands start after the header
        current_offset = self.parser.get_header_size()

        for i, (cmd_size, command) in enumerate(commands):
            try:
                if cmd_size > 0:
                    range_map.add_range(
                        current_offset,
                        current_offset + cmd_size,
                        BinaryTag.LOAD_COMMANDS,
                        f"load_command_{i}_{type(command).__name__}",
                    )
                    current_offset += cmd_size
            except Exception as e:
                logger.debug(f"Failed to map load command {i}: {e}")
                # Use a default size if we can't get the actual size
                cmd_size = 16  # Minimum load command size
                range_map.add_range(
                    current_offset,
                    current_offset + cmd_size,
                    BinaryTag.LOAD_COMMANDS,
                    f"load_command_{i}_estimated",
                )
                current_offset += cmd_size

    def _map_segments_and_sections(self, range_map: RangeMap) -> None:
        """Map segments and sections."""
        sections = self.parser.get_sections_with_offsets()

        for section_name, file_offset, section_size in sections:
            try:
                # Skip sections with no file presence
                if section_size == 0 or file_offset == 0:
                    continue

                # Categorize section based on name
                tag = self._categorize_section(section_name)

                range_map.add_range(file_offset, file_offset + section_size, tag, f"section_{section_name}")

            except Exception as e:
                logger.debug(f"Failed to map section {section_name}: {e}")

    def _map_linkedit_data(self, range_map: RangeMap) -> None:
        """Map linkedit data sections that might not be captured as regular sections."""
        try:
            # Try to map linkedit segment data that might contain various tables
            segments = getattr(self.parser.binary, "segments", None)
            if segments:
                for segment in segments:
                    segment_name = getattr(segment, "name", "")
                    if segment_name == "__LINKEDIT":
                        file_offset = getattr(segment, "file_offset", 0)
                        file_size = getattr(segment, "file_size", 0)

                        if file_offset > 0 and file_size > 0:
                            # Map the entire linkedit segment, which will contain various data structures
                            range_map.add_range(
                                file_offset, file_offset + file_size, BinaryTag.DATA_SEGMENT, "linkedit_segment"
                            )
                            break
        except Exception as e:
            logger.debug(f"Failed to map linkedit data: {e}")

    def _map_symbol_table(self, range_map: RangeMap) -> None:
        """Map symbol table data."""
        try:
            # Look for LC_SYMTAB load command data
            commands = getattr(self.parser.binary, "commands", None)
            if commands:
                for command in commands:
                    if hasattr(command, "command") and hasattr(command, "symbol_offset"):
                        # This is likely a symtab command
                        symbol_offset = getattr(command, "symbol_offset", 0)
                        nb_symbols = getattr(command, "nb_symbols", 0)

                        if symbol_offset > 0 and nb_symbols > 0:
                            # Each symbol entry is typically 16 bytes (64-bit)
                            symbol_size = nb_symbols * 16
                            range_map.add_range(
                                symbol_offset, symbol_offset + symbol_size, BinaryTag.DEBUG_INFO, "symbol_table"
                            )
        except Exception as e:
            logger.debug(f"Failed to map symbol table: {e}")

    def _map_string_table(self, range_map: RangeMap) -> None:
        """Map string table data."""
        try:
            # Look for LC_SYMTAB load command string data
            commands = getattr(self.parser.binary, "commands", None)
            if commands:
                for command in commands:
                    if hasattr(command, "command") and hasattr(command, "string_offset"):
                        # This is likely a symtab command
                        string_offset = getattr(command, "string_offset", 0)
                        string_size = getattr(command, "string_size", 0)

                        if string_offset > 0 and string_size > 0:
                            range_map.add_range(
                                string_offset, string_offset + string_size, BinaryTag.C_STRINGS, "string_table"
                            )
        except Exception as e:
            logger.debug(f"Failed to map string table: {e}")

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

    def _map_dyld_info(self, range_map: RangeMap) -> None:
        """Map DYLD info sections if available."""
        try:
            # Look for LC_DYLD_INFO or LC_DYLD_INFO_ONLY commands
            commands = getattr(self.parser.binary, "commands", None)
            if commands:
                for command in commands:
                    if hasattr(command, "command"):
                        cmd_type = getattr(command, "command", 0)

                        # Check if this is a DYLD info command (LC_DYLD_INFO_ONLY = 0x80000022)
                        if cmd_type in [0x22, 0x80000022]:
                            # Map rebase info
                            if hasattr(command, "rebase_off") and hasattr(command, "rebase_size"):
                                rebase_off = getattr(command, "rebase_off", 0)
                                rebase_size = getattr(command, "rebase_size", 0)
                                if rebase_off > 0 and rebase_size > 0:
                                    range_map.add_range(
                                        rebase_off, rebase_off + rebase_size, BinaryTag.DYLD_REBASE, "dyld_rebase_info"
                                    )

                            # Map bind info
                            if hasattr(command, "bind_off") and hasattr(command, "bind_size"):
                                bind_off = getattr(command, "bind_off", 0)
                                bind_size = getattr(command, "bind_size", 0)
                                if bind_off > 0 and bind_size > 0:
                                    range_map.add_range(
                                        bind_off, bind_off + bind_size, BinaryTag.DYLD_BIND, "dyld_bind_info"
                                    )

                            # Map lazy bind info
                            if hasattr(command, "lazy_bind_off") and hasattr(command, "lazy_bind_size"):
                                lazy_bind_off = getattr(command, "lazy_bind_off", 0)
                                lazy_bind_size = getattr(command, "lazy_bind_size", 0)
                                if lazy_bind_off > 0 and lazy_bind_size > 0:
                                    range_map.add_range(
                                        lazy_bind_off,
                                        lazy_bind_off + lazy_bind_size,
                                        BinaryTag.DYLD_LAZY_BIND,
                                        "dyld_lazy_bind_info",
                                    )

                            # Map export info
                            if hasattr(command, "export_off") and hasattr(command, "export_size"):
                                export_off = getattr(command, "export_off", 0)
                                export_size = getattr(command, "export_size", 0)
                                if export_off > 0 and export_size > 0:
                                    range_map.add_range(
                                        export_off, export_off + export_size, BinaryTag.DYLD_EXPORTS, "dyld_export_info"
                                    )
        except Exception as e:
            logger.debug(f"Failed to map DYLD info: {e}")

    def _map_function_starts(self, range_map: RangeMap) -> None:
        """Map function starts information if available."""
        try:
            # Look for LC_FUNCTION_STARTS load command
            if hasattr(self.parser.binary, "commands"):
                for command in self.parser.binary.commands:
                    if hasattr(command, "command"):
                        cmd_type = getattr(command, "command", 0)

                        # LC_FUNCTION_STARTS = 0x26
                        if cmd_type == 0x26:
                            if hasattr(command, "data_offset") and hasattr(command, "data_size"):
                                data_offset = getattr(command, "data_offset", 0)
                                data_size = getattr(command, "data_size", 0)
                                if data_offset > 0 and data_size > 0:
                                    range_map.add_range(
                                        data_offset,
                                        data_offset + data_size,
                                        BinaryTag.FUNCTION_STARTS,
                                        "function_starts",
                                    )
        except Exception as e:
            logger.debug(f"Failed to map function starts: {e}")

    def _map_code_signature(self, range_map: RangeMap) -> None:
        """Map code signature if present."""
        try:
            # Look for LC_CODE_SIGNATURE load command
            if hasattr(self.parser.binary, "commands"):
                for command in self.parser.binary.commands:
                    if hasattr(command, "command"):
                        cmd_type = getattr(command, "command", 0)

                        # LC_CODE_SIGNATURE = 0x1d
                        if cmd_type == 0x1D:
                            if hasattr(command, "data_offset") and hasattr(command, "data_size"):
                                data_offset = getattr(command, "data_offset", 0)
                                data_size = getattr(command, "data_size", 0)
                                if data_offset > 0 and data_size > 0:
                                    range_map.add_range(
                                        data_offset, data_offset + data_size, BinaryTag.CODE_SIGNATURE, "code_signature"
                                    )
        except Exception as e:
            logger.debug(f"Failed to map code signature: {e}")

    def _map_linkedit_gaps(self, range_map: RangeMap) -> None:
        """Map remaining gaps in the LINKEDIT segment that weren't captured by load commands."""
        try:
            # Find the LINKEDIT segment bounds
            segments = getattr(self.parser.binary, "segments", None)
            if not segments:
                return

            linkedit_start = None
            linkedit_end = None

            for segment in segments:
                segment_name = getattr(segment, "name", "")
                if segment_name == "__LINKEDIT":
                    linkedit_start = getattr(segment, "file_offset", 0)
                    linkedit_size = getattr(segment, "file_size", 0)
                    linkedit_end = linkedit_start + linkedit_size
                    break

            if linkedit_start is None or linkedit_end is None:
                return

            # Find gaps within the LINKEDIT segment using partial splitting
            current_pos = linkedit_start
            linkedit_ranges = []

            # Collect all ranges that fall within LINKEDIT
            for range_item in range_map.ranges:
                if range_item.start >= linkedit_start and range_item.end <= linkedit_end:
                    linkedit_ranges.append(range_item)

            # Sort by start position
            linkedit_ranges.sort(key=lambda r: r.start)

            # Fill gaps between mapped ranges
            for range_item in linkedit_ranges:
                if current_pos < range_item.start:
                    # Gap found, use partial splitting to avoid conflicts
                    gap_size = range_item.start - current_pos
                    range_map.add_range(
                        current_pos,
                        range_item.start,
                        BinaryTag.DATA_SEGMENT,
                        f"linkedit_gap_{gap_size}_bytes",
                        allow_partial=True,  # Use partial splitting for gaps
                    )
                current_pos = max(current_pos, range_item.end)

            # Fill any remaining gap at the end
            if current_pos < linkedit_end:
                gap_size = linkedit_end - current_pos
                range_map.add_range(
                    current_pos,
                    linkedit_end,
                    BinaryTag.DATA_SEGMENT,
                    f"linkedit_end_gap_{gap_size}_bytes",
                    allow_partial=True,  # Use partial splitting for end gaps
                )

        except Exception as e:
            logger.debug(f"Failed to map linkedit gaps: {e}")

    def _map_remaining_gaps(self, range_map: RangeMap) -> None:
        """Map any remaining unmapped regions as padding/alignment."""
        try:
            unmapped_regions = range_map.get_unmapped_regions()

            for region in unmapped_regions:
                # Only map gaps smaller than 64KB as padding/alignment
                # Larger gaps might indicate missing structures that need specific mapping
                if region.size <= 65536:  # 64KB threshold
                    range_map.add_range(
                        region.start,
                        region.end,
                        BinaryTag.UNMAPPED,
                        f"padding_gap_{region.size}_bytes",
                        allow_partial=True,  # Use partial splitting for padding gaps
                    )
                else:
                    logger.warning(f"Large unmapped region: {region.size} bytes at offset {region.start}")
        except Exception as e:
            logger.debug(f"Failed to map remaining gaps: {e}")
