"""Range mapping builder for iOS binaries."""

from __future__ import annotations

from typing import Any

from ..models import BinaryTag, Range, RangeMap
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
            self._map_load_command_data(range_map)

            # Parse Swift metadata with range mapping integration
            self._map_swift_metadata(range_map)

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

        current_offset = self.parser.get_header_size()

        for i, (cmd_size, command) in enumerate(commands):
            try:
                if cmd_size > 0 and current_offset + cmd_size <= self.file_size:
                    try:
                        cmd_name = type(command).__name__
                    except (AttributeError, TypeError):
                        cmd_name = "unknown_error"

                    range_map.add_range(
                        current_offset,
                        current_offset + cmd_size,
                        BinaryTag.LOAD_COMMANDS,
                        f"load_command_{i}_{cmd_name}",
                    )
                    current_offset += cmd_size
                else:
                    logger.error(
                        f"Invalid load command {i}: size={cmd_size}, offset={current_offset}, size={self.file_size}"
                    )
            except (ValueError, AttributeError, TypeError) as e:
                logger.error(f"Failed to map load command {i} at offset {current_offset}: {e}")

    def _map_load_command_data(self, range_map: RangeMap) -> None:
        """Map data referenced by load commands in a single pass."""
        try:
            if not hasattr(self.parser.binary, "commands"):
                logger.debug("Binary has no commands attribute")
                return

            for command in self.parser.binary.commands:
                try:
                    if not hasattr(command, "command"):
                        continue

                    cmd_type = command.command

                    if self._is_symtab_command(command):
                        self._map_symtab_command(range_map, command)
                    elif cmd_type in [0x22, 0x80000022]:  # LC_DYLD_INFO or LC_DYLD_INFO_ONLY
                        self._map_dyld_info_command(range_map, command)
                    elif cmd_type == 0x26:  # LC_FUNCTION_STARTS
                        self._map_function_starts_command(range_map, command)
                    elif cmd_type == 0x1D:  # LC_CODE_SIGNATURE
                        self._map_code_signature_command(range_map, command)
                    elif cmd_type == 0x29:  # LC_DATA_IN_CODE
                        self._map_data_in_code_command(range_map, command)
                    elif cmd_type == 0x2A:  # LC_DYLIB_CODE_SIGN_DRS
                        self._map_dylib_code_sign_drs_command(range_map, command)
                    elif cmd_type == 0x2B:  # LC_LINKER_OPTIMIZATION_HINT
                        self._map_linker_optimization_hint_command(range_map, command)
                    elif cmd_type == 0x32:  # LC_DYLD_EXPORTS_TRIE
                        self._map_dyld_exports_trie_command(range_map, command)
                    elif cmd_type == 0x33:  # LC_DYLD_CHAINED_FIXUPS
                        self._map_dyld_chained_fixups_command(range_map, command)

                except Exception as e:
                    logger.debug(f"Failed to process command {type(command).__name__}: {e}")

        except Exception as e:
            logger.debug(f"Failed to map load command data: {e}")

    def _is_symtab_command(self, command: Any) -> bool:
        """Check if command is a symbol table command."""
        return (
            hasattr(command, "symbol_offset")
            and hasattr(command, "string_offset")
            and hasattr(command, "nb_symbols")
            and hasattr(command, "string_size")
        )

    def _map_symtab_command(self, range_map: RangeMap, command: Any) -> None:
        """Map symbol table and string table from LC_SYMTAB command."""
        try:
            if command.symbol_offset > 0 and command.nb_symbols > 0:
                # Each symbol entry is typically 16 bytes (64-bit)
                symbol_size = command.nb_symbols * 16
                range_map.add_range(
                    command.symbol_offset,
                    command.symbol_offset + symbol_size,
                    BinaryTag.DEBUG_INFO,
                    "symbol_table",
                )

            if command.string_offset > 0 and command.string_size > 0:
                range_map.add_range(
                    command.string_offset,
                    command.string_offset + command.string_size,
                    BinaryTag.C_STRINGS,
                    "string_table",
                )
        except AttributeError as e:
            logger.debug(f"Symbol command missing expected attributes: {e}")
        except Exception as e:
            logger.debug(f"Failed to map symtab command: {e}")

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
                    command.bind_off,
                    command.bind_off + command.bind_size,
                    BinaryTag.DYLD_BIND,
                    "dyld_bind_info",
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
        try:
            if hasattr(command, "data_offset") and command.data_offset > 0 and command.data_size > 0:
                range_map.add_range(
                    command.data_offset,
                    command.data_offset + command.data_size,
                    BinaryTag.DYLD_BIND,
                    "dyld_chained_fixups",
                )
        except Exception as e:
            logger.debug(f"Failed to map chained fixups command: {e}")

    def _map_segments_and_sections(self, range_map: RangeMap) -> None:
        """Map segments and sections."""
        sections = self.parser.get_sections_with_offsets()

        for section_name, file_offset, section_size in sections:
            try:
                if section_size == 0 or file_offset == 0:
                    logger.debug(f"Skipping section {section_name} with no file presence")
                    continue

                tag = self._categorize_section(section_name)

                range_map.add_range(file_offset, file_offset + section_size, tag, f"section_{section_name}")

            except Exception as e:
                logger.debug(f"Failed to map section {section_name}: {e}")

    def _map_linkedit_data(self, range_map: RangeMap) -> None:
        """Map linkedit data sections that might not be captured as regular sections."""
        try:
            if hasattr(self.parser.binary, "segments"):
                for segment in self.parser.binary.segments:
                    if hasattr(segment, "name") and segment.name == "__LINKEDIT":
                        if hasattr(segment, "file_offset") and hasattr(segment, "file_size"):
                            if segment.file_offset > 0 and segment.file_size > 0:
                                range_map.add_range(
                                    segment.file_offset,
                                    segment.file_offset + segment.file_size,
                                    BinaryTag.DATA_SEGMENT,
                                    "linkedit_segment",
                                )
                                break
        except Exception as e:
            logger.debug(f"Failed to map linkedit data: {e}")

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

    def _map_linkedit_gaps(self, range_map: RangeMap) -> None:
        """Map remaining gaps in the LINKEDIT segment that weren't captured by load commands."""
        try:
            if not hasattr(self.parser.binary, "segments"):
                logger.debug("Binary has no segments attribute")
                return

            linkedit_start: int | None = None
            linkedit_end: int | None = None

            for segment in self.parser.binary.segments:
                if hasattr(segment, "name") and segment.name == "__LINKEDIT":
                    if hasattr(segment, "file_offset") and hasattr(segment, "file_size"):
                        linkedit_start = int(segment.file_offset)
                        linkedit_end = linkedit_start + int(segment.file_size)
                        break

            if linkedit_start is None or linkedit_end is None:
                return

            # Find gaps within the LINKEDIT segment using partial splitting
            current_pos: int = linkedit_start
            linkedit_ranges: list[Range] = []

            # Collect all ranges that fall within LINKEDIT
            for range_item in range_map.ranges:
                if range_item.start >= linkedit_start and range_item.end <= linkedit_end:
                    linkedit_ranges.append(range_item)

            # Sort by start position
            linkedit_ranges.sort(key=lambda r: r.start)

            # Fill gaps between mapped ranges
            for range_item in linkedit_ranges:
                if current_pos < range_item.start:
                    gap_size: int = range_item.start - current_pos

                    if gap_size <= 1024:  # Small gaps (<=1KB) - likely padding/alignment
                        logger.debug(f"Filling small gap {gap_size} bytes at offset {current_pos}")
                        range_map.add_range(
                            current_pos,
                            range_item.start,
                            BinaryTag.UNMAPPED,
                            f"linkedit_padding_{gap_size}_bytes",
                            allow_partial=True,
                        )
                    elif gap_size <= 65536:  # Medium gaps (1KB-64KB)
                        logger.debug(f"Filling medium gap {gap_size} bytes at offset {current_pos}")
                        range_map.add_range(
                            current_pos,
                            range_item.start,
                            BinaryTag.DATA_SEGMENT,
                            f"linkedit_data_{gap_size}_bytes",
                            allow_partial=True,
                        )
                    else:  # Large gaps (>64KB) - warn but don't guess
                        logger.warning(f"Large LINKEDIT gap detected: {gap_size} bytes at offset {current_pos}")
                        range_map.add_range(
                            current_pos,
                            range_item.start,
                            BinaryTag.DATA_SEGMENT,
                            f"linkedit_large_gap_{gap_size}_bytes",
                            allow_partial=True,
                        )

                current_pos = max(current_pos, range_item.end)

            # Fill any remaining gap at the end
            if current_pos < linkedit_end:
                gap_size = linkedit_end - current_pos

                if gap_size <= 1024:
                    logger.debug(f"Filling end padding {gap_size} bytes at offset {current_pos}")
                    range_map.add_range(
                        current_pos,
                        linkedit_end,
                        BinaryTag.UNMAPPED,
                        f"linkedit_end_padding_{gap_size}_bytes",
                        allow_partial=True,
                    )
                elif gap_size <= 65536:
                    logger.debug(f"Filling end data {gap_size} bytes at offset {current_pos}")
                    range_map.add_range(
                        current_pos,
                        linkedit_end,
                        BinaryTag.DATA_SEGMENT,
                        f"linkedit_end_data_{gap_size}_bytes",
                        allow_partial=True,
                    )
                else:
                    logger.warning(f"Large LINKEDIT end gap: {gap_size} bytes at offset {current_pos}")
                    range_map.add_range(
                        current_pos,
                        linkedit_end,
                        BinaryTag.DATA_SEGMENT,
                        f"linkedit_end_large_gap_{gap_size}_bytes",
                        allow_partial=True,
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

    def _map_swift_metadata(self, range_map: RangeMap) -> None:
        """Map Swift metadata sections using the comprehensive parser."""
        try:
            from .swift_metadata_parser import SwiftMetadataParser

            # Create Swift metadata parser with range mapping integration
            swift_parser = SwiftMetadataParser(self.parser, range_map)
            metadata = swift_parser.parse_swift_metadata()

            logger.debug(
                f"Swift metadata parsing completed: "
                f"{len(metadata.get('classes', []))} classes, "
                f"{len(metadata.get('protocols', []))} protocols, "
                f"{metadata.get('total_metadata_size', 0)} bytes total"
            )

        except Exception as e:
            logger.debug(f"Failed to map Swift metadata: {e}")
