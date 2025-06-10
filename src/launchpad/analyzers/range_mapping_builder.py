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
            # Map components in order
            self._map_mach_o_header(range_map)
            self._map_load_commands(range_map)
            self._map_segments_and_sections(range_map)
            self._map_dyld_info(range_map)
            self._map_function_starts(range_map)
            self._map_code_signature(range_map)

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
                # Categorize section based on name
                tag = self._categorize_section(section_name)

                range_map.add_range(file_offset, file_offset + section_size, tag, f"section_{section_name}")

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

    def _map_dyld_info(self, range_map: RangeMap) -> None:
        """Map DYLD info sections if available."""
        dyld_info = self.parser.get_dyld_info()
        if not dyld_info:
            return

        # Map rebase info
        if hasattr(dyld_info, "rebase") and dyld_info.rebase:
            rebase_info = dyld_info.rebase
            if hasattr(rebase_info, "data_offset") and hasattr(rebase_info, "data_size"):
                range_map.add_range(
                    rebase_info.data_offset,
                    rebase_info.data_offset + rebase_info.data_size,
                    BinaryTag.DYLD_REBASE,
                    "dyld_rebase_info",
                )

        # Map bind info
        if hasattr(dyld_info, "bind") and dyld_info.bind:
            bind_info = dyld_info.bind
            if hasattr(bind_info, "data_offset") and hasattr(bind_info, "data_size"):
                range_map.add_range(
                    bind_info.data_offset,
                    bind_info.data_offset + bind_info.data_size,
                    BinaryTag.DYLD_BIND,
                    "dyld_bind_info",
                )

        # Map lazy bind info
        if hasattr(dyld_info, "lazy_bind") and dyld_info.lazy_bind:
            lazy_bind_info = dyld_info.lazy_bind
            if hasattr(lazy_bind_info, "data_offset") and hasattr(lazy_bind_info, "data_size"):
                range_map.add_range(
                    lazy_bind_info.data_offset,
                    lazy_bind_info.data_offset + lazy_bind_info.data_size,
                    BinaryTag.DYLD_LAZY_BIND,
                    "dyld_lazy_bind_info",
                )

        # Map export info
        if hasattr(dyld_info, "export_info") and dyld_info.export_info:
            export_info = dyld_info.export_info
            if hasattr(export_info, "data_offset") and hasattr(export_info, "data_size"):
                range_map.add_range(
                    export_info.data_offset,
                    export_info.data_offset + export_info.data_size,
                    BinaryTag.DYLD_EXPORTS,
                    "dyld_export_info",
                )

    def _map_function_starts(self, range_map: RangeMap) -> None:
        """Map function starts information if available."""
        # This would require parsing the LC_FUNCTION_STARTS load command
        # For now, this is a placeholder for future implementation
        pass

    def _map_code_signature(self, range_map: RangeMap) -> None:
        """Map code signature if present."""
        signature_info = self.parser.get_code_signature_info()
        if signature_info:
            offset, size = signature_info
            range_map.add_range(
                offset,
                offset + size,
                BinaryTag.CODE_SIGNATURE,
                "code_signature",
            )
