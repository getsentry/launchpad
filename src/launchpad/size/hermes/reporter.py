"""Hermes bytecode size reporter."""

from __future__ import annotations

from typing import Dict, Literal, TypedDict

from .parser import HermesBytecodeParser

HermesSectionNames = Literal[
    "Header",
    "Function table",
    "String Kinds",
    "Identifier hashes",
    "String table",
    "Overflow String table",
    "String storage",
    "Array buffer",
    "Object key buffer",
    "Object value buffer",
    "BigInt storage",
    "Regular expression table",
    "Regular expression storage",
    "CommonJS module table",
    "Function body",
    "Function info",
    "Debug info",
    "Function Source table",
]


class SectionInfo(TypedDict):
    """Section size information."""

    bytes: int
    percentage: float


class HermesReport(TypedDict):
    """Hermes size report."""

    sections: Dict[HermesSectionNames, SectionInfo]
    unattributed: SectionInfo
    file_size: int


class HermesSizeReporter:
    """Reports bytecode section sizes and percentages."""

    def __init__(self, hermes: HermesBytecodeParser):
        self.hermes = hermes

    def report(self) -> HermesReport:
        """Generate size report for Hermes bytecode."""
        header = self.hermes.get_header()
        file_size = header.file_length if header else 0

        section_order: list[HermesSectionNames] = [
            "Header",
            "Function table",
            "String Kinds",
            "Identifier hashes",
            "String table",
            "Overflow String table",
            "String storage",
            "Array buffer",
            "Object key buffer",
            "Object value buffer",
            "BigInt storage",
            "Regular expression table",
            "Regular expression storage",
            "CommonJS module table",
            "Function body",
            "Function info",
            "Debug info",
            "Function Source table",
        ]

        sections: Dict[HermesSectionNames, SectionInfo] = {
            section_name: {"bytes": 0, "percentage": 0.0} for section_name in section_order
        }

        if not header:
            return {
                "sections": sections,
                "unattributed": {"bytes": 0, "percentage": 0.0},
                "file_size": file_size,
            }

        # Header is always 128 bytes
        sections["Header"]["bytes"] = 128

        function_headers = self.hermes.get_function_headers()
        if function_headers:
            sections["Function table"]["bytes"] = sum(fheader.header_size for fheader in function_headers)

        string_kinds = self.hermes.get_string_kinds()
        sections["String Kinds"]["bytes"] = len(string_kinds) * 4  # Each entry is 4 bytes

        identifier_hashes = self.hermes.get_identifier_hashes()
        sections["Identifier hashes"]["bytes"] = len(identifier_hashes) * 4  # Each hash is 4 bytes

        small_string_table = self.hermes.get_small_string_table()
        sections["String table"]["bytes"] = len(small_string_table) * 4  # Each entry is 4 bytes

        overflow_string_table = self.hermes.get_overflow_string_table()
        sections["Overflow String table"]["bytes"] = len(overflow_string_table) * 8  # Each entry is 8 bytes

        sections["String storage"]["bytes"] = header.string_storage_size
        sections["Array buffer"]["bytes"] = header.array_buffer_size
        sections["Object key buffer"]["bytes"] = header.obj_key_buffer_size
        sections["Object value buffer"]["bytes"] = header.obj_value_buffer_size
        sections["BigInt storage"]["bytes"] = header.big_int_storage_size

        reg_exp_table = self.hermes.get_reg_exp_table()
        sections["Regular expression table"]["bytes"] = len(reg_exp_table) * 8  # Each entry is 8 bytes

        sections["Regular expression storage"]["bytes"] = header.reg_exp_storage_size

        cjs_module_table = self.hermes.get_cjs_module_table()
        sections["CommonJS module table"]["bytes"] = len(cjs_module_table) * 8  # Each entry is 8 bytes

        # Calculate function body size
        if function_headers:
            first_func_header = function_headers[0]
            sections["Function body"]["bytes"] = first_func_header.info_offset - first_func_header.offset

        # Calculate function info size
        if header.debug_info_offset > 0 and function_headers:
            first_func_header = function_headers[0]
            info_offset = first_func_header.info_offset
            if info_offset < header.debug_info_offset and info_offset > 0:
                sections["Function info"]["bytes"] = header.debug_info_offset - info_offset

        debug_info = self.hermes.get_debug_info()
        if debug_info:
            sections["Debug info"]["bytes"] = debug_info.debug_info_header.debug_data_size

        function_source_table = self.hermes.get_function_source_table()
        sections["Function Source table"]["bytes"] = len(function_source_table) * 8  # Each entry is 8 bytes

        # Validate and calculate percentages
        attributed_size = 0
        for section_name in section_order:
            # Ensure non-negative sizes
            if sections[section_name]["bytes"] < 0:
                sections[section_name]["bytes"] = 0
            # Ensure size doesn't exceed file size
            if sections[section_name]["bytes"] > file_size:
                sections[section_name]["bytes"] = 0

            attributed_size += sections[section_name]["bytes"]
            sections[section_name]["percentage"] = (
                (sections[section_name]["bytes"] / file_size * 100) if file_size > 0 else 0
            )

        unattributed_size = file_size - attributed_size
        unattributed = {
            "bytes": unattributed_size,
            "percentage": (unattributed_size / file_size * 100) if file_size > 0 else 0,
        }

        return {
            "sections": sections,
            "unattributed": unattributed,
            "file_size": file_size,
        }

    def print_report(self) -> None:
        """Print formatted size report to console."""
        report = self.report()

        print("\nHermes Bytecode Size Report (Detailed):")
        print(f"Total File Size: {report['file_size']} bytes")
        print("\nSection Breakdown:")

        for section_name, section_info in report["sections"].items():
            print(f"  {section_name}: {section_info['bytes']} bytes ({section_info['percentage']:.2f}%)")

        print(f"\nUnattributed: {report['unattributed']['bytes']} bytes ({report['unattributed']['percentage']:.2f}%)")
