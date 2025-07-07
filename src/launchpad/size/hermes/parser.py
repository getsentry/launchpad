"""Hermes bytecode parser implementation."""

from __future__ import annotations

import struct

from typing import List, Union

from launchpad.parsers.buffer_wrapper import BufferWrapper

from .types import (
    BytecodeFileHeader,
    BytecodeOptions,
    CJSModuleTableEntry,
    DebugFileRegion,
    DebugInfoHeader,
    DebugInfoResult,
    DebugStringTableEntry,
    EntryKind,
    FunctionHeader,
    FunctionHeaderFlag,
    FunctionSourceTableEntry,
    OverflowStringTableEntry,
    RegExpTableEntry,
    SmallFuncHeader,
    StringKindEntry,
    StringTableEntry,
)

MAGIC = 0x1F1903C103BC1FC6
DELTA_MAGIC = ~MAGIC & 0xFFFFFFFFFFFFFFFF
SHA1_NUM_BYTES = 20


class HermesBytecodeParser:
    """Parser for Hermes bytecode files."""

    def __init__(self, data: bytes):
        self.buffer = BufferWrapper(data)
        self.header: BytecodeFileHeader | None = None
        self.function_headers: List[Union[SmallFuncHeader, FunctionHeader]] = []
        self.strings: List[str] = []
        self.string_kinds: List[StringKindEntry] = []
        self.identifier_hashes: List[int] = []
        self.small_string_table: List[StringTableEntry] = []
        self.overflow_string_table: List[OverflowStringTableEntry] = []
        self.debug_info: DebugInfoResult | None = None
        self.reg_exp_table: List[RegExpTableEntry] = []
        self.reg_exp_storage: bytes | None = None
        self.cjs_module_table: List[CJSModuleTableEntry] = []
        self.function_source_table: List[FunctionSourceTableEntry] = []

    @staticmethod
    def is_hermes_file(data: bytes) -> bool:
        """Check if data is a valid Hermes bytecode file."""
        if len(data) < 8:
            return False

        try:
            magic = struct.unpack("<Q", data[:8])[0]
            return magic == MAGIC or magic == DELTA_MAGIC
        except Exception:
            return False

    def get_header(self) -> BytecodeFileHeader | None:
        """Get parsed header."""
        return self.header

    def get_function_headers(self) -> List[Union[SmallFuncHeader, FunctionHeader]]:
        """Get parsed function headers."""
        return self.function_headers

    def get_strings(self) -> List[str]:
        """Get parsed strings."""
        return self.strings

    def get_string_kinds(self) -> List[StringKindEntry]:
        """Get string kinds."""
        return self.string_kinds

    def get_identifier_hashes(self) -> List[int]:
        """Get identifier hashes."""
        return self.identifier_hashes

    def get_debug_info(self) -> DebugInfoResult | None:
        """Get debug info."""
        return self.debug_info

    def get_reg_exp_table(self) -> List[RegExpTableEntry]:
        """Get regular expression table."""
        return self.reg_exp_table

    def get_reg_exp_storage(self) -> bytes | None:
        """Get regular expression storage."""
        return self.reg_exp_storage

    def get_cjs_module_table(self) -> List[CJSModuleTableEntry]:
        """Get CommonJS module table."""
        return self.cjs_module_table

    def get_function_source_table(self) -> List[FunctionSourceTableEntry]:
        """Get function source table."""
        return self.function_source_table

    def get_small_string_table(self) -> List[StringTableEntry]:
        """Get small string table."""
        return self.small_string_table

    def get_overflow_string_table(self) -> List[OverflowStringTableEntry]:
        """Get overflow string table."""
        return self.overflow_string_table

    def parse(self) -> bool:
        """Parse the bytecode file."""
        try:
            self.header = self._parse_header()
            self.buffer.align_buffer(4)

            self.function_headers = self._parse_function_headers(self.header.function_count)
            self.buffer.align_buffer(4)

            self.string_kinds = self._parse_string_kinds(self.header.string_kind_count)
            self.buffer.align_buffer(4)

            self.identifier_hashes = self._parse_identifier_hashes(self.header.identifier_count)
            self.buffer.align_buffer(4)

            self.small_string_table = self._parse_string_table_entries(self.header.string_count)
            self.buffer.align_buffer(4)

            self.overflow_string_table = self._parse_overflow_string_table_entries(self.header.overflow_string_count)
            self.buffer.align_buffer(4)

            self.strings = self._parse_string_storage(
                self.small_string_table,
                self.overflow_string_table,
                self.header.string_storage_size,
            )
            self.buffer.align_buffer(4)

            self.buffer.skip(self.header.array_buffer_size)
            self.buffer.align_buffer(4)

            self.buffer.skip(self.header.obj_key_buffer_size)
            self.buffer.align_buffer(4)

            self.buffer.skip(self.header.obj_value_buffer_size)
            self.buffer.align_buffer(4)

            if self.header.reg_exp_count > 0:
                self.reg_exp_table = self._parse_reg_exp_table(self.header.reg_exp_count)
                self.buffer.align_buffer(4)

            if self.header.reg_exp_storage_size > 0:
                self.reg_exp_storage = self._parse_reg_exp_storage(self.header.reg_exp_storage_size)
                self.buffer.align_buffer(4)

            if self.header.cjs_module_count > 0:
                self.cjs_module_table = self._parse_cjs_module_table(self.header.cjs_module_count)
                self.buffer.align_buffer(4)

            if self.header.function_source_count > 0:
                self.function_source_table = self._parse_function_source_table(self.header.function_source_count)
                self.buffer.align_buffer(4)

            if self.header.debug_info_offset != 0:
                self.debug_info = self._parse_debug_info()
                self.buffer.align_buffer(4)

            return True
        except Exception:
            return False

    def _parse_header(self) -> BytecodeFileHeader:
        """Parse bytecode file header."""
        magic = self.buffer.read_u64()
        if magic != MAGIC and magic != DELTA_MAGIC:
            raise ValueError("Invalid magic number. Not a valid Hermes bytecode file.")

        version = self.buffer.read_u32()
        source_hash = self.buffer.slice(SHA1_NUM_BYTES)
        file_length = self.buffer.read_u32()
        global_code_index = self.buffer.read_u32()
        function_count = self.buffer.read_u32()
        string_kind_count = self.buffer.read_u32()
        identifier_count = self.buffer.read_u32()
        string_count = self.buffer.read_u32()
        overflow_string_count = self.buffer.read_u32()
        string_storage_size = self.buffer.read_u32()
        big_int_count = self.buffer.read_u32()
        big_int_storage_size = self.buffer.read_u32()
        reg_exp_count = self.buffer.read_u32()
        reg_exp_storage_size = self.buffer.read_u32()
        array_buffer_size = self.buffer.read_u32()
        obj_key_buffer_size = self.buffer.read_u32()
        obj_value_buffer_size = self.buffer.read_u32()
        segment_id = self.buffer.read_u32()
        cjs_module_count = self.buffer.read_u32()
        function_source_count = self.buffer.read_u32()
        debug_info_offset = self.buffer.read_u32()

        options_byte = self.buffer.read_u8()
        options = self._parse_bytecode_options(options_byte)

        self.buffer.skip(19)  # Padding

        return BytecodeFileHeader(
            magic=magic,
            version=version,
            source_hash=source_hash,
            file_length=file_length,
            global_code_index=global_code_index,
            function_count=function_count,
            string_kind_count=string_kind_count,
            identifier_count=identifier_count,
            string_count=string_count,
            overflow_string_count=overflow_string_count,
            string_storage_size=string_storage_size,
            big_int_count=big_int_count,
            big_int_storage_size=big_int_storage_size,
            reg_exp_count=reg_exp_count,
            reg_exp_storage_size=reg_exp_storage_size,
            array_buffer_size=array_buffer_size,
            obj_key_buffer_size=obj_key_buffer_size,
            obj_value_buffer_size=obj_value_buffer_size,
            segment_id=segment_id,
            cjs_module_count=cjs_module_count,
            function_source_count=function_source_count,
            debug_info_offset=debug_info_offset,
            options=options,
        )

    def _parse_bytecode_options(self, byte: int) -> BytecodeOptions:
        """Parse bytecode options from byte."""
        return BytecodeOptions(
            static_builtins=(byte & 0b00000001) != 0,
            cjs_modules_statically_resolved=(byte & 0b00000010) != 0,
            has_async=(byte & 0b00000100) != 0,
        )

    def _parse_function_headers(self, count: int) -> List[Union[SmallFuncHeader, FunctionHeader]]:
        """Parse function headers."""
        headers: List[Union[SmallFuncHeader, FunctionHeader]] = []

        for _ in range(count):
            header = self._parse_small_func_header()

            if header.flags.overflowed:
                large_header_offset = (header.info_offset << 16) | header.offset

                saved_position = self.buffer.cursor
                self.buffer.seek(large_header_offset)
                large_header = self._parse_large_function_header()
                large_header = FunctionHeader(**{**large_header.__dict__, "header_size": header.header_size})
                headers.append(large_header)

                self.buffer.seek(saved_position)
            else:
                headers.append(header)

        return headers

    def _parse_small_func_header(self) -> SmallFuncHeader:
        """Parse small function header."""
        starting_position = self.buffer.cursor

        word1 = self.buffer.read_u32()
        offset = word1 & 0x1FFFFFF  # 25 bits
        param_count = (word1 >> 25) & 0x7F  # 7 bits

        word2 = self.buffer.read_u32()
        bytecode_size_in_bytes = word2 & 0x7FFF  # 15 bits
        function_name = (word2 >> 15) & 0x1FFFF  # 17 bits

        word3 = self.buffer.read_u32()
        info_offset = word3 & 0x1FFFFFF  # 25 bits
        frame_size = (word3 >> 25) & 0x7F  # 7 bits

        environment_size = self.buffer.read_u8()
        highest_read_cache_index = self.buffer.read_u8()
        highest_write_cache_index = self.buffer.read_u8()
        flags_byte = self.buffer.read_u8()

        end_position = self.buffer.cursor
        flags = self._parse_function_header_flag(flags_byte)

        return SmallFuncHeader(
            offset=offset,
            param_count=param_count,
            bytecode_size_in_bytes=bytecode_size_in_bytes,
            function_name=function_name,
            info_offset=info_offset,
            frame_size=frame_size,
            environment_size=environment_size,
            highest_read_cache_index=highest_read_cache_index,
            highest_write_cache_index=highest_write_cache_index,
            flags=flags,
            header_size=end_position - starting_position,
            type="small",
        )

    def _parse_function_header_flag(self, byte: int) -> FunctionHeaderFlag:
        """Parse function header flags."""
        return FunctionHeaderFlag(
            prohibit_invoke=byte & 0b00000011,
            strict_mode=(byte & 0b00000100) != 0,
            has_exception_handler=(byte & 0b00001000) != 0,
            has_debug_info=(byte & 0b00010000) != 0,
            overflowed=(byte & 0b00100000) != 0,
        )

    def _parse_large_function_header(self) -> FunctionHeader:
        """Parse large function header."""
        starting_position = self.buffer.cursor

        offset = self.buffer.read_u32()
        param_count = self.buffer.read_u32()
        bytecode_size_in_bytes = self.buffer.read_u32()
        function_name = self.buffer.read_u32()
        info_offset = self.buffer.read_u32()
        frame_size = self.buffer.read_u32()
        environment_size = self.buffer.read_u32()
        highest_read_cache_index = self.buffer.read_u8()
        highest_write_cache_index = self.buffer.read_u8()
        flags_byte = self.buffer.read_u8()

        end_position = self.buffer.cursor
        flags = self._parse_function_header_flag(flags_byte)

        return FunctionHeader(
            offset=offset,
            param_count=param_count,
            bytecode_size_in_bytes=bytecode_size_in_bytes,
            function_name=function_name,
            info_offset=info_offset,
            frame_size=frame_size,
            environment_size=environment_size,
            highest_read_cache_index=highest_read_cache_index,
            highest_write_cache_index=highest_write_cache_index,
            flags=flags,
            large_header_size=end_position - starting_position,
            header_size=0,
            type="large",
        )

    def _parse_string_kinds(self, count: int) -> List[StringKindEntry]:
        entries: List[StringKindEntry] = []
        for _ in range(count):
            packed_value = self.buffer.read_u32()
            kind = EntryKind(packed_value & 0x1)
            count_value = packed_value >> 1
            entries.append(StringKindEntry(kind=kind, count=count_value))
        return entries

    def _parse_identifier_hashes(self, count: int) -> List[int]:
        return [self.buffer.read_u32() for _ in range(count)]

    def _parse_string_table_entries(self, count: int) -> List[StringTableEntry]:
        entries: List[StringTableEntry] = []
        for _ in range(count):
            packed_value = self.buffer.read_u32()
            is_utf16 = (packed_value & 0x1) == 1
            offset = (packed_value >> 1) & 0x7FFFFF
            length = (packed_value >> 24) & 0xFF
            entries.append(
                StringTableEntry(
                    offset=offset,
                    length=length,
                    is_utf16=is_utf16,
                )
            )
        return entries

    def _parse_overflow_string_table_entries(self, count: int) -> List[OverflowStringTableEntry]:
        entries: List[OverflowStringTableEntry] = []
        for _ in range(count):
            offset = self.buffer.read_u32()
            length = self.buffer.read_u32()
            entries.append(OverflowStringTableEntry(offset=offset, length=length))
        return entries

    def _parse_string_storage(
        self,
        string_table_entries: List[StringTableEntry],
        overflow_string_table: List[OverflowStringTableEntry],
        size: int,
    ) -> List[str]:
        strings: List[str] = []
        if size == 0:
            return strings

        storage = self.buffer.slice(size)
        INVALID_LENGTH = (1 << 8) - 1

        for entry in string_table_entries:
            if entry.length >= INVALID_LENGTH:
                overflow_entry = overflow_string_table[entry.offset]
                offset = overflow_entry.offset
                length = overflow_entry.length
            else:
                offset = entry.offset
                length = entry.length

            if length == 0:
                strings.append("")
                continue

            try:
                byte_length = length * 2 if entry.is_utf16 else length
                if offset + byte_length > len(storage):
                    raise ValueError("String exceeds buffer bounds")

                string_bytes = storage[offset : offset + byte_length]

                if entry.is_utf16:
                    strings.append(string_bytes.decode("utf-16"))
                else:
                    strings.append(string_bytes.decode("utf-8"))
            except Exception as e:
                strings.append(f"[Error reading string: {e}]")

        return strings

    def _parse_debug_info(self) -> DebugInfoResult:
        if not self.header:
            raise ValueError("No bytecode header found")

        self.buffer.seek(self.header.debug_info_offset)

        if self.header.version >= 91:
            debug_info_header = DebugInfoHeader(
                filename_count=self.buffer.read_u32(),
                filename_storage_size=self.buffer.read_u32(),
                file_region_count=self.buffer.read_u32(),
                scope_desc_data_offset=self.buffer.read_u32(),
                debug_data_size=self.buffer.read_u32(),
                textified_data_offset=self.buffer.read_u32(),
                string_table_offset=self.buffer.read_u32(),
            )
        else:
            debug_info_header = DebugInfoHeader(
                filename_count=self.buffer.read_u32(),
                filename_storage_size=self.buffer.read_u32(),
                file_region_count=self.buffer.read_u32(),
                scope_desc_data_offset=self.buffer.read_u32(),
                debug_data_size=self.buffer.read_u32(),
            )

        debug_string_table: List[DebugStringTableEntry] = []
        for _ in range(debug_info_header.filename_count):
            offset = self.buffer.read_u32()
            length = self.buffer.read_u32()
            debug_string_table.append(DebugStringTableEntry(offset=offset, length=length))

        debug_string_storage = self.buffer.slice(debug_info_header.filename_storage_size)

        debug_file_regions: List[DebugFileRegion] = []
        for _ in range(debug_info_header.file_region_count):
            from_address = self.buffer.read_u32()
            filename_id = self.buffer.read_u32()
            source_mapping_id = self.buffer.read_u32()
            debug_file_regions.append(
                DebugFileRegion(
                    from_address=from_address,
                    filename_id=filename_id,
                    source_mapping_id=source_mapping_id,
                )
            )

        if self.header.version < 91:
            sources_data_size = debug_info_header.scope_desc_data_offset
            scope_desc_data_size = debug_info_header.debug_data_size - debug_info_header.scope_desc_data_offset
            self.buffer.skip(sources_data_size + scope_desc_data_size)
        else:
            total_size = debug_info_header.debug_data_size - (self.buffer.cursor - self.header.debug_info_offset)
            self.buffer.skip(total_size)

        debug_filenames = self._get_debug_filenames(debug_info_header, debug_string_table, debug_string_storage)

        return DebugInfoResult(
            debug_info_header=debug_info_header,
            debug_string_table=debug_string_table,
            debug_file_regions=debug_file_regions,
            debug_filenames=debug_filenames,
        )

    def _get_debug_filenames(
        self,
        debug_info_header: DebugInfoHeader,
        debug_string_table: List[DebugStringTableEntry],
        debug_string_storage: bytes,
    ) -> List[str]:
        result: List[str] = []
        for entry in debug_string_table:
            if entry.offset + entry.length > len(debug_string_storage):
                result.append(f"[Invalid offset in debug string table: {entry.offset}]")
            else:
                slice_data = debug_string_storage[entry.offset : entry.offset + entry.length]
                result.append(slice_data.decode("utf-8"))
        return result

    def _parse_reg_exp_table(self, count: int) -> List[RegExpTableEntry]:
        entries: List[RegExpTableEntry] = []
        for _ in range(count):
            offset = self.buffer.read_u32()
            length = self.buffer.read_u32()
            entries.append(RegExpTableEntry(offset=offset, length=length))
        return entries

    def _parse_reg_exp_storage(self, size: int) -> bytes:
        if size == 0:
            return b""
        return self.buffer.slice(size)

    def _parse_cjs_module_table(self, count: int) -> List[CJSModuleTableEntry]:
        entries: List[CJSModuleTableEntry] = []
        for _ in range(count):
            first = self.buffer.read_u32()
            second = self.buffer.read_u32()
            entries.append(CJSModuleTableEntry(first=first, second=second))
        return entries

    def _parse_function_source_table(self, count: int) -> List[FunctionSourceTableEntry]:
        entries: List[FunctionSourceTableEntry] = []
        for _ in range(count):
            function_id = self.buffer.read_u32()
            string_offset = self.buffer.read_u32()
            entries.append(
                FunctionSourceTableEntry(
                    function_id=function_id,
                    string_offset=string_offset,
                )
            )
        return entries
