"""Hermes bytecode file format types."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import List, Literal


@dataclass(frozen=True)
class BytecodeOptions:
    """Bytecode options flags."""

    static_builtins: bool
    cjs_modules_statically_resolved: bool
    has_async: bool


@dataclass(frozen=True)
class BytecodeFileHeader:
    """Hermes bytecode file header."""

    magic: int
    version: int
    source_hash: bytes
    file_length: int
    global_code_index: int
    function_count: int
    string_kind_count: int
    identifier_count: int
    string_count: int
    overflow_string_count: int
    string_storage_size: int
    big_int_count: int
    big_int_storage_size: int
    reg_exp_count: int
    reg_exp_storage_size: int
    array_buffer_size: int
    obj_key_buffer_size: int
    obj_value_buffer_size: int
    segment_id: int
    cjs_module_count: int
    function_source_count: int
    debug_info_offset: int
    options: BytecodeOptions


@dataclass(frozen=True)
class FunctionHeaderFlag:
    """Function header flags."""

    prohibit_invoke: int  # 2 bits
    strict_mode: bool
    has_exception_handler: bool
    has_debug_info: bool
    overflowed: bool


@dataclass(frozen=True)
class FunctionHeader:
    """Large function header."""

    offset: int
    param_count: int
    bytecode_size_in_bytes: int
    function_name: int
    info_offset: int
    frame_size: int
    environment_size: int
    highest_read_cache_index: int
    highest_write_cache_index: int
    flags: FunctionHeaderFlag
    header_size: int
    large_header_size: int
    type: Literal["large"]


@dataclass(frozen=True)
class SmallFuncHeader:
    """Small function header with bit-packed fields."""

    offset: int  # 25 bits
    param_count: int  # 7 bits
    bytecode_size_in_bytes: int  # 15 bits
    function_name: int  # 17 bits
    info_offset: int  # 25 bits
    frame_size: int  # 7 bits
    environment_size: int  # 8 bits
    highest_read_cache_index: int  # 8 bits
    highest_write_cache_index: int  # 8 bits
    flags: FunctionHeaderFlag
    header_size: int
    type: Literal["small"]


class EntryKind(IntEnum):
    """String entry kind."""

    String = 0
    Identifier = 1


@dataclass(frozen=True)
class StringKindEntry:
    """String kind table entry."""

    kind: EntryKind
    count: int


@dataclass(frozen=True)
class StringTableEntry:
    """String table entry."""

    offset: int
    length: int
    is_utf16: bool


@dataclass(frozen=True)
class OverflowStringTableEntry:
    """Overflow string table entry."""

    offset: int
    length: int


@dataclass(frozen=True)
class DebugInfoHeader:
    """Debug info header."""

    filename_count: int
    filename_storage_size: int
    file_region_count: int
    scope_desc_data_offset: int
    debug_data_size: int
    # The next two fields only exist in version >= 91
    textified_data_offset: int | None = None
    string_table_offset: int | None = None


@dataclass(frozen=True)
class DebugStringTableEntry:
    """Debug string table entry."""

    offset: int
    length: int


@dataclass(frozen=True)
class DebugFileRegion:
    """Debug file region."""

    from_address: int
    filename_id: int
    source_mapping_id: int


@dataclass(frozen=True)
class DebugInfoResult:
    """Debug info parsing result."""

    debug_info_header: DebugInfoHeader
    debug_string_table: List[DebugStringTableEntry]
    debug_file_regions: List[DebugFileRegion]
    debug_filenames: List[str]


@dataclass(frozen=True)
class RegExpTableEntry:
    """Regular expression table entry."""

    offset: int
    length: int


@dataclass(frozen=True)
class CJSModuleTableEntry:
    """CommonJS module table entry."""

    first: int
    second: int


@dataclass(frozen=True)
class FunctionSourceTableEntry:
    """Function source table entry."""

    function_id: int
    string_offset: int
