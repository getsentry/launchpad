"""Simple data model for binary components used in size analysis."""

from __future__ import annotations

from enum import Enum


class BinaryTag(Enum):
    """Enum for categorizing binary content types."""

    # String categories
    CFSTRINGS = "cfstrings"
    SWIFT_FILE_PATHS = "swift_file_paths"
    METHOD_SIGNATURES = "method_signatures"
    OBJC_TYPE_STRINGS = "objc_type_strings"
    C_STRINGS = "c_strings"

    # Header and metadata
    HEADERS = "headers"
    LOAD_COMMANDS = "load_commands"

    # Executable code
    TEXT_SEGMENT = "text_segment"
    FUNCTION_STARTS = "function_starts"
    EXTERNAL_METHODS = "external_methods"

    # Code signature
    CODE_SIGNATURE = "code_signature"

    # DYLD info categories
    DYLD = "dyld"  # Parent category for all DYLD-related ranges
    DYLD_REBASE = "dyld_rebase"
    DYLD_BIND = "dyld_bind"
    DYLD_LAZY_BIND = "dyld_lazy_bind"
    DYLD_EXPORTS = "dyld_exports"
    DYLD_FIXUPS = "dyld_fixups"
    DYLD_STRING_TABLE = "dyld_string_table"

    # Binary modules/classes
    OBJC_CLASSES = "objc_classes"
    SWIFT_METADATA = "swift_metadata"
    BINARY_MODULES = "binary_modules"

    # Data sections
    DATA_SEGMENT = "data_segment"
    CONST_DATA = "const_data"

    # Unwind and debug info
    UNWIND_INFO = "unwind_info"
    DEBUG_INFO = "debug_info"

    OTHER = "other"

    # Unmapped regions
    UNMAPPED = "unmapped"
