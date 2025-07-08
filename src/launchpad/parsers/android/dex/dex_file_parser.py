"""DEX file parser for Android applications."""

from __future__ import annotations

from launchpad.parsers.android.dex.dex_base_utils import DexBaseUtils
from launchpad.parsers.android.dex.dex_class_parser import DexClassParser
from launchpad.parsers.android.dex.types import (
    ClassDefinition,
)
from launchpad.parsers.buffer_wrapper import BufferWrapper
from launchpad.utils import logging

logger = logging.get_logger(__name__)


# https://source.android.com/docs/core/runtime/dex-format
class DexFileParser:
    @staticmethod
    def get_class_definitions(buffer: bytes) -> list[ClassDefinition]:
        class_defs: list[ClassDefinition] = []

        buffer_wrapper = BufferWrapper(buffer)
        header = DexBaseUtils.get_header(buffer_wrapper)
        class_parser = DexClassParser(header, buffer_wrapper)

        for i in range(header.class_defs_size):
            class_defs.append(class_parser.parse(i))

        return class_defs
