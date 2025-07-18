"""DEX file parser for Android applications."""

from __future__ import annotations

from launchpad.parsers.android.dex.dex_base_utils import DexBaseUtils
from launchpad.parsers.android.dex.dex_class_parser import DexClassParser
from launchpad.parsers.android.dex.dex_mapping import DexMapping
from launchpad.parsers.android.dex.types import (
    ClassDefinition,
)
from launchpad.parsers.buffer_wrapper import BufferWrapper
from launchpad.utils import logging

logger = logging.get_logger(__name__)


# https://source.android.com/docs/core/runtime/dex-format
class DexFileParser:
    def __init__(self, buffer: bytes, dex_mapping: DexMapping | None = None):
        self._buffer_wrapper = BufferWrapper(buffer)
        self._header = DexBaseUtils.get_header(self._buffer_wrapper)
        self._dex_mapping = dex_mapping

    def get_class_definitions(self) -> list[ClassDefinition]:
        class_defs: list[ClassDefinition] = []

        for i in range(self._header.class_defs_size):
            offset = self._header.class_defs_off + i * 32
            class_parser = DexClassParser(
                header=self._header,
                buffer_wrapper=self._buffer_wrapper,
                offset=offset,
                dex_mapping=self._dex_mapping,
            )

            class_defs.append(class_parser.parse())

        return class_defs
