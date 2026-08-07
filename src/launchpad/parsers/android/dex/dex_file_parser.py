from __future__ import annotations

from launchpad.parsers.android.dex.dex_base_utils import DexBaseUtils
from launchpad.parsers.android.dex.dex_class_parser import DexClassParser
from launchpad.parsers.android.dex.dex_mapping import DexMapping
from launchpad.parsers.android.dex.types import (
    ClassDefinition,
    DexStats,
)
from launchpad.parsers.buffer_wrapper import BufferWrapper
from launchpad.utils import logging

logger = logging.get_logger(__name__)


# https://source.android.com/docs/core/runtime/dex-format
class DexFileParser:
    def __init__(
        self,
        buffer: bytes,
        dex_mapping: DexMapping | None = None,
        stats: DexStats | None = None,
    ):
        self._buffer_wrapper = BufferWrapper(buffer)
        self._header = DexBaseUtils.get_header(self._buffer_wrapper)
        self._dex_mapping = dex_mapping
        self._stats = stats if stats is not None else DexStats()
        self._stats.file_count += 1
        self._stats.total_bytes += len(buffer)
        self._stats.parser_mapping_present = self._stats.parser_mapping_present or dex_mapping is not None

    def get_class_definitions(self) -> list[ClassDefinition]:
        class_defs: list[ClassDefinition] = []

        for i in range(self._header.class_defs_size):
            offset = self._header.class_defs_off + i * 32
            class_parser = DexClassParser(
                header=self._header,
                buffer_wrapper=self._buffer_wrapper,
                offset=offset,
                dex_mapping=self._dex_mapping,
                stats=self._stats,
            )

            class_definition = class_parser.parse()
            self._stats.parser_class_count += 1
            self._stats.parser_method_count += len(class_definition.methods)
            self._stats.parser_field_count += len(class_definition.fields)
            class_defs.append(class_definition)

        return class_defs
