from __future__ import annotations

from pathlib import Path

from launchpad.artifacts.android.manifest.axml import AxmlUtils
from launchpad.artifacts.android.resources.binary import BinaryResourceTable
from launchpad.parsers.android.binary.android_binary_parser import AndroidBinaryParser
from launchpad.parsers.android.binary.types import XmlNode
from launchpad.utils.logging import get_logger

from .icon_parser import IconParser

logger = get_logger(__name__)


class BinaryXmlDrawableParser(IconParser):
    def __init__(
        self,
        extract_dir: Path,
        binary_res_tables: list[BinaryResourceTable],
    ) -> None:
        super().__init__(extract_dir)
        self.binary_res_tables = binary_res_tables

    def _get_attr_value(self, attributes: list, name: str, required: bool = False) -> str | None:
        if required:
            return AxmlUtils.get_required_attr_value(attributes, name, self.binary_res_tables)  # type: ignore[arg-type]
        return AxmlUtils.get_optional_attr_value(attributes, name, self.binary_res_tables)  # type: ignore[arg-type]

    def _get_resource_path(self, resource_ref: str) -> str | None:
        return AxmlUtils.get_resource_from_binary_resource_files(resource_ref, self.binary_res_tables)

    def _parse_xml_node(self, buffer: bytes) -> XmlNode:
        return AndroidBinaryParser(buffer).parse_xml()
