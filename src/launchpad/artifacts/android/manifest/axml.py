"""Utilities for parsing Android binary XML format."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence

from launchpad.parsers.android.android_binary_parser import AndroidBinaryParser

from ..resources.binary import BinaryResourceTable
from .manifest import AndroidApplication, AndroidManifest

logger = logging.getLogger(__name__)


@dataclass
class XmlAttribute:
    """Represents an XML attribute in binary format."""

    name: str
    value: Optional[str]
    typed_value: Optional[Any] = None


@dataclass
class XmlNode:
    """Represents an XML node in binary format."""

    node_name: str
    attributes: Sequence[XmlAttribute]
    child_nodes: Sequence[XmlNode]


class BinaryXmlParser:
    """Parser for Android binary XML format."""

    def __init__(self, buffer: bytes) -> None:
        """Initialize parser with binary buffer.

        Args:
            buffer: Raw bytes of the binary XML file
        """
        self.buffer = buffer

    def parse_xml(self) -> Optional[XmlNode]:
        """Parse the binary XML into a tree of nodes.

        Returns:
            Root XML node if parsing successful, None otherwise
        """
        try:
            parser = AndroidBinaryParser(self.buffer)
            parsed_node = parser.parse_xml()

            if not parsed_node:
                logger.error("Could not parse binary XML - no root node found")
                return None

            # Convert the parser's XmlNode to our model's XmlNode
            def convert_node(node) -> XmlNode:  # type: ignore[no-untyped-def]
                attributes = []
                for attr in node.attributes:
                    value = attr.value
                    typed_value = attr.typed_value

                    # Handle resource references and typed values
                    if not value and typed_value:
                        if typed_value.type == "reference":
                            # Resource references will be resolved later by AxmlUtils
                            value = typed_value.value
                        elif typed_value.type in ["int_dec", "boolean"]:
                            value = str(typed_value.value)
                        elif typed_value.type == "dimension":
                            value = f"{typed_value.value.value}{typed_value.value.unit}"
                        elif typed_value.type in ["rgb8", "argb8"]:
                            value = f"#{typed_value.value:x}"
                        elif typed_value.type == "string":
                            value = typed_value.value
                        elif typed_value.type == "unknown":
                            # Convert IEEE 754 integer representation to float
                            import struct

                            float_view = struct.unpack("<f", struct.pack("<I", typed_value.value))[0]
                            value = str(float_view)

                    attributes.append(XmlAttribute(name=attr.name, value=value, typed_value=typed_value))

                # Recursively convert child nodes
                child_nodes = [convert_node(child) for child in node.child_nodes]

                return XmlNode(node_name=node.node_name, attributes=attributes, child_nodes=child_nodes)

            return convert_node(parsed_node)

        except Exception as e:
            logger.error(f"Failed to parse binary XML: {e}")
            return None


class AxmlUtils:
    """Utility functions for working with Android binary XML."""

    @staticmethod
    def binary_xml_to_android_manifest(
        buffer: bytes, binary_resource_tables: List[BinaryResourceTable]
    ) -> AndroidManifest:
        """Convert binary XML buffer to AndroidManifest.

        Args:
            buffer: Raw bytes of the binary XML file
            binary_resource_tables: List of resource tables for resolving references

        Returns:
            Parsed Android manifest

        Raises:
            ValueError: If manifest cannot be parsed or required fields are missing
        """
        xml_node = BinaryXmlParser(buffer).parse_xml()
        if not xml_node:
            raise ValueError("Could not load binary manifest for APK")

        manifest_attributes = xml_node.attributes
        package_name = AxmlUtils.get_required_attr_value(manifest_attributes, "package", binary_resource_tables)
        version_name = AxmlUtils.get_optional_attr_value(manifest_attributes, "versionName", binary_resource_tables)
        version_code = AxmlUtils.get_optional_attr_value(manifest_attributes, "versionCode", binary_resource_tables)

        uses_sdk_element = next((node for node in xml_node.child_nodes if node.node_name == "uses-sdk"), None)

        # Default to 1 since Android assumes 1 if not specified
        min_sdk_str = (
            AxmlUtils.get_optional_attr_value(uses_sdk_element.attributes, "minSdkVersion", binary_resource_tables)
            if uses_sdk_element
            else "1"
        )
        min_sdk_version = int(min_sdk_str)  # type: ignore[arg-type]

        # Get list of permissions
        permissions = [
            attr.value
            for node in xml_node.child_nodes
            if node.node_name == "uses-permission"
            for attr in node.attributes
            if attr.name == "name" and attr.value
        ]

        application_element = next((node for node in xml_node.child_nodes if node.node_name == "application"), None)
        if not application_element:
            raise ValueError("Could not find application element in binary manifest")

        icon_path = AxmlUtils.get_optional_attr_value(application_element.attributes, "icon", binary_resource_tables)
        label = AxmlUtils.get_optional_attr_value(application_element.attributes, "label", binary_resource_tables)
        uses_cleartext_traffic = (
            AxmlUtils.get_optional_attr_value(
                application_element.attributes, "usesCleartextTraffic", binary_resource_tables
            )
            == "true"
        )

        # Find meta-data node with Reaper instrumented name
        metadata_nodes = [node for node in application_element.child_nodes if node.node_name == "meta-data"]
        reaper_metadata = next(
            (
                node
                for node in metadata_nodes
                if AxmlUtils.get_optional_attr_value(node.attributes, "name", binary_resource_tables)
                == "com.emergetools.reaper.REAPER_INSTRUMENTED"
            ),
            None,
        )
        emerge_reaper_instrumented = reaper_metadata is not None and any(
            attr.name == "value" and attr.value == "true" for attr in reaper_metadata.attributes
        )

        return AndroidManifest(
            package_name=package_name,
            version_name=version_name,
            version_code=version_code,
            min_sdk_version=min_sdk_version,
            permissions=permissions,
            application=AndroidApplication(
                icon_path=icon_path,
                label=label,
                uses_cleartext_traffic=uses_cleartext_traffic,
                reaper_instrumented=emerge_reaper_instrumented,
            ),
            is_feature_split=False,  # Not relevant for binary XML parsing from APKs
        )

    @staticmethod
    def get_optional_attr_value(
        attributes: Sequence[XmlAttribute], name: str, binary_res_tables: List[BinaryResourceTable]
    ) -> Optional[str]:
        """Get optional attribute value, resolving resource references if needed.

        Args:
            attributes: List of XML attributes
            name: Name of attribute to find
            binary_res_tables: List of resource tables for resolving references

        Returns:
            Attribute value if found and resolved, None otherwise
        """
        attribute = next((attr for attr in attributes if attr.name == name), None)

        if not attribute:
            logger.debug("Could not find attribute with name: %s", name)
            return None

        value = attribute.value
        if not value:
            logger.debug("Could not find string value for attribute with name: %s, trying to parse typedValue", name)

            if not attribute.typed_value:
                logger.debug("Could not find typedValue for attribute with name: %s", name)
                return None

            typed_value = attribute.typed_value
            if typed_value.type == "string":
                return str(typed_value.value)
            elif typed_value.type == "reference":
                return AxmlUtils.get_resource_from_binary_resource_files(typed_value.value, binary_res_tables)
            elif typed_value.type == "int_dec":
                return str(typed_value.value)
            elif typed_value.type == "dimension":
                return f"{typed_value.value.value}{typed_value.value.unit}"
            elif typed_value.type in ["rgb8", "argb8"]:
                return f"#{typed_value.value:x}"
            elif typed_value.type == "boolean":
                return str(typed_value.value)
            elif typed_value.type == "unknown":
                # Convert IEEE 754 integer representation to float
                import struct

                float_view = struct.unpack("<f", struct.pack("<I", typed_value.value))[0]
                return str(float_view)
            else:
                logger.debug("Unsupported typedValue type: %s", typed_value.type)
                return None

        # Special handling for string references
        if value.startswith("resourceId:"):
            return AxmlUtils.get_resource_from_binary_resource_files(value, binary_res_tables)

        return value

    @staticmethod
    def get_required_attr_value(
        attributes: Sequence[XmlAttribute], name: str, binary_res_tables: List[BinaryResourceTable]
    ) -> str:
        """Get required attribute value, raising error if not found.

        Args:
            attributes: List of XML attributes
            name: Name of attribute to find
            binary_res_tables: List of resource tables for resolving references

        Returns:
            Attribute value if found and resolved

        Raises:
            ValueError: If attribute not found or cannot be resolved
        """
        value = AxmlUtils.get_optional_attr_value(attributes, name, binary_res_tables)
        if value is None:
            raise ValueError(f"Missing required attribute: {name}")
        return value

    @staticmethod
    def get_resource_from_binary_resource_files(
        value: str, binary_res_tables: List[BinaryResourceTable]
    ) -> Optional[str]:
        """Get resource value from binary resource tables.

        Args:
            value: Resource ID string (e.g. "resourceId:0x7f010001")
            binary_res_tables: List of resource tables to search

        Returns:
            Resolved resource value if found, None otherwise
        """
        # Try each table until we find a value
        for table in binary_res_tables:
            try:
                return table.get_value_by_string_id(value)
            except Exception as e:
                logger.debug("Failed to get value from table: %s", e)
                continue
        return None
