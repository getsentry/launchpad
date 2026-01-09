from __future__ import annotations

from pathlib import Path

from launchpad.artifacts.android.manifest.proto_xml import ProtoXmlUtils
from launchpad.artifacts.android.resources.proto import ProtobufResourceTable
from launchpad.artifacts.android.resources.protos.Resources_pb2 import (  # type: ignore[attr-defined]
    XmlAttribute as PbXmlAttribute,
)
from launchpad.artifacts.android.resources.protos.Resources_pb2 import (
    XmlElement as PbXmlElement,
)
from launchpad.artifacts.android.resources.protos.Resources_pb2 import (
    XmlNode as PbXmlNode,  # type: ignore[attr-defined]
)
from launchpad.parsers.android.binary.types import (
    NodeType,
    TypedValue,
    XmlAttribute,
    XmlNode,
)
from launchpad.utils.logging import get_logger

from .icon_parser import IconParser

logger = get_logger(__name__)


class ProtoXmlDrawableParser(IconParser):
    def __init__(self, extract_dir: Path, proto_res_tables: list[ProtobufResourceTable]) -> None:
        super().__init__(extract_dir)
        self.proto_res_tables = proto_res_tables

    def _get_attr_value(self, attributes: list, name: str, required: bool = False) -> str | None:
        if required:
            return ProtoXmlUtils.required_attr_value_by_name(attributes, name, self.proto_res_tables)
        return ProtoXmlUtils.optional_attr_value_by_name(attributes, name, self.proto_res_tables)

    def _get_resource_path(self, resource_ref: str) -> str | None:
        # Handle different resource reference formats
        if resource_ref.startswith("@ref/"):
            # Format: @ref/0x7f05000c
            resource_ref = resource_ref.replace("@ref/", "resourceId:")
        elif resource_ref.startswith("@"):
            # Format: @drawable/icon -> try to get by key first
            for table in self.proto_res_tables:
                try:
                    value = table.get_value_by_key(resource_ref)
                    if value is not None:
                        return value
                except Exception as e:
                    logger.debug(f"Failed to get resource by key: {e}")
                    continue
            return None

        # At this point, resource_ref should be in format "resourceId:0x7f05000c"
        if not resource_ref.startswith("resourceId:"):
            logger.debug(f"Unexpected resource reference format: {resource_ref}")
            return None

        for table in self.proto_res_tables:
            try:
                value = table.get_value_by_string_id(resource_ref)
                if value is not None:
                    return value
            except Exception as e:
                logger.debug(f"Failed to get resource by string ID: {e}")
                continue

        return None

    def _parse_xml_node(self, buffer: bytes) -> XmlNode:
        pb_node = PbXmlNode.FromString(buffer)
        if not pb_node.element:
            raise ValueError("No element found in protobuf XML node")

        return self._convert_pb_element_to_xml_node(pb_node.element)

    def _convert_pb_element_to_xml_node(self, pb_element: PbXmlElement) -> XmlNode:
        # Convert attributes
        attributes = [self._convert_pb_attribute(attr) for attr in pb_element.attribute]

        # Convert child nodes
        child_nodes = []
        for child in pb_element.child:
            if child.element:
                child_nodes.append(self._convert_pb_element_to_xml_node(child.element))

        return XmlNode(
            node_type=NodeType.ELEMENT_NODE,
            node_name=pb_element.name,
            namespace_uri=(pb_element.namespace_uri if pb_element.namespace_uri else None),
            attributes=attributes,
            child_nodes=child_nodes,
        )

    def _convert_pb_attribute(self, pb_attr: PbXmlAttribute) -> XmlAttribute:
        # Extract the attribute value
        value = None
        raw_type = 0x03  # TYPE_STRING as default

        if pb_attr.value:
            value = pb_attr.value
        elif pb_attr.compiled_item:
            # Try to extract value from compiled item
            compiled_item = pb_attr.compiled_item
            if compiled_item.HasField("str"):
                value = str(compiled_item.str.value)
            elif compiled_item.HasField("ref"):
                ref = compiled_item.ref
                if ref.name:
                    value = ref.name
                elif ref.id:
                    value = f"resourceId:{ref.id:#010x}"
                raw_type = 0x01  # TYPE_REFERENCE
            elif compiled_item.HasField("prim"):
                prim = compiled_item.prim
                if prim.HasField("int_decimal_value"):
                    value = str(prim.int_decimal_value)
                    raw_type = 0x10  # TYPE_INT_DEC
                elif prim.HasField("boolean_value"):
                    value = str(prim.boolean_value).lower()
                    raw_type = 0x12  # TYPE_INT_BOOLEAN
                elif prim.HasField("color_argb8_value"):
                    value = f"#{prim.color_argb8_value:08x}"
                    raw_type = 0x1C  # TYPE_INT_COLOR_ARGB8
                elif prim.HasField("color_rgb8_value"):
                    value = f"#{prim.color_rgb8_value:06x}"
                    raw_type = 0x1D  # TYPE_INT_COLOR_RGB8

        # Create TypedValue
        typed_value = TypedValue(value=value, type="string", raw_type=raw_type)

        return XmlAttribute(
            name=pb_attr.name,
            node_type=NodeType.ATTRIBUTE_NODE,
            namespace_uri=pb_attr.namespace_uri if pb_attr.namespace_uri else None,
            node_name=pb_attr.name,
            typed_value=typed_value,
            value=value,
        )
