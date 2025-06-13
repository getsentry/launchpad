"""Utilities for parsing Android protobuf XML format."""

from __future__ import annotations

import logging
from typing import Any, Callable, List, Optional, Sequence

from ..resources.proto import ProtobufResourceTable
from ..resources.protos.Resources_pb2 import XmlAttribute, XmlElement  # type: ignore[attr-defined]
from ..resources.protos.Resources_pb2 import XmlNode as PbXmlNode  # type: ignore[attr-defined]
from .manifest import AndroidApplication, AndroidManifest, DeliveryType

logger = logging.getLogger(__name__)


class ProtoXmlUtils:
    """Utility functions for working with Android protobuf XML."""

    # Resource IDs for common manifest attributes
    # Find constant values at https://stuff.mit.edu/afs/sipb/project/android/docs/reference/android/R.attr.html
    VERSION_NAME_RESOURCE_ID = 0x0101021C
    VERSION_CODE_RESOURCE_ID = 0x0101021C
    MIN_SDK_VERSION_RESOURCE_ID = 0x0101020C
    ICON_RESOURCE_ID = 0x01010254
    LABEL_RESOURCE_ID = 0x01010001

    @staticmethod
    def proto_xml_to_android_manifest(
        manifest_xml_content: bytes, proto_res_tables: List[ProtobufResourceTable]
    ) -> AndroidManifest:
        """Convert protobuf XML buffer to AndroidManifest.

        Args:
            name: Name of the manifest file
            manifest_xml_content: Raw bytes of the protobuf XML file
            proto_res_tables: List of resource tables for resolving references

        Returns:
            Parsed Android manifest

        Raises:
            ValueError: If manifest cannot be parsed or required fields are missing
        """
        xml_element = PbXmlNode.FromString(manifest_xml_content).element
        if not xml_element:
            raise ValueError("Could not load protobuf manifest for AAB")

        manifest_attributes = xml_element.attribute
        package_name = ProtoXmlUtils.required_attr_value_by_name(manifest_attributes, "package", proto_res_tables)
        split = ProtoXmlUtils.optional_attr_value_by_name(manifest_attributes, "split", proto_res_tables)
        is_feature_split = (
            ProtoXmlUtils.optional_attr_value_by_name(manifest_attributes, "isFeatureSplit", proto_res_tables) == "true"
        )

        version_name = ProtoXmlUtils.optional_attr_value_with_fallback(
            manifest_attributes, proto_res_tables, "versionName", ProtoXmlUtils.VERSION_NAME_RESOURCE_ID
        )
        version_code = ProtoXmlUtils.optional_attr_value_with_fallback(
            manifest_attributes, proto_res_tables, "versionCode", ProtoXmlUtils.VERSION_CODE_RESOURCE_ID
        )

        uses_sdk_element = next((node.element for node in xml_element.child if node.element.name == "uses-sdk"), None)
        if not uses_sdk_element:
            raise ValueError("Could not find uses-sdk element in manifest")

        # Default to 1 since Android assumes 1 if not specified
        min_sdk_str = (
            ProtoXmlUtils.optional_attr_value_with_fallback(
                uses_sdk_element.attribute,
                proto_res_tables,
                "minSdkVersion",
                ProtoXmlUtils.MIN_SDK_VERSION_RESOURCE_ID,
            )
            or "1"
        )
        min_sdk_version = int(min_sdk_str)

        # Get list of permissions
        permissions = [
            attr.value
            for node in xml_element.child
            if node.element.name == "uses-permission"
            for attr in node.element.attribute
            if attr.name == "name" and attr.value
        ]

        application_element = next(
            (node.element for node in xml_element.child if node.element.name == "application"), None
        )
        application = None
        if application_element and application_element.attribute:
            application = AndroidApplication(
                icon_path=ProtoXmlUtils.optional_attr_value_with_fallback(
                    application_element.attribute,
                    proto_res_tables,
                    "icon",
                    ProtoXmlUtils.ICON_RESOURCE_ID,
                ),
                label=ProtoXmlUtils.optional_attr_value_with_fallback(
                    application_element.attribute,
                    proto_res_tables,
                    "label",
                    ProtoXmlUtils.LABEL_RESOURCE_ID,
                ),
                uses_cleartext_traffic=(
                    ProtoXmlUtils.optional_attr_value_by_name(
                        application_element.attribute, "usesCleartextTraffic", proto_res_tables
                    )
                    == "true"
                ),
            )

        # Handle module element if present
        module_element = next((node.element for node in xml_element.child if node.element.name == "module"), None)
        module = None
        if module_element and module_element.attribute:
            module = ProtoXmlUtils._parse_module_element(
                module_element, application, split, is_feature_split, proto_res_tables
            )

        return AndroidManifest(
            package_name=package_name,
            split=split,
            version_name=version_name,
            version_code=version_code,
            min_sdk_version=min_sdk_version,
            is_feature_split=is_feature_split,
            permissions=permissions,
            application=application,
            module=module,
        )

    @staticmethod
    def _parse_module_element(
        module_element: XmlElement,
        application: Optional[AndroidApplication],
        split: Optional[str],
        is_feature_split: bool,
        proto_res_tables: List[ProtobufResourceTable],
    ) -> Optional[Any]:
        """Parse module element from manifest."""
        module_attributes = module_element.attribute
        is_instant = ProtoXmlUtils.optional_attr_value_by_name(module_attributes, "instant", proto_res_tables) == "true"

        # Find delivery element
        delivery_element = next(
            (node.element for node in module_element.child if node.element.name == "delivery"), None
        )
        delivery_type = None

        if delivery_element:
            # Check for delivery type elements
            on_demand = next(
                (node.element for node in delivery_element.child if node.element.name == DeliveryType.ON_DEMAND.value),
                None,
            )
            install_time = next(
                (
                    node.element
                    for node in delivery_element.child
                    if node.element.name == DeliveryType.INSTALL_TIME.value
                ),
                None,
            )
            fast_follow = next(
                (
                    node.element
                    for node in delivery_element.child
                    if node.element.name == DeliveryType.FAST_FOLLOW.value
                ),
                None,
            )

            if on_demand:
                delivery_type = DeliveryType.ON_DEMAND
            elif install_time:
                delivery_type = DeliveryType.INSTALL_TIME
            elif fast_follow:
                delivery_type = DeliveryType.FAST_FOLLOW
            else:
                logger.warning(f"Unknown delivery type for module {delivery_element.child}, defaulting to INSTALL_TIME")
                delivery_type = DeliveryType.INSTALL_TIME
        elif module_attributes:
            # Try to find delivery type from attributes
            on_demand_value = ProtoXmlUtils.optional_attr_value_by_name(module_attributes, "onDemand", proto_res_tables)
            if on_demand_value == "true":
                delivery_type = DeliveryType.ON_DEMAND
            else:
                logger.warning("Unknown delivery type for module element, defaulting to INSTALL_TIME")
                delivery_type = DeliveryType.INSTALL_TIME

        if not delivery_type:
            raise ValueError(f"No delivery type found for module element {module_element.child}, {delivery_element}")

        # Get title based on delivery type
        title = None
        if delivery_type == DeliveryType.INSTALL_TIME:
            title = application.label if application else None
            if not title:
                if split:
                    title = split
                elif is_instant:
                    title = "Instant App"
                else:
                    raise ValueError("No title found for module element")
        else:
            title = ProtoXmlUtils.required_attr_value_by_name(module_attributes, "title", proto_res_tables)

        return {
            "title": title,
            "instant": is_instant,
            "delivery": delivery_type,
        }

    @staticmethod
    def optional_attr_value_with_fallback(
        attributes: Sequence[XmlAttribute],
        proto_res_tables: List[ProtobufResourceTable],
        name: str,
        resource_id: int,
    ) -> Optional[str]:
        """Get optional attribute value with fallback to resource ID.

        Args:
            attributes: List of XML attributes
            proto_res_tables: List of resource tables for resolving references
            name: Name of attribute to find
            resource_id: Resource ID to fall back to if name not found

        Returns:
            Attribute value if found and resolved, None otherwise
        """
        logger.debug(f"optionalAttrValueWithFallback: {name}, {resource_id:02x}")

        attr_value = ProtoXmlUtils.optional_attr_value_by_name(attributes, name, proto_res_tables)

        if not attr_value:
            logger.debug("could not find attribute by name, trying to find by resourceId")
            attr_value = ProtoXmlUtils.optional_attr_value_by_resource_id(attributes, resource_id, proto_res_tables)

        return attr_value

    @staticmethod
    def optional_attr_value_by_name(
        attributes: Sequence[XmlAttribute],
        name: str,
        proto_res_tables: List[ProtobufResourceTable],
    ) -> Optional[str]:
        """Get optional attribute value by name.

        Args:
            attributes: List of XML attributes
            name: Name of attribute to find
            proto_res_tables: List of resource tables for resolving references

        Returns:
            Attribute value if found and resolved, None otherwise
        """
        return ProtoXmlUtils._get_optional_attr_value(attributes, proto_res_tables, lambda attr: attr.name == name)

    @staticmethod
    def required_attr_value_by_name(
        attributes: Sequence[XmlAttribute],
        name: str,
        proto_res_tables: List[ProtobufResourceTable],
    ) -> str:
        """Get required attribute value by name.

        Args:
            attributes: List of XML attributes
            name: Name of attribute to find
            proto_res_tables: List of resource tables for resolving references

        Returns:
            Attribute value if found and resolved

        Raises:
            ValueError: If attribute not found or cannot be resolved
        """
        attr = ProtoXmlUtils._get_optional_attr_value(attributes, proto_res_tables, lambda attr: attr.name == name)
        if not attr:
            raise ValueError(f"Missing required attribute: {name}")
        return attr

    @staticmethod
    def optional_attr_value_by_resource_id(
        attributes: Sequence[XmlAttribute],
        resource_id: int,
        proto_res_tables: List[ProtobufResourceTable],
    ) -> Optional[str]:
        """Get optional attribute value by resource ID.

        Args:
            attributes: List of XML attributes
            resource_id: Resource ID to find
            proto_res_tables: List of resource tables for resolving references

        Returns:
            Attribute value if found and resolved, None otherwise
        """
        return ProtoXmlUtils._get_optional_attr_value(
            attributes, proto_res_tables, lambda attr: attr.resource_id == resource_id
        )

    @staticmethod
    def _get_optional_attr_value(
        attributes: Sequence[XmlAttribute],
        proto_res_tables: List[ProtobufResourceTable],
        attr_filter: Callable[[XmlAttribute], bool],
    ) -> Optional[str]:
        """Get optional attribute value using a filter function.

        Args:
            attributes: List of XML attributes
            proto_res_tables: List of resource tables for resolving references
            attr_filter: Function to filter attributes

        Returns:
            Attribute value if found and resolved, None otherwise
        """
        attribute = next((attr for attr in attributes if attr_filter(attr)), None)

        if not attribute:
            logger.debug("could not find attribute matching filter")
            return None

        value = attribute.value
        if not value:
            logger.debug("could not find string value for attribute matching filter, trying to parse compiled value")

            if not attribute.compiled_item:
                logger.debug("could not find compiledItem for attribute matching filter")
                return None

            compiled_item = attribute.compiled_item
            if compiled_item.HasField("str"):
                return str(compiled_item.str.value)
            elif compiled_item.HasField("ref"):
                ref = compiled_item.ref
                if ref.HasField("name"):
                    return ProtoXmlUtils._get_resource_by_key_from_proto_resource_files(ref.name, proto_res_tables)
                elif ref.HasField("id"):
                    return ProtoXmlUtils._get_resource_by_id_from_proto_resource_files(ref.id, proto_res_tables)
                else:
                    logger.error("item.value.ref.id and item.value.ref.name are not defined")
                    return None
            elif compiled_item.HasField("prim"):
                prim = compiled_item.prim
                if prim.HasField("int_decimal_value"):
                    return str(prim.int_decimal_value)
                elif prim.HasField("boolean_value"):
                    return str(prim.boolean_value)
                else:
                    logger.debug(f"could not find primitive value unknown type: {prim.WhichOneof('oneof_value')}")
                    return None
            else:
                logger.debug(
                    f"could not find string value for attribute, unknown type: {compiled_item.WhichOneof('value')}"
                )
                return None

        # Special handling for string references
        if value.startswith("@"):
            return ProtoXmlUtils._get_resource_by_key_from_proto_resource_files(value, proto_res_tables)

        return str(value)

    @staticmethod
    def _get_resource_by_key_from_proto_resource_files(
        key: str, res_tables: List[ProtobufResourceTable]
    ) -> Optional[str]:
        """Get resource value by key from protobuf resource tables.

        Args:
            key: Resource key to find
            res_tables: List of resource tables to search

        Returns:
            Resource value if found, None otherwise
        """
        for table in res_tables:
            try:
                value = table.get_value_by_key(key)
                if value is not None:
                    return value
            except Exception as e:
                logger.debug(f"failed to get value by key: {e}")
                continue
        return None

    @staticmethod
    def _get_resource_by_id_from_proto_resource_files(
        id_val: int, res_tables: List[ProtobufResourceTable]
    ) -> Optional[str]:
        """Get resource value by ID from protobuf resource tables.

        Args:
            id_val: Resource ID to find
            res_tables: List of resource tables to search

        Returns:
            Resource value if found, None otherwise
        """
        for table in res_tables:
            try:
                value = table.get_value_by_id(id_val)
                if value is not None:
                    return value
            except Exception as e:
                logger.debug(f"failed to get value by id: {e}")
                continue
        return None
