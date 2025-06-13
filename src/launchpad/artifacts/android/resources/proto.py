import logging
from typing import Optional

from .protos.Resources_pb2 import Type  # type: ignore[attr-defined]
from .protos.Resources_pb2 import Entry, Package  # type: ignore[attr-defined]
from .protos.Resources_pb2 import ResourceTable as PBResourceTable  # type: ignore[attr-defined]
from .resource_table import DEFAULT_PACKAGE_ID, ResourceTable

logger = logging.getLogger(__name__)


class ProtobufResourceTable(ResourceTable):
    """Implementation of ResourceTable for protobuf Android resource tables."""

    def __init__(self, buffer: bytes):
        """Initialize with a binary buffer containing the protobuf resource table."""
        self.pb_resource_table = PBResourceTable.FromString(buffer)

    @staticmethod
    def resource_id_from_string(value: str) -> int:
        """Convert a resource ID string (e.g. 'resourceId:0x7f010001') to an integer."""
        return int(value.replace("resourceId:", ""), 16)

    def get_value_by_key(self, key: str, locale: Optional[str] = None) -> Optional[str]:
        """Get a resource value by its key and optional locale."""
        type_name = "string"
        trimmed_key = key
        if "/" in key:
            splits = key.split("/")
            type_name = splits[0].replace("@", "")
            trimmed_key = splits[1]

        type = self._get_types_by_name(type_name)
        if not type:
            if type_name.startswith("android:color"):
                # Since we don't have android resources in the APK, we need to look up framework colors
                # Note: this would need to be implemented with a mapping of Android framework colors
                return None
            logger.debug("No type found in the resource package.")
            return None

        entry = next((e for e in type.entry if e.name == trimmed_key), None)
        if not entry:
            logger.debug(f"No entry found with the name {key}.")
            return None

        return self._get_default_value_from_entry(entry)

    def get_value_by_string_id(self, string_id: str) -> Optional[str]:
        """Get a resource value by its string ID (e.g. 'resourceId:0x7f010001')."""
        int_id = self.resource_id_from_string(string_id)
        return self.get_value_by_id(int_id)

    def get_value_by_id(self, id_val: int) -> Optional[str]:
        """Get a resource value by its integer ID."""
        # Type ID is the T elements of 0xPPTTEEEE
        type_id = (id_val >> 16) & 0xFF
        types = self._get_types_by_id(type_id)
        if not types:
            logger.debug(f"No types found in the resource package matching {type_id}")
            return None

        # Entry ID is the E elements of 0xPPTTEEEE
        entry_id = id_val & 0x0000FFFF
        entry = next((e for e in types.entry if e.entry_id.id == entry_id), None)
        if not entry:
            logger.debug(f"No entry found with the id {id_val}.")
            return None

        return self._get_default_value_from_entry(entry)

    def _get_application_package(self) -> Optional[Package]:
        """Get the application's resource package (package ID 0x7f)."""
        return next(
            (pkg for pkg in self.pb_resource_table.package if pkg.package_id.id == DEFAULT_PACKAGE_ID),
            None,
        )

    def _get_types_by_name(self, type_name: str) -> Optional[Type]:
        """Get resource type by name."""
        resource_package = self._get_application_package()
        if not resource_package:
            logger.debug("No resource package found in the resource table.")
            return None

        types = next((type_ for type_ in resource_package.type if type_.name == type_name), None)
        if not types:
            logger.debug(f"No types found in the resource package matching typeName: {type_name}")
            return None
        return types

    def _get_types_by_id(self, id_val: int) -> Optional[Type]:
        """Get resource type by ID."""
        resource_package = self._get_application_package()
        if not resource_package:
            logger.debug("No resource package found in the resource table.")
            return None

        types = next((type_ for type_ in resource_package.type if type_.type_id.id == id_val), None)
        if not types:
            logger.debug(f"No types found in the resource package matching id: {id_val:02x}")
            return None
        return types

    def _get_default_value_from_entry(self, entry: Entry) -> Optional[str]:
        """Get the default string value from an entry."""

        # Default entry value is the first config value with no locale
        entry_value = next(
            (cv for cv in entry.config_value if cv.config is None or cv.config.locale == ""),
            None,
        )

        if not entry_value:
            logger.debug(f"No default entry value found for entry {entry.name}.")
            return None

        if entry_value.value.HasField("item"):
            item = entry_value.value.item

            if item.HasField("str"):
                logger.debug(f"No str value found for entry {entry.name}.")
                return str(item.str.value)
            elif item.HasField("ref"):
                ref = item.ref
                if ref.name:
                    return self.get_value_by_id(ref.id)
                elif ref.id:
                    return self.get_value_by_key(ref.name)
                else:
                    logger.debug("item.value.ref.id and item.value.ref.name are not defined.")
                    return None
            elif item.HasField("file"):
                return str(item.file.path)
            elif item.HasField("prim"):
                prim = item.prim
                if prim.HasField("int_decimal_value"):
                    return str(prim.int_decimal_value)
                elif prim.HasField("boolean_value"):
                    return str(prim.boolean_value)
                elif prim.HasField("color_rgb8_value"):
                    return f"#{prim.color_rgb8_value:06x}"
                elif prim.HasField("color_argb8_value"):
                    return f"#{prim.color_argb8_value:08x}"
                else:
                    logger.debug(f"Unsupported prim value: {prim.WhichOneof('oneof_value')}")
                    return None
            else:
                logger.debug(f"Unsupported item case: {item.value.WhichOneof('value')}")
                return None
        else:
            logger.debug(f"No value found for entry {entry.name}.")
            return None
