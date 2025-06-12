from dataclasses import dataclass
from typing import List, Optional

from launchpad.parsers.android_binary.android_binary_parser import AndroidBinaryParser
from launchpad.parsers.android_binary.types import ResourceTablePackage, ResourceTableType, TypedValue

# Default package id for app package is 0x7f
DEFAULT_PACKAGE_ID = 0x7F


@dataclass(frozen=True)
class ResourceTable:
    """Interface for resource table implementations."""

    def get_value_by_key(self, key: str, locale: Optional[str] = None) -> Optional[str]:
        """Get a resource value by its key and optional locale."""
        raise NotImplementedError()

    def get_value_by_id(self, id_val: int) -> Optional[str]:
        """Get a resource value by its ID."""
        raise NotImplementedError()


class BinaryResourceTable(ResourceTable):
    """Implementation of ResourceTable for binary Android resource tables."""

    def __init__(self, buffer: bytes):
        """Initialize with a binary buffer containing the resource table."""
        self.binary_parser = AndroidBinaryParser(buffer)
        self.binary_parser.parse_resource_table()

    @staticmethod
    def resource_id_from_string(value: str) -> int:
        """Convert a resource ID string (e.g. 'resourceId:0x7f010001') to an integer."""
        return int(value.replace("resourceId:", ""), 16)

    def get_value_by_key(self, key: str, locale: Optional[str] = None) -> Optional[str]:
        """Get a resource value by its key and optional locale."""
        app_package = self._get_application_package()
        if not app_package:
            raise ValueError("No app package found in the resource table.")

        # Find string type with matching locale
        strings = next(
            (
                type_
                for type_ in app_package.types
                if type_.name == "string"
                and (not locale or type_.config.language == locale)
                and type_.config.region == ""
            ),
            None,
        )
        if not strings:
            raise ValueError("No string type found in the app package.")

        # Find entry with matching key
        entry = next((e for e in strings.entries if e.key == key), None)
        if not entry:
            raise ValueError(f"No string entry found with the name {key}.")

        if not entry.value:
            raise ValueError(f"No value found for entry with key {key}.")

        return self._resolve_value(entry.value)

    def get_value_by_string_id(self, string_id: str) -> Optional[str]:
        """Get a resource value by its string ID (e.g. 'resourceId:0x7f010001')."""
        int_id = self.resource_id_from_string(string_id)
        return self.get_value_by_id(int_id)

    def get_value_by_id(self, id_val: int) -> Optional[str]:
        """Get a resource value by its integer ID."""
        type_id = (id_val >> 16) & 0xFF
        types = self._get_types_by_id(type_id)
        if not types:
            raise ValueError(f"No type found in the resource table matching {type_id}")

        entry_id = id_val & 0x0000FFFF
        # Types are based on configuration, but since ids appear to be unique across
        # different configs, we can just take the first match
        entry = next(
            (e for type_ in types for e in type_.entries if e.id == entry_id),
            None,
        )

        if not entry:
            raise ValueError(f"No entry found with the id {entry_id:04x}.")

        if not entry.value:
            raise ValueError(f"No value found for entry with id {entry_id:04x}.")

        return self._resolve_value(entry.value)

    def _get_application_package(self) -> Optional[ResourceTablePackage]:
        """Get the application's resource package (package ID 0x7f)."""
        return next(
            (pkg for pkg in self.binary_parser.packages if pkg.id == DEFAULT_PACKAGE_ID),
            None,
        )

    def _get_types_by_id(self, id_val: int) -> List[ResourceTableType]:
        """Get all resource types with the given ID."""
        resource_package = self._get_application_package()
        if not resource_package:
            print("No resource package found in the resource table.")
            return []

        types = [type_ for type_ in resource_package.types if type_.id == id_val]
        if not types:
            print(f"No types found in the resource package matching id: {id_val:02x}")
            return []
        return types

    def _resolve_value(self, value: TypedValue) -> Optional[str]:
        """Resolve a typed value to its string representation."""
        if value.type == "string":
            return str(value.value)
        elif value.type == "reference":
            return self.get_value_by_string_id(value.value)
        elif value.type == "rgb8":
            return f"#{value.value:06x}"
        elif value.type == "argb8":
            return f"#{value.value:08x}"
        elif value.type == "rgb4":
            return f"#{value.value:03x}"
        elif value.type == "argb4":
            return f"#{value.value:04x}"
        elif value.type == "int_dec":
            return str(value.value)
        elif value.type == "int_hex":
            return f"0x{value.value:x}"
        elif value.type == "boolean":
            return str(bool(value.value))
        elif value.type == "dimension":
            return f"{value.value.value}{value.value.unit}"
        elif value.type == "fraction":
            return f"{value.value.value}{value.value.type}"
        elif value.type == "null":
            return None
        else:
            raise ValueError(f"Unsupported value type: {value.type}")
