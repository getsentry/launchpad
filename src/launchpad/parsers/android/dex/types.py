"""Types for DEX file parsing."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any


@dataclass
class DexFileHeader:
    class_defs_size: int
    class_defs_off: int
    string_ids_off: int
    type_ids_off: int
    field_ids_off: int
    proto_ids_off: int
    method_ids_off: int


@dataclass
class Prototype:
    shorty_descriptor: str
    return_type: str
    parameters: list[str]


@dataclass
class Parameter:
    name: str
    type: str
    annotations: list[Annotation]


@dataclass
class Annotation:
    type_name: str
    elements: dict[str, Any]
    parameter_index: int | None = None


@dataclass
class MethodAnnotation:
    method_index: int
    annotations_offset: int


@dataclass
class ParameterAnnotation:
    method_index: int
    annotations_offset: int


@dataclass
class AnnotationsDirectory:
    class_annotations_offset: int
    method_annotations: list[MethodAnnotation]
    parameter_annotations: list[ParameterAnnotation]


@dataclass
class Method:
    class_signature: str
    prototype: Prototype
    name: str
    annotations: list[Annotation] | None = None
    access_flags: list[AccessFlag] | None = None
    parameters: list[Parameter] | None = None


@dataclass
class ClassDefinition:
    signature: str
    source_file_name: str | None
    annotations: list[Annotation]
    methods: list[Method]
    access_flags: list[AccessFlag]
    superclass: ClassDefinition | None
    interfaces: list[ClassDefinition]
    # Size information for private size calculation
    _class_data_offset: int = 0
    _static_values_offset: int = 0

    def fqn(self) -> str:
        signature = self.signature

        # Remove leading 'L' and trailing ';' if they exist
        if signature.startswith("L"):
            signature = signature[1:]
        if signature.endswith(";"):
            signature = signature[:-1]

        # Replace '/' with '.'
        return signature.replace("/", ".")

    def get_name(self) -> str:
        return self.fqn().split(".")[-1]

    def get_size(self) -> int:
        """Calculate the private size of this class definition.

        Based on the reference implementation from smali/dexlib2:
        https://github.com/JesusFreke/smali/blob/2771eae0a11f07bd892732232e6ee4e32437230d/dexlib2/src/main/java/org/jf/dexlib2/dexbacked/DexBackedClassDef.java#L505

        Returns:
            Size in bytes
        """
        # Class definition item is 32 bytes
        size = 32

        # Add size for interfaces if present
        if self.interfaces:
            # type_list_item: 4 bytes for size + 2 bytes per type index
            size += 4 + len(self.interfaces) * 2

        # Add size for annotations directory if present
        if self.annotations:
            # annotations_directory_item: 16 bytes base + variable size for annotations
            size += 16
            # Add size for each annotation
            for annotation in self.annotations:
                # annotation_item: 1 byte visibility + variable size for annotation
                size += 1 + self._get_annotation_size(annotation)

        # Add size for class data if present
        if self._class_data_offset != 0:
            # class_data_item: variable size based on fields and methods
            size += self._get_class_data_size()

        # Add size for static values if present
        if self._static_values_offset != 0:
            # encoded_array_item: variable size
            size += self._get_static_values_size()

        return size

    def _get_annotation_size(self, annotation: Annotation) -> int:
        """Calculate size of an annotation item."""
        # type_index (uleb128) + element_count (uleb128) + elements
        size = self._uleb128_size(annotation.type_name) + 1  # Approximate type_index size

        # Add size for each element
        for name, value in annotation.elements.items():
            # name_index (uleb128) + encoded_value
            size += self._uleb128_size(name) + self._get_encoded_value_size(value)

        return size

    def _get_encoded_value_size(self, value: Any) -> int:
        """Calculate size of an encoded value."""
        if value is None:
            return 1  # NULL value is 1 byte
        elif isinstance(value, bool):
            return 1  # BOOLEAN value is 1 byte
        elif isinstance(value, int):
            if -128 <= value <= 127:
                return 2  # BYTE: 1 byte type + 1 byte value
            elif -32768 <= value <= 32767:
                return 3  # SHORT: 1 byte type + 2 bytes value
            else:
                return 5  # INT: 1 byte type + 4 bytes value
        elif isinstance(value, float):
            return 5  # FLOAT: 1 byte type + 4 bytes value
        elif isinstance(value, str):
            return 5  # STRING: 1 byte type + 4 bytes index
        elif isinstance(value, list):
            # ARRAY: 1 byte type + uleb128 size + sum of element sizes
            size = 2  # 1 byte type + 1 byte size (approximate)
            for element in value:
                size += self._get_encoded_value_size(element)
            return size
        else:
            return 5  # Default to 5 bytes for unknown types

    def _get_class_data_size(self) -> int:
        """Calculate size of class data item."""
        # This is a simplified calculation - in practice, this would require
        # parsing the actual class data structure
        size = 0

        # static_fields_size + instance_fields_size + direct_methods_size + virtual_methods_size
        # All are uleb128 values
        size += 4  # Approximate size for 4 uleb128 values

        # Add size for fields and methods (simplified)
        # In practice, this would require parsing the actual encoded data
        size += len(self.methods) * 8  # Approximate size per method

        return size

    def _get_static_values_size(self) -> int:
        """Calculate size of static values array."""
        # This is a simplified calculation
        return 4  # Minimum size for encoded_array_item

    def _uleb128_size(self, value: str) -> int:
        """Calculate the size of a uleb128 encoded value."""
        # Simplified calculation - in practice this would be the actual encoded size
        return 1


class EncodedValueType(IntEnum):
    """Encoded value types for DEX format."""

    BYTE = 0x00
    SHORT = 0x02
    CHAR = 0x03
    INT = 0x04
    LONG = 0x06
    FLOAT = 0x10
    DOUBLE = 0x11
    METHOD_TYPE = 0x15
    METHOD_HANDLE = 0x16
    STRING = 0x17
    TYPE = 0x18
    FIELD = 0x19
    METHOD = 0x1A
    ENUM = 0x1B
    ARRAY = 0x1C
    ANNOTATION = 0x1D
    NULL = 0x1E
    BOOLEAN = 0x1F


class AnnotationVisibility(IntEnum):
    """Annotation visibility types."""

    BUILD = 0x00
    RUNTIME = 0x01
    SYSTEM = 0x02


class AccessFlag(IntEnum):
    """Access flags for classes, methods, and fields."""

    PUBLIC = 0x1
    PRIVATE = 0x2
    PROTECTED = 0x4
    STATIC = 0x8
    FINAL = 0x10
    SYNCHRONIZED = 0x20
    VOLATILE = 0x40
    BRIDGE = 0x40
    TRANSIENT = 0x80
    VARARGS = 0x80
    NATIVE = 0x100
    INTERFACE = 0x200
    ABSTRACT = 0x400
    STRICT = 0x800
    SYNTHETIC = 0x1000
    ANNOTATION = 0x2000
    ENUM = 0x4000
    # 0x8000 is unused
    CONSTRUCTOR = 0x10000
    DECLARED_SYNCHRONIZED = 0x20000


# Constants
ENDIAN_CONSTANT = 0x12345678
NO_INDEX = 0xFFFFFFFF
