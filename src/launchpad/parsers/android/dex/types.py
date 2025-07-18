from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from launchpad.parsers.android.dex.android_code_utils import AndroidCodeUtils

# Types taken from https://source.android.com/docs/core/runtime/dex-format


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
    elements: dict[str, EncodedValue]
    parameter_index: int | None = None


@dataclass
class MethodAnnotation:
    method_index: int
    annotations_offset: int


@dataclass
class FieldAnnotation:
    field_index: int
    annotations_offset: int


@dataclass
class ParameterAnnotation:
    method_index: int
    annotations_offset: int


@dataclass
class AnnotationsDirectory:
    class_annotations_offset: int
    class_annotations: list[Annotation]
    field_annotations: list[FieldAnnotation]
    method_annotations: list[MethodAnnotation]
    parameter_annotations: list[ParameterAnnotation]


@dataclass
class EncodedValue:
    value: Any
    type: EncodedValueType
    offset: int
    size: int


@dataclass
class Field:
    size: int
    signature: str
    access_flags: list[AccessFlag]
    annotations: list[Annotation]


@dataclass
class Method:
    size: int
    name: str
    signature: str
    prototype: Prototype
    annotations: list[Annotation] | None = None
    access_flags: list[AccessFlag] | None = None
    parameters: list[Parameter] | None = None


@dataclass
class ClassDefinition:
    size: int
    signature: str
    source_file_name: str | None
    interfaces: list[str]
    annotations: list[Annotation]
    access_flags: list[AccessFlag]
    fields: list[Field]
    methods: list[Method]

    def fqn(self) -> str:
        # Remove Kotlin suffix from signature if present
        signature = AndroidCodeUtils.remove_kotlin_suffix_from_signature(self.signature)
        return AndroidCodeUtils.class_signature_to_fqn(signature)

    def get_name(self) -> str:
        return self.fqn().split(".")[-1]


class EncodedValueType(IntEnum):
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
    BUILD = 0x00
    RUNTIME = 0x01
    SYSTEM = 0x02


class AccessFlag(IntEnum):
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


ENDIAN_CONSTANT = 0x12345678
NO_INDEX = 0xFFFFFFFF
