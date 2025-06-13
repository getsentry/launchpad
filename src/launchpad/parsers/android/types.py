"""Types and enums for Android binary parser."""

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, List, Union


# https://android.googlesource.com/platform/frameworks/base/+/56a2301/include/androidfw/ResourceTypes.h
class ChunkType(IntEnum):
    """Android binary chunk types."""

    NULL = 0x0000
    STRING_POOL = 0x0001
    TABLE = 0x0002
    XML = 0x0003
    XML_START_NAMESPACE = 0x0100
    XML_END_NAMESPACE = 0x0101
    XML_START_ELEMENT = 0x0102
    XML_END_ELEMENT = 0x0103
    XML_CDATA = 0x0104
    XML_RESOURCE_MAP = 0x0180
    TABLE_PACKAGE = 0x0200
    TABLE_TYPE = 0x0201
    TABLE_TYPE_SPEC = 0x0202
    TABLE_LIBRARY = 0x0203


class NodeType(IntEnum):
    """XML node types."""

    ELEMENT_NODE = 1
    ATTRIBUTE_NODE = 2
    CDATA_SECTION_NODE = 4


class StringFlags(IntEnum):
    """String pool flags."""

    UTF8 = 0x00000100


class TypeFlags(IntEnum):
    """Type flags."""

    SPARSE = 0x0001


class EntryFlags(IntEnum):
    """Entry flags."""

    COMPLEX = 0x0001


class TypedValueRawType(IntEnum):
    """Raw type values for typed values."""

    TYPE_NULL = 0x00
    TYPE_REFERENCE = 0x01
    TYPE_ATTRIBUTE = 0x02
    TYPE_STRING = 0x03
    TYPE_FLOAT = 0x04
    TYPE_DIMENSION = 0x05
    TYPE_FRACTION = 0x06
    TYPE_INT_DEC = 0x10
    TYPE_INT_HEX = 0x11
    TYPE_INT_BOOLEAN = 0x12
    TYPE_INT_COLOR_ARGB8 = 0x1C
    TYPE_INT_COLOR_RGB8 = 0x1D
    TYPE_INT_COLOR_ARGB4 = 0x1E
    TYPE_INT_COLOR_RGB4 = 0x1F
    COMPLEX_UNIT_PX = 0x00
    COMPLEX_UNIT_DIP = 0x01
    COMPLEX_UNIT_SP = 0x02
    COMPLEX_UNIT_PT = 0x03
    COMPLEX_UNIT_IN = 0x04
    COMPLEX_UNIT_MM = 0x05
    COMPLEX_UNIT_FRACTION = 0x00
    COMPLEX_UNIT_FRACTION_PARENT = 0x01


@dataclass
class ChunkHeader:
    """Header for a binary chunk."""

    start_offset: int
    chunk_type: ChunkType
    header_size: int
    chunk_size: int


@dataclass
class StringPool:
    """String pool data."""

    strings: List[str]
    flags: int
    string_count: int
    strings_start: int
    style_count: int
    styles_start: int


@dataclass
class Dimension:
    """Dimension value."""

    value: int
    unit: str
    raw_unit: int


@dataclass
class Fraction:
    """Fraction value."""

    value: float
    type: str
    raw_type: int


@dataclass
class TypedValue:
    """Typed value."""

    value: Any
    type: str
    raw_type: int


@dataclass
class XmlAttribute:
    """XML attribute."""

    name: str
    node_type: NodeType
    namespace_uri: str | None
    node_name: str
    typed_value: TypedValue
    value: str | None


@dataclass
class XmlCData:
    """XML CDATA section."""

    attributes: List[XmlAttribute]
    child_nodes: List["XmlNode"]
    node_type: NodeType
    node_name: str
    data: str | None
    typed_value: TypedValue


@dataclass
class XmlNode:
    """XML node."""

    node_type: NodeType
    attributes: List[XmlAttribute]
    child_nodes: List[Union["XmlNode", XmlCData]]
    node_name: str | None = None
    namespace_uri: str | None = None


@dataclass
class ResourceTypeConfig:
    """Resource type configuration."""

    size: int
    language: str
    region: str


@dataclass
class ResourceTableEntry:
    """Resource table entry."""

    size: int
    flags: int
    id: int
    key: str
    parent_entry: int
    value: TypedValue | None
    values: Dict[int, TypedValue]


@dataclass
class ResourceTableType:
    """Resource table type."""

    id: int
    name: str
    config: ResourceTypeConfig
    entries: List[ResourceTableEntry]


@dataclass
class ResourceTablePackage:
    """Resource table package."""

    id: int
    name: str
    types: List[ResourceTableType]
