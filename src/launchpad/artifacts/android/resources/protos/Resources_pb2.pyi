#  type: ignore

from typing import ClassVar as _ClassVar
from typing import Iterable as _Iterable
from typing import Mapping as _Mapping
from typing import Optional as _Optional
from typing import Union as _Union

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper

from .Configuration_pb2 import Configuration as _Configuration_pb2

DESCRIPTOR: _descriptor.FileDescriptor

# Generated with protoc --proto_path=src/launchpad/artifacts/android/resources/proto --python_out=src/launchpad/artifacts/android/resources/proto src/launchpad/artifacts/android/resources/proto/Configuration.proto src/launchpad/artifacts/android/resources/proto/Resources.proto --pyi_out=src/launchpad/artifacts/android/resources/proto
class StringPool(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class SourcePosition(_message.Message):
    __slots__ = ("line_number", "column_number")
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    COLUMN_NUMBER_FIELD_NUMBER: _ClassVar[int]
    line_number: int
    column_number: int
    def __init__(self, line_number: _Optional[int] = ..., column_number: _Optional[int] = ...) -> None: ...

class Source(_message.Message):
    __slots__ = ("path_idx", "position")
    PATH_IDX_FIELD_NUMBER: _ClassVar[int]
    POSITION_FIELD_NUMBER: _ClassVar[int]
    path_idx: int
    position: SourcePosition
    def __init__(
        self, path_idx: _Optional[int] = ..., position: _Optional[_Union[SourcePosition, _Mapping]] = ...
    ) -> None: ...

class ToolFingerprint(_message.Message):
    __slots__ = ("tool", "version")
    TOOL_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    tool: str
    version: str
    def __init__(self, tool: _Optional[str] = ..., version: _Optional[str] = ...) -> None: ...

class DynamicRefTable(_message.Message):
    __slots__ = ("package_id", "package_name")
    PACKAGE_ID_FIELD_NUMBER: _ClassVar[int]
    PACKAGE_NAME_FIELD_NUMBER: _ClassVar[int]
    package_id: PackageId
    package_name: str
    def __init__(
        self, package_id: _Optional[_Union[PackageId, _Mapping]] = ..., package_name: _Optional[str] = ...
    ) -> None: ...

class ResourceTable(_message.Message):
    __slots__ = ("source_pool", "package", "overlayable", "tool_fingerprint", "dynamic_ref_table")
    SOURCE_POOL_FIELD_NUMBER: _ClassVar[int]
    PACKAGE_FIELD_NUMBER: _ClassVar[int]
    OVERLAYABLE_FIELD_NUMBER: _ClassVar[int]
    TOOL_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    DYNAMIC_REF_TABLE_FIELD_NUMBER: _ClassVar[int]
    source_pool: StringPool
    package: _containers.RepeatedCompositeFieldContainer[Package]
    overlayable: _containers.RepeatedCompositeFieldContainer[Overlayable]
    tool_fingerprint: _containers.RepeatedCompositeFieldContainer[ToolFingerprint]
    dynamic_ref_table: _containers.RepeatedCompositeFieldContainer[DynamicRefTable]
    def __init__(
        self,
        source_pool: _Optional[_Union[StringPool, _Mapping]] = ...,
        package: _Optional[_Iterable[_Union[Package, _Mapping]]] = ...,
        overlayable: _Optional[_Iterable[_Union[Overlayable, _Mapping]]] = ...,
        tool_fingerprint: _Optional[_Iterable[_Union[ToolFingerprint, _Mapping]]] = ...,
        dynamic_ref_table: _Optional[_Iterable[_Union[DynamicRefTable, _Mapping]]] = ...,
    ) -> None: ...

class PackageId(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class Package(_message.Message):
    __slots__ = ("package_id", "package_name", "type")
    PACKAGE_ID_FIELD_NUMBER: _ClassVar[int]
    PACKAGE_NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    package_id: PackageId
    package_name: str
    type: _containers.RepeatedCompositeFieldContainer[Type]
    def __init__(
        self,
        package_id: _Optional[_Union[PackageId, _Mapping]] = ...,
        package_name: _Optional[str] = ...,
        type: _Optional[_Iterable[_Union[Type, _Mapping]]] = ...,
    ) -> None: ...

class TypeId(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class Type(_message.Message):
    __slots__ = ("type_id", "name", "entry")
    TYPE_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    type_id: TypeId
    name: str
    entry: _containers.RepeatedCompositeFieldContainer[Entry]
    def __init__(
        self,
        type_id: _Optional[_Union[TypeId, _Mapping]] = ...,
        name: _Optional[str] = ...,
        entry: _Optional[_Iterable[_Union[Entry, _Mapping]]] = ...,
    ) -> None: ...

class Visibility(_message.Message):
    __slots__ = ("level", "source", "comment", "staged_api")

    class Level(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[Visibility.Level]
        PRIVATE: _ClassVar[Visibility.Level]
        PUBLIC: _ClassVar[Visibility.Level]

    UNKNOWN: Visibility.Level
    PRIVATE: Visibility.Level
    PUBLIC: Visibility.Level
    LEVEL_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    STAGED_API_FIELD_NUMBER: _ClassVar[int]
    level: Visibility.Level
    source: Source
    comment: str
    staged_api: bool
    def __init__(
        self,
        level: _Optional[_Union[Visibility.Level, str]] = ...,
        source: _Optional[_Union[Source, _Mapping]] = ...,
        comment: _Optional[str] = ...,
        staged_api: bool = ...,
    ) -> None: ...

class AllowNew(_message.Message):
    __slots__ = ("source", "comment")
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    source: Source
    comment: str
    def __init__(self, source: _Optional[_Union[Source, _Mapping]] = ..., comment: _Optional[str] = ...) -> None: ...

class Overlayable(_message.Message):
    __slots__ = ("name", "source", "actor")
    NAME_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    ACTOR_FIELD_NUMBER: _ClassVar[int]
    name: str
    source: Source
    actor: str
    def __init__(
        self, name: _Optional[str] = ..., source: _Optional[_Union[Source, _Mapping]] = ..., actor: _Optional[str] = ...
    ) -> None: ...

class OverlayableItem(_message.Message):
    __slots__ = ("source", "comment", "policy", "overlayable_idx")

    class Policy(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[OverlayableItem.Policy]
        PUBLIC: _ClassVar[OverlayableItem.Policy]
        SYSTEM: _ClassVar[OverlayableItem.Policy]
        VENDOR: _ClassVar[OverlayableItem.Policy]
        PRODUCT: _ClassVar[OverlayableItem.Policy]
        SIGNATURE: _ClassVar[OverlayableItem.Policy]
        ODM: _ClassVar[OverlayableItem.Policy]
        OEM: _ClassVar[OverlayableItem.Policy]
        ACTOR: _ClassVar[OverlayableItem.Policy]
        CONFIG_SIGNATURE: _ClassVar[OverlayableItem.Policy]

    NONE: OverlayableItem.Policy
    PUBLIC: OverlayableItem.Policy
    SYSTEM: OverlayableItem.Policy
    VENDOR: OverlayableItem.Policy
    PRODUCT: OverlayableItem.Policy
    SIGNATURE: OverlayableItem.Policy
    ODM: OverlayableItem.Policy
    OEM: OverlayableItem.Policy
    ACTOR: OverlayableItem.Policy
    CONFIG_SIGNATURE: OverlayableItem.Policy
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    OVERLAYABLE_IDX_FIELD_NUMBER: _ClassVar[int]
    source: Source
    comment: str
    policy: _containers.RepeatedScalarFieldContainer[OverlayableItem.Policy]
    overlayable_idx: int
    def __init__(
        self,
        source: _Optional[_Union[Source, _Mapping]] = ...,
        comment: _Optional[str] = ...,
        policy: _Optional[_Iterable[_Union[OverlayableItem.Policy, str]]] = ...,
        overlayable_idx: _Optional[int] = ...,
    ) -> None: ...

class StagedId(_message.Message):
    __slots__ = ("source", "staged_id")
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    STAGED_ID_FIELD_NUMBER: _ClassVar[int]
    source: Source
    staged_id: int
    def __init__(self, source: _Optional[_Union[Source, _Mapping]] = ..., staged_id: _Optional[int] = ...) -> None: ...

class EntryId(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class Entry(_message.Message):
    __slots__ = (
        "entry_id",
        "name",
        "visibility",
        "allow_new",
        "overlayable_item",
        "config_value",
        "staged_id",
        "flag_disabled_config_value",
    )
    ENTRY_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VISIBILITY_FIELD_NUMBER: _ClassVar[int]
    ALLOW_NEW_FIELD_NUMBER: _ClassVar[int]
    OVERLAYABLE_ITEM_FIELD_NUMBER: _ClassVar[int]
    CONFIG_VALUE_FIELD_NUMBER: _ClassVar[int]
    STAGED_ID_FIELD_NUMBER: _ClassVar[int]
    FLAG_DISABLED_CONFIG_VALUE_FIELD_NUMBER: _ClassVar[int]
    entry_id: EntryId
    name: str
    visibility: Visibility
    allow_new: AllowNew
    overlayable_item: OverlayableItem
    config_value: _containers.RepeatedCompositeFieldContainer[ConfigValue]
    staged_id: StagedId
    flag_disabled_config_value: _containers.RepeatedCompositeFieldContainer[ConfigValue]
    def __init__(
        self,
        entry_id: _Optional[_Union[EntryId, _Mapping]] = ...,
        name: _Optional[str] = ...,
        visibility: _Optional[_Union[Visibility, _Mapping]] = ...,
        allow_new: _Optional[_Union[AllowNew, _Mapping]] = ...,
        overlayable_item: _Optional[_Union[OverlayableItem, _Mapping]] = ...,
        config_value: _Optional[_Iterable[_Union[ConfigValue, _Mapping]]] = ...,
        staged_id: _Optional[_Union[StagedId, _Mapping]] = ...,
        flag_disabled_config_value: _Optional[_Iterable[_Union[ConfigValue, _Mapping]]] = ...,
    ) -> None: ...

class ConfigValue(_message.Message):
    __slots__ = ("config", "value")
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    config: _Configuration_pb2.Configuration
    value: Value
    def __init__(
        self,
        config: _Optional[_Union[_Configuration_pb2.Configuration, _Mapping]] = ...,
        value: _Optional[_Union[Value, _Mapping]] = ...,
    ) -> None: ...

class Value(_message.Message):
    __slots__ = ("source", "comment", "weak", "item", "compound_value")
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    WEAK_FIELD_NUMBER: _ClassVar[int]
    ITEM_FIELD_NUMBER: _ClassVar[int]
    COMPOUND_VALUE_FIELD_NUMBER: _ClassVar[int]
    source: Source
    comment: str
    weak: bool
    item: Item
    compound_value: CompoundValue
    def __init__(
        self,
        source: _Optional[_Union[Source, _Mapping]] = ...,
        comment: _Optional[str] = ...,
        weak: bool = ...,
        item: _Optional[_Union[Item, _Mapping]] = ...,
        compound_value: _Optional[_Union[CompoundValue, _Mapping]] = ...,
    ) -> None: ...

class Item(_message.Message):
    __slots__ = (
        "ref",
        "str",
        "raw_str",
        "styled_str",
        "file",
        "id",
        "prim",
        "flag_status",
        "flag_negated",
        "flag_name",
    )
    REF_FIELD_NUMBER: _ClassVar[int]
    STR_FIELD_NUMBER: _ClassVar[int]
    RAW_STR_FIELD_NUMBER: _ClassVar[int]
    STYLED_STR_FIELD_NUMBER: _ClassVar[int]
    FILE_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    PRIM_FIELD_NUMBER: _ClassVar[int]
    FLAG_STATUS_FIELD_NUMBER: _ClassVar[int]
    FLAG_NEGATED_FIELD_NUMBER: _ClassVar[int]
    FLAG_NAME_FIELD_NUMBER: _ClassVar[int]
    ref: Reference
    str: String
    raw_str: RawString
    styled_str: StyledString
    file: FileReference
    id: Id
    prim: Primitive
    flag_status: int
    flag_negated: bool
    flag_name: str
    def __init__(
        self,
        ref: _Optional[_Union[Reference, _Mapping]] = ...,
        str: _Optional[_Union[String, _Mapping]] = ...,
        raw_str: _Optional[_Union[RawString, _Mapping]] = ...,
        styled_str: _Optional[_Union[StyledString, _Mapping]] = ...,
        file: _Optional[_Union[FileReference, _Mapping]] = ...,
        id: _Optional[_Union[Id, _Mapping]] = ...,
        prim: _Optional[_Union[Primitive, _Mapping]] = ...,
        flag_status: _Optional[int] = ...,
        flag_negated: bool = ...,
        flag_name: _Optional[str] = ...,
    ) -> None: ...

class CompoundValue(_message.Message):
    __slots__ = ("attr", "style", "styleable", "array", "plural", "macro", "flag_status", "flag_negated", "flag_name")
    ATTR_FIELD_NUMBER: _ClassVar[int]
    STYLE_FIELD_NUMBER: _ClassVar[int]
    STYLEABLE_FIELD_NUMBER: _ClassVar[int]
    ARRAY_FIELD_NUMBER: _ClassVar[int]
    PLURAL_FIELD_NUMBER: _ClassVar[int]
    MACRO_FIELD_NUMBER: _ClassVar[int]
    FLAG_STATUS_FIELD_NUMBER: _ClassVar[int]
    FLAG_NEGATED_FIELD_NUMBER: _ClassVar[int]
    FLAG_NAME_FIELD_NUMBER: _ClassVar[int]
    attr: Attribute
    style: Style
    styleable: Styleable
    array: Array
    plural: Plural
    macro: MacroBody
    flag_status: int
    flag_negated: bool
    flag_name: str
    def __init__(
        self,
        attr: _Optional[_Union[Attribute, _Mapping]] = ...,
        style: _Optional[_Union[Style, _Mapping]] = ...,
        styleable: _Optional[_Union[Styleable, _Mapping]] = ...,
        array: _Optional[_Union[Array, _Mapping]] = ...,
        plural: _Optional[_Union[Plural, _Mapping]] = ...,
        macro: _Optional[_Union[MacroBody, _Mapping]] = ...,
        flag_status: _Optional[int] = ...,
        flag_negated: bool = ...,
        flag_name: _Optional[str] = ...,
    ) -> None: ...

class Boolean(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: bool
    def __init__(self, value: bool = ...) -> None: ...

class Reference(_message.Message):
    __slots__ = ("type", "id", "name", "private", "is_dynamic", "type_flags", "allow_raw")

    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        REFERENCE: _ClassVar[Reference.Type]
        ATTRIBUTE: _ClassVar[Reference.Type]

    REFERENCE: Reference.Type
    ATTRIBUTE: Reference.Type
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PRIVATE_FIELD_NUMBER: _ClassVar[int]
    IS_DYNAMIC_FIELD_NUMBER: _ClassVar[int]
    TYPE_FLAGS_FIELD_NUMBER: _ClassVar[int]
    ALLOW_RAW_FIELD_NUMBER: _ClassVar[int]
    type: Reference.Type
    id: int
    name: str
    private: bool
    is_dynamic: Boolean
    type_flags: int
    allow_raw: bool
    def __init__(
        self,
        type: _Optional[_Union[Reference.Type, str]] = ...,
        id: _Optional[int] = ...,
        name: _Optional[str] = ...,
        private: bool = ...,
        is_dynamic: _Optional[_Union[Boolean, _Mapping]] = ...,
        type_flags: _Optional[int] = ...,
        allow_raw: bool = ...,
    ) -> None: ...

class Id(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class String(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: str
    def __init__(self, value: _Optional[str] = ...) -> None: ...

class RawString(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: str
    def __init__(self, value: _Optional[str] = ...) -> None: ...

class StyledString(_message.Message):
    __slots__ = ("value", "span")

    class Span(_message.Message):
        __slots__ = ("tag", "first_char", "last_char")
        TAG_FIELD_NUMBER: _ClassVar[int]
        FIRST_CHAR_FIELD_NUMBER: _ClassVar[int]
        LAST_CHAR_FIELD_NUMBER: _ClassVar[int]
        tag: str
        first_char: int
        last_char: int
        def __init__(
            self, tag: _Optional[str] = ..., first_char: _Optional[int] = ..., last_char: _Optional[int] = ...
        ) -> None: ...

    VALUE_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    value: str
    span: _containers.RepeatedCompositeFieldContainer[StyledString.Span]
    def __init__(
        self, value: _Optional[str] = ..., span: _Optional[_Iterable[_Union[StyledString.Span, _Mapping]]] = ...
    ) -> None: ...

class FileReference(_message.Message):
    __slots__ = ("path", "type")

    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[FileReference.Type]
        PNG: _ClassVar[FileReference.Type]
        BINARY_XML: _ClassVar[FileReference.Type]
        PROTO_XML: _ClassVar[FileReference.Type]

    UNKNOWN: FileReference.Type
    PNG: FileReference.Type
    BINARY_XML: FileReference.Type
    PROTO_XML: FileReference.Type
    PATH_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    path: str
    type: FileReference.Type
    def __init__(self, path: _Optional[str] = ..., type: _Optional[_Union[FileReference.Type, str]] = ...) -> None: ...

class Primitive(_message.Message):
    __slots__ = (
        "null_value",
        "empty_value",
        "float_value",
        "dimension_value",
        "fraction_value",
        "int_decimal_value",
        "int_hexadecimal_value",
        "boolean_value",
        "color_argb8_value",
        "color_rgb8_value",
        "color_argb4_value",
        "color_rgb4_value",
        "dimension_value_deprecated",
        "fraction_value_deprecated",
    )

    class NullType(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...

    class EmptyType(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...

    NULL_VALUE_FIELD_NUMBER: _ClassVar[int]
    EMPTY_VALUE_FIELD_NUMBER: _ClassVar[int]
    FLOAT_VALUE_FIELD_NUMBER: _ClassVar[int]
    DIMENSION_VALUE_FIELD_NUMBER: _ClassVar[int]
    FRACTION_VALUE_FIELD_NUMBER: _ClassVar[int]
    INT_DECIMAL_VALUE_FIELD_NUMBER: _ClassVar[int]
    INT_HEXADECIMAL_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOLEAN_VALUE_FIELD_NUMBER: _ClassVar[int]
    COLOR_ARGB8_VALUE_FIELD_NUMBER: _ClassVar[int]
    COLOR_RGB8_VALUE_FIELD_NUMBER: _ClassVar[int]
    COLOR_ARGB4_VALUE_FIELD_NUMBER: _ClassVar[int]
    COLOR_RGB4_VALUE_FIELD_NUMBER: _ClassVar[int]
    DIMENSION_VALUE_DEPRECATED_FIELD_NUMBER: _ClassVar[int]
    FRACTION_VALUE_DEPRECATED_FIELD_NUMBER: _ClassVar[int]
    null_value: Primitive.NullType
    empty_value: Primitive.EmptyType
    float_value: float
    dimension_value: int
    fraction_value: int
    int_decimal_value: int
    int_hexadecimal_value: int
    boolean_value: bool
    color_argb8_value: int
    color_rgb8_value: int
    color_argb4_value: int
    color_rgb4_value: int
    dimension_value_deprecated: float
    fraction_value_deprecated: float
    def __init__(
        self,
        null_value: _Optional[_Union[Primitive.NullType, _Mapping]] = ...,
        empty_value: _Optional[_Union[Primitive.EmptyType, _Mapping]] = ...,
        float_value: _Optional[float] = ...,
        dimension_value: _Optional[int] = ...,
        fraction_value: _Optional[int] = ...,
        int_decimal_value: _Optional[int] = ...,
        int_hexadecimal_value: _Optional[int] = ...,
        boolean_value: bool = ...,
        color_argb8_value: _Optional[int] = ...,
        color_rgb8_value: _Optional[int] = ...,
        color_argb4_value: _Optional[int] = ...,
        color_rgb4_value: _Optional[int] = ...,
        dimension_value_deprecated: _Optional[float] = ...,
        fraction_value_deprecated: _Optional[float] = ...,
    ) -> None: ...

class Attribute(_message.Message):
    __slots__ = ("format_flags", "min_int", "max_int", "symbol")

    class FormatFlags(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[Attribute.FormatFlags]
        ANY: _ClassVar[Attribute.FormatFlags]
        REFERENCE: _ClassVar[Attribute.FormatFlags]
        STRING: _ClassVar[Attribute.FormatFlags]
        INTEGER: _ClassVar[Attribute.FormatFlags]
        BOOLEAN: _ClassVar[Attribute.FormatFlags]
        COLOR: _ClassVar[Attribute.FormatFlags]
        FLOAT: _ClassVar[Attribute.FormatFlags]
        DIMENSION: _ClassVar[Attribute.FormatFlags]
        FRACTION: _ClassVar[Attribute.FormatFlags]
        ENUM: _ClassVar[Attribute.FormatFlags]
        FLAGS: _ClassVar[Attribute.FormatFlags]

    NONE: Attribute.FormatFlags
    ANY: Attribute.FormatFlags
    REFERENCE: Attribute.FormatFlags
    STRING: Attribute.FormatFlags
    INTEGER: Attribute.FormatFlags
    BOOLEAN: Attribute.FormatFlags
    COLOR: Attribute.FormatFlags
    FLOAT: Attribute.FormatFlags
    DIMENSION: Attribute.FormatFlags
    FRACTION: Attribute.FormatFlags
    ENUM: Attribute.FormatFlags
    FLAGS: Attribute.FormatFlags

    class Symbol(_message.Message):
        __slots__ = ("source", "comment", "name", "value", "type")
        SOURCE_FIELD_NUMBER: _ClassVar[int]
        COMMENT_FIELD_NUMBER: _ClassVar[int]
        NAME_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        source: Source
        comment: str
        name: Reference
        value: int
        type: int
        def __init__(
            self,
            source: _Optional[_Union[Source, _Mapping]] = ...,
            comment: _Optional[str] = ...,
            name: _Optional[_Union[Reference, _Mapping]] = ...,
            value: _Optional[int] = ...,
            type: _Optional[int] = ...,
        ) -> None: ...

    FORMAT_FLAGS_FIELD_NUMBER: _ClassVar[int]
    MIN_INT_FIELD_NUMBER: _ClassVar[int]
    MAX_INT_FIELD_NUMBER: _ClassVar[int]
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    format_flags: int
    min_int: int
    max_int: int
    symbol: _containers.RepeatedCompositeFieldContainer[Attribute.Symbol]
    def __init__(
        self,
        format_flags: _Optional[int] = ...,
        min_int: _Optional[int] = ...,
        max_int: _Optional[int] = ...,
        symbol: _Optional[_Iterable[_Union[Attribute.Symbol, _Mapping]]] = ...,
    ) -> None: ...

class Style(_message.Message):
    __slots__ = ("parent", "parent_source", "entry")

    class Entry(_message.Message):
        __slots__ = ("source", "comment", "key", "item")
        SOURCE_FIELD_NUMBER: _ClassVar[int]
        COMMENT_FIELD_NUMBER: _ClassVar[int]
        KEY_FIELD_NUMBER: _ClassVar[int]
        ITEM_FIELD_NUMBER: _ClassVar[int]
        source: Source
        comment: str
        key: Reference
        item: Item
        def __init__(
            self,
            source: _Optional[_Union[Source, _Mapping]] = ...,
            comment: _Optional[str] = ...,
            key: _Optional[_Union[Reference, _Mapping]] = ...,
            item: _Optional[_Union[Item, _Mapping]] = ...,
        ) -> None: ...

    PARENT_FIELD_NUMBER: _ClassVar[int]
    PARENT_SOURCE_FIELD_NUMBER: _ClassVar[int]
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    parent: Reference
    parent_source: Source
    entry: _containers.RepeatedCompositeFieldContainer[Style.Entry]
    def __init__(
        self,
        parent: _Optional[_Union[Reference, _Mapping]] = ...,
        parent_source: _Optional[_Union[Source, _Mapping]] = ...,
        entry: _Optional[_Iterable[_Union[Style.Entry, _Mapping]]] = ...,
    ) -> None: ...

class Styleable(_message.Message):
    __slots__ = ("entry",)

    class Entry(_message.Message):
        __slots__ = ("source", "comment", "attr")
        SOURCE_FIELD_NUMBER: _ClassVar[int]
        COMMENT_FIELD_NUMBER: _ClassVar[int]
        ATTR_FIELD_NUMBER: _ClassVar[int]
        source: Source
        comment: str
        attr: Reference
        def __init__(
            self,
            source: _Optional[_Union[Source, _Mapping]] = ...,
            comment: _Optional[str] = ...,
            attr: _Optional[_Union[Reference, _Mapping]] = ...,
        ) -> None: ...

    ENTRY_FIELD_NUMBER: _ClassVar[int]
    entry: _containers.RepeatedCompositeFieldContainer[Styleable.Entry]
    def __init__(self, entry: _Optional[_Iterable[_Union[Styleable.Entry, _Mapping]]] = ...) -> None: ...

class Array(_message.Message):
    __slots__ = ("element",)

    class Element(_message.Message):
        __slots__ = ("source", "comment", "item")
        SOURCE_FIELD_NUMBER: _ClassVar[int]
        COMMENT_FIELD_NUMBER: _ClassVar[int]
        ITEM_FIELD_NUMBER: _ClassVar[int]
        source: Source
        comment: str
        item: Item
        def __init__(
            self,
            source: _Optional[_Union[Source, _Mapping]] = ...,
            comment: _Optional[str] = ...,
            item: _Optional[_Union[Item, _Mapping]] = ...,
        ) -> None: ...

    ELEMENT_FIELD_NUMBER: _ClassVar[int]
    element: _containers.RepeatedCompositeFieldContainer[Array.Element]
    def __init__(self, element: _Optional[_Iterable[_Union[Array.Element, _Mapping]]] = ...) -> None: ...

class Plural(_message.Message):
    __slots__ = ("entry",)

    class Arity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ZERO: _ClassVar[Plural.Arity]
        ONE: _ClassVar[Plural.Arity]
        TWO: _ClassVar[Plural.Arity]
        FEW: _ClassVar[Plural.Arity]
        MANY: _ClassVar[Plural.Arity]
        OTHER: _ClassVar[Plural.Arity]

    ZERO: Plural.Arity
    ONE: Plural.Arity
    TWO: Plural.Arity
    FEW: Plural.Arity
    MANY: Plural.Arity
    OTHER: Plural.Arity

    class Entry(_message.Message):
        __slots__ = ("source", "comment", "arity", "item")
        SOURCE_FIELD_NUMBER: _ClassVar[int]
        COMMENT_FIELD_NUMBER: _ClassVar[int]
        ARITY_FIELD_NUMBER: _ClassVar[int]
        ITEM_FIELD_NUMBER: _ClassVar[int]
        source: Source
        comment: str
        arity: Plural.Arity
        item: Item
        def __init__(
            self,
            source: _Optional[_Union[Source, _Mapping]] = ...,
            comment: _Optional[str] = ...,
            arity: _Optional[_Union[Plural.Arity, str]] = ...,
            item: _Optional[_Union[Item, _Mapping]] = ...,
        ) -> None: ...

    ENTRY_FIELD_NUMBER: _ClassVar[int]
    entry: _containers.RepeatedCompositeFieldContainer[Plural.Entry]
    def __init__(self, entry: _Optional[_Iterable[_Union[Plural.Entry, _Mapping]]] = ...) -> None: ...

class XmlNode(_message.Message):
    __slots__ = ("element", "text", "source")
    ELEMENT_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    element: XmlElement
    text: str
    source: SourcePosition
    def __init__(
        self,
        element: _Optional[_Union[XmlElement, _Mapping]] = ...,
        text: _Optional[str] = ...,
        source: _Optional[_Union[SourcePosition, _Mapping]] = ...,
    ) -> None: ...

class XmlElement(_message.Message):
    __slots__ = ("namespace_declaration", "namespace_uri", "name", "attribute", "child")
    NAMESPACE_DECLARATION_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_URI_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTE_FIELD_NUMBER: _ClassVar[int]
    CHILD_FIELD_NUMBER: _ClassVar[int]
    namespace_declaration: _containers.RepeatedCompositeFieldContainer[XmlNamespace]
    namespace_uri: str
    name: str
    attribute: _containers.RepeatedCompositeFieldContainer[XmlAttribute]
    child: _containers.RepeatedCompositeFieldContainer[XmlNode]
    def __init__(
        self,
        namespace_declaration: _Optional[_Iterable[_Union[XmlNamespace, _Mapping]]] = ...,
        namespace_uri: _Optional[str] = ...,
        name: _Optional[str] = ...,
        attribute: _Optional[_Iterable[_Union[XmlAttribute, _Mapping]]] = ...,
        child: _Optional[_Iterable[_Union[XmlNode, _Mapping]]] = ...,
    ) -> None: ...

class XmlNamespace(_message.Message):
    __slots__ = ("prefix", "uri", "source")
    PREFIX_FIELD_NUMBER: _ClassVar[int]
    URI_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    prefix: str
    uri: str
    source: SourcePosition
    def __init__(
        self,
        prefix: _Optional[str] = ...,
        uri: _Optional[str] = ...,
        source: _Optional[_Union[SourcePosition, _Mapping]] = ...,
    ) -> None: ...

class XmlAttribute(_message.Message):
    __slots__ = ("namespace_uri", "name", "value", "source", "resource_id", "compiled_item")
    NAMESPACE_URI_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    COMPILED_ITEM_FIELD_NUMBER: _ClassVar[int]
    namespace_uri: str
    name: str
    value: str
    source: SourcePosition
    resource_id: int
    compiled_item: Item
    def __init__(
        self,
        namespace_uri: _Optional[str] = ...,
        name: _Optional[str] = ...,
        value: _Optional[str] = ...,
        source: _Optional[_Union[SourcePosition, _Mapping]] = ...,
        resource_id: _Optional[int] = ...,
        compiled_item: _Optional[_Union[Item, _Mapping]] = ...,
    ) -> None: ...

class MacroBody(_message.Message):
    __slots__ = ("raw_string", "style_string", "untranslatable_sections", "namespace_stack", "source")
    RAW_STRING_FIELD_NUMBER: _ClassVar[int]
    STYLE_STRING_FIELD_NUMBER: _ClassVar[int]
    UNTRANSLATABLE_SECTIONS_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_STACK_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    raw_string: str
    style_string: StyleString
    untranslatable_sections: _containers.RepeatedCompositeFieldContainer[UntranslatableSection]
    namespace_stack: _containers.RepeatedCompositeFieldContainer[NamespaceAlias]
    source: SourcePosition
    def __init__(
        self,
        raw_string: _Optional[str] = ...,
        style_string: _Optional[_Union[StyleString, _Mapping]] = ...,
        untranslatable_sections: _Optional[_Iterable[_Union[UntranslatableSection, _Mapping]]] = ...,
        namespace_stack: _Optional[_Iterable[_Union[NamespaceAlias, _Mapping]]] = ...,
        source: _Optional[_Union[SourcePosition, _Mapping]] = ...,
    ) -> None: ...

class NamespaceAlias(_message.Message):
    __slots__ = ("prefix", "package_name", "is_private")
    PREFIX_FIELD_NUMBER: _ClassVar[int]
    PACKAGE_NAME_FIELD_NUMBER: _ClassVar[int]
    IS_PRIVATE_FIELD_NUMBER: _ClassVar[int]
    prefix: str
    package_name: str
    is_private: bool
    def __init__(
        self, prefix: _Optional[str] = ..., package_name: _Optional[str] = ..., is_private: bool = ...
    ) -> None: ...

class StyleString(_message.Message):
    __slots__ = ("str", "spans")

    class Span(_message.Message):
        __slots__ = ("name", "start_index", "end_index")
        NAME_FIELD_NUMBER: _ClassVar[int]
        START_INDEX_FIELD_NUMBER: _ClassVar[int]
        END_INDEX_FIELD_NUMBER: _ClassVar[int]
        name: str
        start_index: int
        end_index: int
        def __init__(
            self, name: _Optional[str] = ..., start_index: _Optional[int] = ..., end_index: _Optional[int] = ...
        ) -> None: ...

    STR_FIELD_NUMBER: _ClassVar[int]
    SPANS_FIELD_NUMBER: _ClassVar[int]
    str: str
    spans: _containers.RepeatedCompositeFieldContainer[StyleString.Span]
    def __init__(
        self, str: _Optional[str] = ..., spans: _Optional[_Iterable[_Union[StyleString.Span, _Mapping]]] = ...
    ) -> None: ...

class UntranslatableSection(_message.Message):
    __slots__ = ("start_index", "end_index")
    START_INDEX_FIELD_NUMBER: _ClassVar[int]
    END_INDEX_FIELD_NUMBER: _ClassVar[int]
    start_index: int
    end_index: int
    def __init__(self, start_index: _Optional[int] = ..., end_index: _Optional[int] = ...) -> None: ...
