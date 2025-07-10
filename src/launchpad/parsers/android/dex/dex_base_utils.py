from typing import Any

from launchpad.parsers.android.dex.types import (
    ENDIAN_CONSTANT,
    AccessFlag,
    Annotation,
    AnnotationsDirectory,
    AnnotationVisibility,
    DexFileHeader,
    EncodedValueType,
    Method,
    MethodAnnotation,
    ParameterAnnotation,
    Prototype,
)
from launchpad.parsers.buffer_wrapper import BufferWrapper
from launchpad.utils import logging

logger = logging.get_logger(__name__)


class DexBaseUtils:
    @staticmethod
    def get_header(buffer_wrapper: BufferWrapper) -> DexFileHeader:
        """Read DEX file header.

        https://source.android.com/docs/core/runtime/dex-format#header-item

        Returns:
            DEX file header information

        Raises:
            ValueError: If file is not a valid DEX file
        """
        buffer_wrapper.seek(0)

        # First 8 bytes will be 'dex\n{version}\0', if not, invalid file
        magic = []
        for i in range(8):
            magic.append(chr(buffer_wrapper.read_u8()))

        if "".join(magic[:3]) != "dex":
            raise ValueError("Invalid dex file magic")

        version = "".join(magic[4:8])
        logger.debug(f"DEX file version: {version}")
        buffer_wrapper.read_u32()  # checksum
        buffer_wrapper.skip(20)  # signature
        buffer_wrapper.read_u32()  # file size
        buffer_wrapper.read_u32()  # header size
        endian_tag = buffer_wrapper.read_u32()

        if endian_tag != ENDIAN_CONSTANT:
            raise ValueError(f"Unsupported endian tag {endian_tag:08x}")

        buffer_wrapper.read_u32()  # link size
        buffer_wrapper.read_u32()  # link offset
        buffer_wrapper.read_u32()  # map offset
        buffer_wrapper.read_u32()  # string ids size
        string_ids_off = buffer_wrapper.read_u32()
        buffer_wrapper.read_u32()  # type ids size
        type_ids_off = buffer_wrapper.read_u32()
        buffer_wrapper.read_u32()  # prototype ids size
        proto_ids_off = buffer_wrapper.read_u32()
        buffer_wrapper.read_u32()  # field ids size
        field_ids_off = buffer_wrapper.read_u32()
        buffer_wrapper.read_u32()  # method ids size
        method_ids_off = buffer_wrapper.read_u32()
        class_defs_size = buffer_wrapper.read_u32()
        class_defs_off = buffer_wrapper.read_u32()
        buffer_wrapper.read_u32()  # data size
        buffer_wrapper.read_u32()  # data offset

        return DexFileHeader(
            class_defs_size=class_defs_size,
            class_defs_off=class_defs_off,
            string_ids_off=string_ids_off,
            type_ids_off=type_ids_off,
            field_ids_off=field_ids_off,
            method_ids_off=method_ids_off,
            proto_ids_off=proto_ids_off,
        )

    @staticmethod
    def get_annotations_directory(
        buffer_wrapper: BufferWrapper,
        header: DexFileHeader,
        annotations_directory_offset: int,
    ) -> AnnotationsDirectory | None:
        """Parse annotations directory.

        https://source.android.com/docs/core/runtime/dex-format#annotations-directory

        Args:
            annotations_directory_offset: Offset to annotations directory

        Returns:
            Annotations directory or None if not present
        """
        if annotations_directory_offset == 0:
            return None

        cursor = buffer_wrapper.cursor
        buffer_wrapper.seek(annotations_directory_offset)

        class_annotations_offset = buffer_wrapper.read_u32()
        fields_size = buffer_wrapper.read_u32()
        annotated_methods_size = buffer_wrapper.read_u32()
        annotated_parameters_size = buffer_wrapper.read_u32()

        # Skip fields for now
        buffer_wrapper.skip(8 * fields_size)  # field_annotation is 8 bytes

        class_annotations: list[Annotation] = []
        if class_annotations_offset != 0:
            class_annotations = DexBaseUtils.get_annotation_set(
                buffer_wrapper=buffer_wrapper,
                header=header,
                offset=class_annotations_offset,
            )

        method_annotations: list[MethodAnnotation] = []
        for i in range(annotated_methods_size):
            method_index = buffer_wrapper.read_u32()
            annotations_offset = buffer_wrapper.read_u32()
            method_annotations.append(
                MethodAnnotation(method_index=method_index, annotations_offset=annotations_offset)
            )

        parameter_annotations: list[ParameterAnnotation] = []
        for i in range(annotated_parameters_size):
            method_index = buffer_wrapper.read_u32()
            annotations_offset = buffer_wrapper.read_u32()
            parameter_annotations.append(
                ParameterAnnotation(method_index=method_index, annotations_offset=annotations_offset)
            )

        buffer_wrapper.seek(cursor)
        return AnnotationsDirectory(
            class_annotations_offset=class_annotations_offset,
            class_annotations=class_annotations,
            method_annotations=method_annotations,
            parameter_annotations=parameter_annotations,
        )

    @staticmethod
    def get_annotation_set_ref_list(
        buffer_wrapper: BufferWrapper, header: DexFileHeader, offset: int
    ) -> list[Annotation]:
        """Parse annotation set reference list.

        https://source.android.com/docs/core/runtime/dex-format#set-ref-list

        Args:
            offset: Offset to annotation set ref list

        Returns:
            List of annotations
        """
        annotations: list[Annotation] = []

        if offset == 0:
            return annotations

        cursor = buffer_wrapper.cursor
        buffer_wrapper.seek(offset)

        size = buffer_wrapper.read_u32()

        for parameter_index in range(size):
            annotation_set_offset = buffer_wrapper.read_u32()
            if annotation_set_offset != 0:
                annotation_set = DexBaseUtils.parse_annotation_set(buffer_wrapper, header, annotation_set_offset)
                for annotation in annotation_set:
                    annotation.parameter_index = parameter_index
                annotations.extend(annotation_set)

        buffer_wrapper.seek(cursor)
        return annotations

    @staticmethod
    def get_annotation_set(buffer_wrapper: BufferWrapper, header: DexFileHeader, offset: int) -> list[Annotation]:
        """Parse annotation set.

        https://source.android.com/docs/core/runtime/dex-format#annotation-set-item
        https://source.android.com/docs/core/runtime/dex-format#annotation-off-item
        https://source.android.com/docs/core/runtime/dex-format#annotation-item

        Args:
            offset: Offset to annotation set

        Returns:
            List of annotations
        """
        annotations: list[Annotation] = []

        if offset == 0:
            return annotations

        cursor = buffer_wrapper.cursor
        buffer_wrapper.seek(offset)

        size = buffer_wrapper.read_u32()

        for i in range(size):
            buffer_wrapper.seek(offset + 4 + i * 4)  # offset + size + (index * annotation_set_item size)
            buffer_wrapper.seek(buffer_wrapper.read_u32())  # annotation set item offset

            visibility = buffer_wrapper.read_u8()

            # Only check runtime visible annotations
            if visibility != AnnotationVisibility.RUNTIME:
                continue

            type_idx = buffer_wrapper.read_uleb128()

            element_count = buffer_wrapper.read_uleb128()
            elements: dict[str, Any] = {}

            for j in range(element_count):
                element_name_index = buffer_wrapper.read_uleb128()
                element_name = DexBaseUtils.get_string(buffer_wrapper, header, element_name_index)
                value = DexBaseUtils.get_encoded_value(buffer_wrapper, header)
                elements[element_name] = value

            type_name = DexBaseUtils.get_type_name(buffer_wrapper, header, type_idx)

            annotations.append(Annotation(type_name=type_name, elements=elements))

        buffer_wrapper.seek(cursor)
        return annotations

    @staticmethod
    def get_encoded_value(buffer_wrapper: BufferWrapper, header: DexFileHeader) -> Any:
        """Parse encoded value.

        https://source.android.com/docs/core/runtime/dex-format#value-formats

        Returns:
            Parsed value
        """
        encoded_byte = buffer_wrapper.read_u8()
        value_type = encoded_byte & 0x1F
        value_arg = encoded_byte >> 5

        match value_type:
            case EncodedValueType.BYTE:
                return buffer_wrapper.read_u8()
            case EncodedValueType.SHORT:
                return buffer_wrapper.read_sized_int(value_arg + 1)
            case EncodedValueType.CHAR:
                return chr(buffer_wrapper.read_u16())
            case EncodedValueType.INT:
                return buffer_wrapper.read_sized_int(value_arg + 1)
            case EncodedValueType.LONG:
                return buffer_wrapper.read_sized_long(value_arg + 1)
            case EncodedValueType.FLOAT:
                return buffer_wrapper.read_sized_float(value_arg + 1)
            case EncodedValueType.DOUBLE:
                return buffer_wrapper.read_sized_double(value_arg + 1)
            case EncodedValueType.METHOD_TYPE:
                proto_index = buffer_wrapper.read_sized_uint(value_arg + 1)
                return DexBaseUtils.get_encoded_method_prototype(buffer_wrapper, header, proto_index)
            case EncodedValueType.METHOD_HANDLE:
                handle_type = buffer_wrapper.read_u16()
                buffer_wrapper.read_u16()  # unused
                field_or_method_index = buffer_wrapper.read_u16()
                buffer_wrapper.read_u16()  # unused
                return {
                    "field_or_method_index": field_or_method_index,
                    "handle_type": handle_type,
                }
            case EncodedValueType.STRING:
                string_index = buffer_wrapper.read_sized_uint(value_arg + 1)
                return DexBaseUtils.get_string(buffer_wrapper, header, string_index)
            case EncodedValueType.TYPE:
                type_index = buffer_wrapper.read_sized_uint(value_arg + 1)
                return DexBaseUtils.get_type_name(buffer_wrapper, header, type_index)
            case EncodedValueType.FIELD:
                field_index = buffer_wrapper.read_sized_uint(value_arg + 1)
                return DexBaseUtils.get_encoded_field(buffer_wrapper, header, field_index)
            case EncodedValueType.METHOD:
                method_index = buffer_wrapper.read_sized_uint(value_arg + 1)
                return DexBaseUtils.get_encoded_method(buffer_wrapper, header, method_index)
            case EncodedValueType.ENUM:
                enum_field_index = buffer_wrapper.read_sized_uint(value_arg + 1)
                return DexBaseUtils.get_encoded_field(buffer_wrapper, header, enum_field_index)
            case EncodedValueType.ARRAY:
                return DexBaseUtils.get_encoded_array(buffer_wrapper, header)
            case EncodedValueType.ANNOTATION:
                return DexBaseUtils.get_encoded_annotation(buffer_wrapper, header)
            case EncodedValueType.NULL:
                return None
            case EncodedValueType.BOOLEAN:
                return value_arg != 0
            case _:
                raise ValueError(f"Unsupported encoded value type: {value_type:02x}")

    @staticmethod
    def get_encoded_method_prototype(
        buffer_wrapper: BufferWrapper, header: DexFileHeader, proto_index: int
    ) -> Prototype:
        """Get method prototype.

        https://source.android.com/docs/core/runtime/dex-format#proto-id-item

        Args:
            proto_index: Prototype index

        Returns:
            Method prototype
        """
        cursor = buffer_wrapper.cursor

        buffer_wrapper.seek(header.proto_ids_off + proto_index * 12)  # Each proto_id_item is 12 bytes

        shorty_idx = buffer_wrapper.read_u32()
        return_type_idx = buffer_wrapper.read_u32()
        parameters_off = buffer_wrapper.read_u32()

        shorty_descriptor = DexBaseUtils.get_string(buffer_wrapper, header, shorty_idx)
        return_type = DexBaseUtils.get_type_name(buffer_wrapper, header, return_type_idx)
        parameters: list[str] = []
        if parameters_off != 0:
            parameters = DexBaseUtils.get_type_list(buffer_wrapper, header, parameters_off)

        buffer_wrapper.seek(cursor)
        return Prototype(
            shorty_descriptor=shorty_descriptor,
            return_type=return_type,
            parameters=parameters,
        )

    @staticmethod
    def get_encoded_field(buffer_wrapper: BufferWrapper, header: DexFileHeader, field_index: int) -> str:
        cursor = buffer_wrapper.cursor

        buffer_wrapper.seek(header.field_ids_off + field_index * 8)  # Each field_id_item is 8 bytes

        class_index = buffer_wrapper.read_u16()
        type_index = buffer_wrapper.read_u16()
        name_index = buffer_wrapper.read_u32()

        class_name = DexBaseUtils.get_type_name(buffer_wrapper, header, class_index)
        type_name = DexBaseUtils.get_type_name(buffer_wrapper, header, type_index)
        name = DexBaseUtils.get_string(buffer_wrapper, header, name_index)

        buffer_wrapper.seek(cursor)
        return f"{class_name}->{name}:{type_name}"

    @staticmethod
    def get_encoded_method(buffer_wrapper: BufferWrapper, header: DexFileHeader, method_index: int) -> Method:
        """Get method reference.

        https://source.android.com/docs/core/runtime/dex-format#method-id-item

        Args:
            method_index: Method index

        Returns:
            Method information
        """
        cursor = buffer_wrapper.cursor

        buffer_wrapper.seek(header.method_ids_off + method_index * 8)  # Each method_id_item is 8 bytes

        class_index = buffer_wrapper.read_u16()
        proto_index = buffer_wrapper.read_u16()
        name_index = buffer_wrapper.read_u32()

        class_signature = DexBaseUtils.get_type_name(buffer_wrapper, header, class_index)
        prototype = DexBaseUtils.get_encoded_method_prototype(buffer_wrapper, header, proto_index)
        name = DexBaseUtils.get_string(buffer_wrapper, header, name_index)

        buffer_wrapper.seek(cursor)
        return Method(class_signature=class_signature, prototype=prototype, name=name)

    @staticmethod
    def get_encoded_array(buffer_wrapper: BufferWrapper, header: DexFileHeader) -> list[Any]:
        """Get encoded array.

        https://source.android.com/docs/core/runtime/dex-format#encoded-array

        Returns:
            List of values
        """
        size = buffer_wrapper.read_uleb128()
        values: list[Any] = []

        for i in range(size):
            values.append(DexBaseUtils.get_encoded_value(buffer_wrapper, header))

        return values

    @staticmethod
    def get_encoded_annotation(buffer_wrapper: BufferWrapper, header: DexFileHeader) -> Annotation:
        """Get encoded annotation.

        https://source.android.com/docs/core/runtime/dex-format#encoded-annotation

        Returns:
            Annotation
        """
        type_index = buffer_wrapper.read_uleb128()
        size = buffer_wrapper.read_uleb128()
        annotation = Annotation(
            type_name=DexBaseUtils.get_type_name(buffer_wrapper, header, type_index),
            elements={},
        )

        for i in range(size):
            name_index = buffer_wrapper.read_uleb128()
            name = DexBaseUtils.get_string(buffer_wrapper, header, name_index)
            annotation.elements[name] = DexBaseUtils.get_encoded_value(buffer_wrapper, header)

        return annotation

    @staticmethod
    def get_type_list(buffer_wrapper: BufferWrapper, header: DexFileHeader, type_list_offset: int) -> list[str]:
        """Get type list.

        https://source.android.com/docs/core/runtime/dex-format#type-list

        Args:
            type_list_offset: Type list offset

        Returns:
            List of type names
        """
        cursor = buffer_wrapper.cursor

        buffer_wrapper.seek(type_list_offset)

        size = buffer_wrapper.read_u32()
        types: list[str] = []
        for i in range(size):
            type_index = buffer_wrapper.read_u16()
            types.append(DexBaseUtils.get_type_name(buffer_wrapper, header, type_index))

        buffer_wrapper.seek(cursor)
        return types

    @staticmethod
    def get_type_name(buffer_wrapper: BufferWrapper, header: DexFileHeader, type_index: int) -> str:
        """Get type name by index.

        https://source.android.com/docs/core/runtime/dex-format#type-id-item

        Args:
            type_index: Type index

        Returns:
            Type name
        """
        cursor = buffer_wrapper.cursor

        buffer_wrapper.seek(header.type_ids_off + type_index * 4)  # Each type_id_item is 4 bytes

        string_index = buffer_wrapper.read_u32()
        string = DexBaseUtils.get_string(buffer_wrapper, header, string_index)
        buffer_wrapper.seek(cursor)

        return string

    @staticmethod
    def get_string(buffer_wrapper: BufferWrapper, header: DexFileHeader, string_index: int) -> str:
        """Get string by index.

        https://source.android.com/docs/core/runtime/dex-format#string-item
        https://source.android.com/docs/core/runtime/dex-format#string-data-item

        Args:
            buffer_wrapper: Buffer wrapper
            header: DEX file header
            string_index: String index

        Returns:
            String value
        """
        cursor = buffer_wrapper.cursor

        buffer_wrapper.seek(header.string_ids_off + string_index * 4)  # Each string_id_item is 4 bytes
        buffer_wrapper.seek(buffer_wrapper.read_u32())  # string data offset

        string_length = buffer_wrapper.read_uleb128()
        string = buffer_wrapper.read_string_with_length(string_length)

        buffer_wrapper.seek(cursor)
        return string

    @staticmethod
    def parse_access_flags(access_flags: int) -> list[AccessFlag]:
        """Parse access flags.

        https://source.android.com/docs/core/runtime/dex-format#access-flags

        Args:
            access_flags: Raw access flags value

        Returns:
            List of access flags
        """
        flags: list[AccessFlag] = []

        for flag in AccessFlag:
            if access_flags & flag:
                flags.append(flag)

        return flags
