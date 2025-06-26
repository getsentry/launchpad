"""DEX file parser for Android applications."""

from __future__ import annotations

from typing import Any

from launchpad.parsers.android.dex.types import (
    ENDIAN_CONSTANT,
    NO_INDEX,
    AccessFlag,
    Annotation,
    AnnotationsDirectory,
    AnnotationVisibility,
    ClassDefinition,
    DexFileHeader,
    EncodedValueType,
    Method,
    MethodAnnotation,
    Parameter,
    ParameterAnnotation,
    Prototype,
)
from launchpad.parsers.buffer_wrapper import BufferWrapper
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class DexFileParser:
    def __init__(self, buffer: bytes) -> None:
        self.buffer_wrapper = BufferWrapper(buffer)
        self.header = self._read_header()

    def _read_header(self) -> DexFileHeader:
        """Read DEX file header.

        https://source.android.com/docs/core/runtime/dex-format#header-item

        Returns:
            DEX file header information

        Raises:
            ValueError: If file is not a valid DEX file
        """
        self.buffer_wrapper.seek(0)

        # First 8 bytes will be 'dex\n{version}\0', if not, invalid file
        magic = []
        for i in range(8):
            magic.append(chr(self.buffer_wrapper.read_u8()))

        if "".join(magic[:3]) != "dex":
            raise ValueError("Invalid dex file magic")

        version = "".join(magic[4:8])
        logger.debug(f"DEX file version: {version}")
        self.buffer_wrapper.read_u32()  # checksum
        self.buffer_wrapper.skip(20)  # signature
        self.buffer_wrapper.read_u32()  # file size
        self.buffer_wrapper.read_u32()  # header size
        endian_tag = self.buffer_wrapper.read_u32()

        if endian_tag != ENDIAN_CONSTANT:
            raise ValueError(f"Unsupported endian tag {endian_tag:08x}")

        self.buffer_wrapper.read_u32()  # link size
        self.buffer_wrapper.read_u32()  # link offset
        self.buffer_wrapper.read_u32()  # map offset
        self.buffer_wrapper.read_u32()  # string ids size
        string_ids_off = self.buffer_wrapper.read_u32()
        self.buffer_wrapper.read_u32()  # type ids size
        type_ids_off = self.buffer_wrapper.read_u32()
        self.buffer_wrapper.read_u32()  # prototype ids size
        proto_ids_off = self.buffer_wrapper.read_u32()  # prototype ids offset
        self.buffer_wrapper.read_u32()  # field ids size
        field_ids_off = self.buffer_wrapper.read_u32()  # field ids offset
        self.buffer_wrapper.read_u32()  # method ids size
        method_ids_off = self.buffer_wrapper.read_u32()
        class_defs_size = self.buffer_wrapper.read_u32()
        class_defs_off = self.buffer_wrapper.read_u32()
        self.buffer_wrapper.read_u32()  # data size
        self.buffer_wrapper.read_u32()  # data offset

        return DexFileHeader(
            class_defs_size=class_defs_size,
            class_defs_off=class_defs_off,
            string_ids_off=string_ids_off,
            type_ids_off=type_ids_off,
            field_ids_off=field_ids_off,
            method_ids_off=method_ids_off,
            proto_ids_off=proto_ids_off,
        )

    def get_class_definitions(self) -> list[ClassDefinition]:
        """Parse class definitions from the DEX file.

        https://source.android.com/docs/core/runtime/dex-format#class-def-item

        Returns:
            List of class definitions
        """
        class_defs: list[ClassDefinition] = []
        pending_superclasses: list[tuple[int, str]] = []
        pending_interfaces: list[tuple[int, list[str]]] = []
        class_by_signature: dict[str, ClassDefinition] = {}

        for i in range(self.header.class_defs_size):
            self.buffer_wrapper.seek(self.header.class_defs_off + i * 32)
            class_idx = self.buffer_wrapper.read_u32()
            access_flags = self._parse_access_flags(self.buffer_wrapper.read_u32())
            superclass_index = self.buffer_wrapper.read_u32()
            interfaces_offset = self.buffer_wrapper.read_u32()

            source_file_idx = self.buffer_wrapper.read_u32()
            annotations_offset = self.buffer_wrapper.read_u32()
            class_data_offset = self.buffer_wrapper.read_u32()  # Class data offset
            static_values_offset = self.buffer_wrapper.read_u32()  # static values offset
            signature = self._get_type_name(class_idx)

            if superclass_index != NO_INDEX:
                superclass_signature = self._get_type_name(superclass_index)
                pending_superclasses.append((i, superclass_signature))

            # Not NO_INDEX on purpose.
            if interfaces_offset != 0:
                pending_interfaces.append((i, self._get_type_list(interfaces_offset)))

            source_file_name: str | None = None
            if source_file_idx != NO_INDEX:
                source_file_name = self._get_string(source_file_idx)

            annotations_directory = self._parse_annotations_directory(annotations_offset)

            annotations: list[Annotation] = []
            if annotations_directory:
                annotations = self._parse_annotation_set(annotations_directory.class_annotations_offset)

            methods: list[Method] = []
            if class_data_offset != 0:
                methods = self._parse_method_definitions(class_data_offset, annotations_directory)

            class_def = ClassDefinition(
                signature=signature,
                source_file_name=source_file_name,
                annotations=annotations,
                methods=methods,
                access_flags=access_flags,
                superclass=None,
                interfaces=[],
                _class_data_offset=class_data_offset,
                _static_values_offset=static_values_offset,
            )
            class_by_signature[signature] = class_def
            class_defs.append(class_def)

        # Resolve superclass references
        for class_idx, superclass_signature in pending_superclasses:
            if superclass_signature in class_by_signature:
                class_defs[class_idx].superclass = class_by_signature[superclass_signature]

        # Resolve interface references
        for class_idx, signatures in pending_interfaces:
            class_def = class_defs[class_idx]
            for signature in signatures:
                if signature in class_by_signature:
                    class_def.interfaces.append(class_by_signature[signature])

        return class_defs

    def _parse_annotations_directory(self, annotations_directory_offset: int) -> AnnotationsDirectory | None:
        """Parse annotations directory.

        https://source.android.com/docs/core/runtime/dex-format#annotations-directory

        Args:
            annotations_directory_offset: Offset to annotations directory

        Returns:
            Annotations directory or None if not present
        """
        if annotations_directory_offset == 0:
            return None

        cursor = self.buffer_wrapper.cursor
        self.buffer_wrapper.seek(annotations_directory_offset)

        class_annotations_offset = self.buffer_wrapper.read_u32()
        fields_size = self.buffer_wrapper.read_u32()
        annotated_methods_size = self.buffer_wrapper.read_u32()
        annotated_parameters_size = self.buffer_wrapper.read_u32()

        # Skip fields for now
        self.buffer_wrapper.skip(8 * fields_size)  # field_annotation is 8 bytes

        method_annotations: list[MethodAnnotation] = []
        for i in range(annotated_methods_size):
            method_index = self.buffer_wrapper.read_u32()
            annotations_offset = self.buffer_wrapper.read_u32()
            method_annotations.append(
                MethodAnnotation(method_index=method_index, annotations_offset=annotations_offset)
            )

        parameter_annotations: list[ParameterAnnotation] = []
        for i in range(annotated_parameters_size):
            method_index = self.buffer_wrapper.read_u32()
            annotations_offset = self.buffer_wrapper.read_u32()
            parameter_annotations.append(
                ParameterAnnotation(method_index=method_index, annotations_offset=annotations_offset)
            )

        self.buffer_wrapper.seek(cursor)
        return AnnotationsDirectory(
            class_annotations_offset=class_annotations_offset,
            method_annotations=method_annotations,
            parameter_annotations=parameter_annotations,
        )

    def _parse_method_definitions(
        self, class_data_offset: int, annotations_directory: AnnotationsDirectory | None
    ) -> list[Method]:
        """Parse method definitions from class data.

        https://source.android.com/docs/core/runtime/dex-format#class-data-item

        Args:
            class_data_offset: Offset to class data
            annotations_directory: Annotations directory

        Returns:
            List of methods
        """
        methods: list[Method] = []

        if class_data_offset == 0:
            return methods

        self.buffer_wrapper.seek(class_data_offset)

        static_fields_size = self.buffer_wrapper.read_uleb128()
        instance_fields_size = self.buffer_wrapper.read_uleb128()
        direct_methods_size = self.buffer_wrapper.read_uleb128()
        virtual_methods_size = self.buffer_wrapper.read_uleb128()

        # Skip static fields and instance fields
        for i in range(static_fields_size):
            self.buffer_wrapper.read_uleb128()  # field index diff
            self.buffer_wrapper.read_uleb128()  # access flags

        for i in range(instance_fields_size):
            self.buffer_wrapper.read_uleb128()  # field index diff
            self.buffer_wrapper.read_uleb128()  # access flags

        direct_methods = self._parse_encoded_methods(direct_methods_size, annotations_directory)
        virtual_methods = self._parse_encoded_methods(virtual_methods_size, annotations_directory)

        methods.extend(direct_methods)
        methods.extend(virtual_methods)

        return methods

    def _parse_annotation_set_ref_list(self, offset: int) -> list[Annotation]:
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

        cursor = self.buffer_wrapper.cursor
        self.buffer_wrapper.seek(offset)

        size = self.buffer_wrapper.read_u32()

        for parameter_index in range(size):
            annotation_set_offset = self.buffer_wrapper.read_u32()
            if annotation_set_offset != 0:
                annotation_set = self._parse_annotation_set(annotation_set_offset)
                for annotation in annotation_set:
                    annotation.parameter_index = parameter_index
                annotations.extend(annotation_set)

        self.buffer_wrapper.seek(cursor)
        return annotations

    def _parse_annotation_set(self, offset: int) -> list[Annotation]:
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

        cursor = self.buffer_wrapper.cursor
        self.buffer_wrapper.seek(offset)

        size = self.buffer_wrapper.read_u32()

        for i in range(size):
            self.buffer_wrapper.seek(offset + 4 + i * 4)  # offset + size + (index * annotation_set_item size)
            self.buffer_wrapper.seek(self.buffer_wrapper.read_u32())  # annotation set item offset

            visibility = self.buffer_wrapper.read_u8()

            # Only check runtime visible annotations
            if visibility != AnnotationVisibility.RUNTIME:
                continue

            type_idx = self.buffer_wrapper.read_uleb128()

            element_count = self.buffer_wrapper.read_uleb128()
            elements: dict[str, Any] = {}

            for j in range(element_count):
                element_name_index = self.buffer_wrapper.read_uleb128()
                element_name = self._get_string(element_name_index)
                value = self._parse_encoded_value()
                elements[element_name] = value

            type_name = self._get_type_name(type_idx)

            annotations.append(Annotation(type_name=type_name, elements=elements))

        self.buffer_wrapper.seek(cursor)
        return annotations

    def _parse_encoded_value(self) -> Any:
        """Parse encoded value.

        https://source.android.com/docs/core/runtime/dex-format#value-formats

        Returns:
            Parsed value
        """
        encoded_byte = self.buffer_wrapper.read_u8()
        value_type = encoded_byte & 0x1F
        value_arg = encoded_byte >> 5

        match value_type:
            case EncodedValueType.BYTE:
                return self.buffer_wrapper.read_u8()
            case EncodedValueType.SHORT:
                return self.buffer_wrapper.read_sized_int(value_arg + 1)
            case EncodedValueType.CHAR:
                return chr(self.buffer_wrapper.read_u16())
            case EncodedValueType.INT:
                return self.buffer_wrapper.read_sized_int(value_arg + 1)
            case EncodedValueType.LONG:
                return self.buffer_wrapper.read_sized_long(value_arg + 1)
            case EncodedValueType.FLOAT:
                return self.buffer_wrapper.read_sized_float(value_arg + 1)
            case EncodedValueType.DOUBLE:
                return self.buffer_wrapper.read_sized_double(value_arg + 1)
            case EncodedValueType.METHOD_TYPE:
                proto_index = self.buffer_wrapper.read_sized_uint(value_arg + 1)
                return self._get_proto(proto_index)
            case EncodedValueType.METHOD_HANDLE:
                handle_type = self.buffer_wrapper.read_u16()
                self.buffer_wrapper.read_u16()  # unused
                field_or_method_index = self.buffer_wrapper.read_u16()
                self.buffer_wrapper.read_u16()  # unused
                return {
                    "field_or_method_index": field_or_method_index,
                    "handle_type": handle_type,
                }
            case EncodedValueType.STRING:
                string_index = self.buffer_wrapper.read_sized_uint(value_arg + 1)
                return self._get_string(string_index)
            case EncodedValueType.TYPE:
                type_index = self.buffer_wrapper.read_sized_uint(value_arg + 1)
                return self._get_type_name(type_index)
            case EncodedValueType.FIELD:
                field_index = self.buffer_wrapper.read_sized_uint(value_arg + 1)
                return self._get_field(field_index)
            case EncodedValueType.METHOD:
                method_index = self.buffer_wrapper.read_sized_uint(value_arg + 1)
                return self._get_method(method_index)
            case EncodedValueType.ENUM:
                enum_field_index = self.buffer_wrapper.read_sized_uint(value_arg + 1)
                return self._get_field(enum_field_index)
            case EncodedValueType.ARRAY:
                return self._parse_encoded_array()
            case EncodedValueType.ANNOTATION:
                return self._parse_encoded_annotation()
            case EncodedValueType.NULL:
                return None
            case EncodedValueType.BOOLEAN:
                return value_arg != 0
            case _:
                raise ValueError(f"Unsupported encoded value type: {value_type:02x}")

    def _parse_encoded_array(self) -> list[Any]:
        """Parse encoded array.

        https://source.android.com/docs/core/runtime/dex-format#encoded-array

        Returns:
            List of values
        """
        size = self.buffer_wrapper.read_uleb128()
        values: list[Any] = []

        for i in range(size):
            values.append(self._parse_encoded_value())

        return values

    def _parse_encoded_annotation(self) -> Annotation:
        """Parse encoded annotation.

        https://source.android.com/docs/core/runtime/dex-format#encoded-annotation

        Returns:
            Annotation
        """
        type_index = self.buffer_wrapper.read_uleb128()
        size = self.buffer_wrapper.read_uleb128()
        annotation = Annotation(type_name=self._get_type_name(type_index), elements={})

        for i in range(size):
            name_index = self.buffer_wrapper.read_uleb128()
            name = self._get_string(name_index)
            annotation.elements[name] = self._parse_encoded_value()

        return annotation

    def _parse_encoded_methods(self, size: int, annotations_directory: AnnotationsDirectory | None) -> list[Method]:
        """Parse encoded methods.

        Args:
            size: Number of methods
            annotations_directory: Annotations directory

        Returns:
            List of methods
        """
        methods: list[Method] = []

        method_index = 0
        for i in range(size):
            method_idx_diff = self.buffer_wrapper.read_uleb128()
            method_index += method_idx_diff
            access_flags = self._parse_access_flags(self.buffer_wrapper.read_uleb128())
            code_offset = self.buffer_wrapper.read_uleb128()

            parameter_names: list[str] = []
            if code_offset != 0:
                parameter_names = self._get_parameter_names(code_offset)

            method = self._get_method(method_index)

            annotations: list[Annotation] = []
            if annotations_directory:
                for method_annotation in annotations_directory.method_annotations:
                    if method_annotation.method_index == method_index:
                        annotations.extend(self._parse_annotation_set(method_annotation.annotations_offset))

            parameters = self._get_method_parameters(
                method.prototype.parameters,
                parameter_names,
                annotations_directory,
                method_index,
            )

            methods.append(
                Method(
                    class_signature=method.class_signature,
                    prototype=method.prototype,
                    name=method.name,
                    annotations=annotations,
                    access_flags=access_flags,
                    parameters=parameters,
                )
            )

        return methods

    def _get_method_parameters(
        self,
        parameter_types: list[str],
        parameter_names: list[str],
        annotations_directory: AnnotationsDirectory | None,
        method_index: int,
    ) -> list[Parameter]:
        """Get method parameters with annotations.

        Args:
            parameter_types: Parameter type names
            parameter_names: Parameter names
            annotations_directory: Annotations directory
            method_index: Method index

        Returns:
            List of parameters
        """
        parameter_annotations: list[Annotation] = []
        if annotations_directory:
            for parameter_annotation in annotations_directory.parameter_annotations:
                if parameter_annotation.method_index == method_index:
                    parameter_annotations = self._parse_annotation_set_ref_list(parameter_annotation.annotations_offset)
                    break

        annotation_index = 0
        parameters: list[Parameter] = []
        for index, param_type in enumerate(parameter_types):
            param_annotations: list[Annotation] = []
            while (
                annotation_index < len(parameter_annotations)
                and parameter_annotations[annotation_index].parameter_index == index
            ):
                param_annotations.append(parameter_annotations[annotation_index])
                annotation_index += 1

            parameters.append(
                Parameter(
                    type=param_type,
                    name=parameter_names[index] if index < len(parameter_names) else "",
                    annotations=param_annotations,
                )
            )

        return parameters

    def _get_parameter_names(self, code_offset: int) -> list[str]:
        """Get parameter names from debug info.

        Args:
            code_offset: Code item offset

        Returns:
            List of parameter names
        """
        cursor = self.buffer_wrapper.cursor

        try:
            self.buffer_wrapper.seek(code_offset)

            self.buffer_wrapper.read_u16()  # registers_size
            self.buffer_wrapper.read_u16()  # ins_size
            self.buffer_wrapper.read_u16()  # outs_size
            self.buffer_wrapper.read_u16()  # tries_size
            debug_item_off = self.buffer_wrapper.read_u32()

            # Parse debug_info_item
            self.buffer_wrapper.seek(debug_item_off)
            self.buffer_wrapper.read_uleb128()  # line_start
            parameters_size = self.buffer_wrapper.read_uleb128()
            parameter_names: list[str] = []

            # Skip for cases where params are beyond bounds of what we're looking for
            if parameters_size <= 3:
                for i in range(parameters_size):
                    name_idx = self.buffer_wrapper.read_uleb128() - 1
                    if name_idx != NO_INDEX:
                        parameter_names.append(self._get_string(name_idx))
                    else:
                        parameter_names.append("")

            self.buffer_wrapper.seek(cursor)
            return parameter_names
        except Exception:
            self.buffer_wrapper.seek(cursor)
            return []

    def _get_proto(self, proto_index: int) -> Prototype:
        """Get method prototype.

        https://source.android.com/docs/core/runtime/dex-format#proto-id-item

        Args:
            proto_index: Prototype index

        Returns:
            Method prototype
        """
        cursor = self.buffer_wrapper.cursor

        self.buffer_wrapper.seek(self.header.proto_ids_off + proto_index * 12)  # Each proto_id_item is 12 bytes

        shorty_idx = self.buffer_wrapper.read_u32()
        return_type_idx = self.buffer_wrapper.read_u32()
        parameters_off = self.buffer_wrapper.read_u32()

        shorty_descriptor = self._get_string(shorty_idx)
        return_type = self._get_type_name(return_type_idx)
        parameters: list[str] = []
        if parameters_off != 0:
            parameters = self._get_type_list(parameters_off)

        self.buffer_wrapper.seek(cursor)
        return Prototype(
            shorty_descriptor=shorty_descriptor,
            return_type=return_type,
            parameters=parameters,
        )

    def _get_type_list(self, type_list_offset: int) -> list[str]:
        """Get type list.

        https://source.android.com/docs/core/runtime/dex-format#type-list

        Args:
            type_list_offset: Type list offset

        Returns:
            List of type names
        """
        cursor = self.buffer_wrapper.cursor

        self.buffer_wrapper.seek(type_list_offset)

        size = self.buffer_wrapper.read_u32()
        types: list[str] = []
        for i in range(size):
            type_index = self.buffer_wrapper.read_u16()
            types.append(self._get_type_name(type_index))

        self.buffer_wrapper.seek(cursor)
        return types

    def _get_field(self, field_index: int) -> str:
        """Get field reference.

        https://source.android.com/docs/core/runtime/dex-format#field-id-item

        Args:
            field_index: Field index

        Returns:
            Field reference string
        """
        cursor = self.buffer_wrapper.cursor

        self.buffer_wrapper.seek(self.header.field_ids_off + field_index * 8)  # Each field_id_item is 8 bytes

        class_index = self.buffer_wrapper.read_u16()
        type_index = self.buffer_wrapper.read_u16()
        name_index = self.buffer_wrapper.read_u32()

        class_name = self._get_type_name(class_index)
        type_name = self._get_type_name(type_index)
        name = self._get_string(name_index)

        self.buffer_wrapper.seek(cursor)
        return f"{class_name}->{name}:{type_name}"

    def _get_method(self, method_index: int) -> Method:
        """Get method reference.

        https://source.android.com/docs/core/runtime/dex-format#method-id-item

        Args:
            method_index: Method index

        Returns:
            Method information
        """
        cursor = self.buffer_wrapper.cursor

        self.buffer_wrapper.seek(self.header.method_ids_off + method_index * 8)  # Each method_id_item is 8 bytes

        class_index = self.buffer_wrapper.read_u16()
        proto_index = self.buffer_wrapper.read_u16()
        name_index = self.buffer_wrapper.read_u32()

        class_signature = self._get_type_name(class_index)
        prototype = self._get_proto(proto_index)
        name = self._get_string(name_index)

        self.buffer_wrapper.seek(cursor)
        return Method(class_signature=class_signature, prototype=prototype, name=name)

    def _get_type_name(self, index: int) -> str:
        """Get type name by index.

        https://source.android.com/docs/core/runtime/dex-format#type-id-item

        Args:
            index: Type index

        Returns:
            Type name
        """
        cursor = self.buffer_wrapper.cursor

        self.buffer_wrapper.seek(self.header.type_ids_off + index * 4)  # Each type_id_item is 4 bytes

        string_index = self.buffer_wrapper.read_u32()
        string = self._get_string(string_index)
        self.buffer_wrapper.seek(cursor)

        return string

    def _get_string(self, index: int) -> str:
        """Get string by index.

        https://source.android.com/docs/core/runtime/dex-format#string-item
        https://source.android.com/docs/core/runtime/dex-format#string-data-item

        Args:
            index: String index

        Returns:
            String value
        """
        cursor = self.buffer_wrapper.cursor

        self.buffer_wrapper.seek(self.header.string_ids_off + index * 4)  # Each string_id_item is 4 bytes
        self.buffer_wrapper.seek(self.buffer_wrapper.read_u32())  # string data offset

        string_length = self.buffer_wrapper.read_uleb128()
        string = self.buffer_wrapper.read_string_with_length(string_length)
        self.buffer_wrapper.seek(cursor)

        return string

    def _parse_access_flags(self, access_flags: int) -> list[AccessFlag]:
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
