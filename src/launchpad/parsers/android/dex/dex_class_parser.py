from launchpad.parsers.android.dex.dex_base_utils import DexBaseUtils
from launchpad.parsers.android.dex.dex_field_parser import DexFieldParser
from launchpad.parsers.android.dex.dex_method_parser import DexMethodParser
from launchpad.parsers.android.dex.types import (
    NO_INDEX,
    AccessFlag,
    Annotation,
    AnnotationsDirectory,
    ClassDefinition,
    DexFileHeader,
    Field,
    Method,
)
from launchpad.parsers.buffer_wrapper import BufferWrapper


class DexClassParser:
    def __init__(self, header: DexFileHeader, buffer_wrapper: BufferWrapper, offset: int):
        self._header = header
        self._buffer_wrapper = buffer_wrapper
        self._offset = offset

        # Cachable for later reuse
        self._static_fields = None
        self._instance_fields = None
        self._direct_methods = None
        self._virtual_methods = None
        self._annotations_directory = None
        self._buffer_wrapper.seek(self._offset)

        self._class_index = self._buffer_wrapper.read_u32()
        self._access_flags = self._buffer_wrapper.read_u32()
        self._superclass_index = self._buffer_wrapper.read_u32()
        self._interfaces_offset = self._buffer_wrapper.read_u32()
        self._source_file_idx = self._buffer_wrapper.read_u32()
        self._annotations_offset = self._buffer_wrapper.read_u32()
        self._class_data_offset = self._buffer_wrapper.read_u32()
        self._static_values_offset = self._buffer_wrapper.read_u32()

        self._static_field_values = []
        if self._static_values_offset != 0:
            self._buffer_wrapper.seek(self._static_values_offset)
            self._static_field_values = DexBaseUtils.get_encoded_array(
                self._buffer_wrapper,
                self._header,
            )

    def parse(self) -> ClassDefinition:
        return ClassDefinition(
            size=self.get_size(),
            signature=self.get_class_signature(),
            source_file_name=self.get_source_file_name(),
            interfaces=self.get_interfaces(),
            annotations=self.get_annotations(),
            access_flags=self.get_access_flags(),
            fields=self.get_fields(),
        )

    def get_class_signature(self) -> str:
        return DexBaseUtils.get_type_name(self._buffer_wrapper, self._header, self._class_index)

    def get_source_file_name(self) -> str | None:
        if self._source_file_idx == NO_INDEX:
            return None
        return DexBaseUtils.get_string(self._buffer_wrapper, self._header, self._source_file_idx)

    def get_access_flags(self) -> list[AccessFlag]:
        return DexBaseUtils.parse_access_flags(self._access_flags)

    def get_size(self) -> int:
        """Calculate private size of this class definition following smali pattern.

        Based on smali DexBackedClassDef.getSize() implementation:
        https://github.com/JesusFreke/smali/blob/2771eae0a11f07bd892732232e6ee4e32437230d/dexlib2/src/main/java/org/jf/dexlib2/dexbacked/DexBackedClassDef.java#L505
        """
        # Class definition field size (8 * uint fields (4 bytes) = 32 bytes)
        size = 32

        # Type ID size (4 bytes for the type_id reference)
        size += 4

        interfaces = self.get_interfaces()
        if interfaces.__len__() > 0:
            # 4 bytes (uint) for size + 2 bytes (ushort) per type
            size += 4 + len(interfaces) * 2

        annotations_directory = self._get_annotations_directory()
        if annotations_directory is not None:
            size += 16  # 4 * 4 bytes (uint) for fields in directory

            annotations = annotations_directory.class_annotations
            if annotations.__len__() > 0:
                # 4 bytes (uint) for size + 4 bytes (uint) per annotation
                size += 4 + annotations.__len__() * 4

        # Class data item overhead
        # actual class data size is calculated with methods & fields below
        size += self._get_class_data_overhead_size()

        # Static values overhead
        size += self._get_static_values_overhead_size()

        for method in self.get_methods():
            size += method.size

        for field in self.get_fields():
            size += field.size

        return size

    def get_interfaces(self) -> list[str]:
        if self._interfaces_offset == 0:
            return []

        cursor = self._buffer_wrapper.cursor

        self._buffer_wrapper.seek(self._interfaces_offset)
        size = self._buffer_wrapper.read_u32()

        interfaces: list[str] = []
        for _ in range(size):
            type_index = self._buffer_wrapper.read_u16()
            interfaces.append(DexBaseUtils.get_type_name(self._buffer_wrapper, self._header, type_index))

        self._buffer_wrapper.seek(cursor)

        return interfaces

    def _get_annotations_directory(self) -> AnnotationsDirectory | None:
        if self._annotations_offset == 0:
            return None

        if self._annotations_directory is not None:
            return self._annotations_directory

        annotations_directory = DexBaseUtils.get_annotations_directory(
            buffer_wrapper=self._buffer_wrapper,
            header=self._header,
            annotations_directory_offset=self._annotations_offset,
        )

        self._annotations_directory = annotations_directory
        return annotations_directory

    def get_annotations(self) -> list[Annotation]:
        annotations_directory = self._get_annotations_directory()
        if annotations_directory is None:
            return []

        return annotations_directory.class_annotations

    def get_methods(self) -> list[Method]:
        methods = []

        for method in self._get_direct_methods():
            methods.append(method)

        for method in self._get_virtual_methods():
            methods.append(method)

        return methods

    def _get_direct_methods(self) -> list[Method]:
        # Cache for later reuse
        if self._direct_methods is not None:
            return self._direct_methods

        if self._class_data_offset == 0:
            return []

        cursor = self._buffer_wrapper.cursor
        self._buffer_wrapper.seek(self._class_data_offset)

        static_fields_size = self._buffer_wrapper.read_uleb128()
        instance_fields_size = self._buffer_wrapper.read_uleb128()
        direct_methods_size = self._buffer_wrapper.read_uleb128()
        self._buffer_wrapper.read_uleb128()  # virtual_methods_size

        # Skip fields
        self._skip_fields(self._buffer_wrapper, static_fields_size + instance_fields_size)

        methods = []
        last_index = 0

        for _ in range(direct_methods_size):
            cursor = self._buffer_wrapper.cursor
            method_idx_diff = self._buffer_wrapper.read_uleb128()
            access_flags = self._buffer_wrapper.read_uleb128()
            code_offset = self._buffer_wrapper.read_uleb128()
            method_overhead = self._buffer_wrapper.cursor - cursor

            method_index = last_index + method_idx_diff
            last_index = method_index

            method_parser = DexMethodParser(
                buffer_wrapper=self._buffer_wrapper,
                header=self._header,
                method_index=method_index,
                code_offset=code_offset,
                method_overhead=method_overhead,
                annotations_directory=self._get_annotations_directory(),
            )

            method = Method(
                size=method_parser.get_size(),
                name=method_parser.name,
                signature=method_parser.signature,
                prototype=method_parser.prototype,
                access_flags=DexBaseUtils.parse_access_flags(access_flags),
                annotations=method_parser.get_annotations(),
                parameters=[],
            )

            methods.append(method)

        self._direct_methods = methods
        self._buffer_wrapper.seek(cursor)
        return methods

    def _get_virtual_methods(self) -> list[Method]:
        # Cache for later reuse
        if self._virtual_methods is not None:
            return self._virtual_methods

        if self._class_data_offset == 0:
            return []

        cursor = self._buffer_wrapper.cursor
        self._buffer_wrapper.seek(self._class_data_offset)

        static_fields_size = self._buffer_wrapper.read_uleb128()
        instance_fields_size = self._buffer_wrapper.read_uleb128()
        direct_methods_size = self._buffer_wrapper.read_uleb128()  # direct_methods_size
        virtual_methods_size = self._buffer_wrapper.read_uleb128()  # virtual_methods_size

        # Skip fields
        self._skip_fields(self._buffer_wrapper, static_fields_size + instance_fields_size)

        # Skip direct methods
        self._skip_methods(self._buffer_wrapper, direct_methods_size)

        methods = []
        last_index = 0

        for _ in range(virtual_methods_size):
            cursor = self._buffer_wrapper.cursor
            method_idx_diff = self._buffer_wrapper.read_uleb128()
            access_flags = self._buffer_wrapper.read_uleb128()
            code_offset = self._buffer_wrapper.read_uleb128()
            method_overhead = self._buffer_wrapper.cursor - cursor

            method_index = last_index + method_idx_diff
            last_index = method_index

            method_parser = DexMethodParser(
                buffer_wrapper=self._buffer_wrapper,
                header=self._header,
                method_index=method_index,
                code_offset=code_offset,
                method_overhead=method_overhead,
                annotations_directory=self._get_annotations_directory(),
            )

            method = Method(
                size=method_parser.get_size(),
                name=method_parser.name,
                signature=method_parser.signature,
                prototype=method_parser.prototype,
                access_flags=DexBaseUtils.parse_access_flags(access_flags),
                annotations=method_parser.get_annotations(),
                parameters=[],
            )

            methods.append(method)

        self._virtual_methods = methods
        self._buffer_wrapper.seek(cursor)
        return methods

    def get_fields(self) -> list[Field]:
        fields = []

        for field in self._get_static_fields():
            fields.append(field)

        for field in self._get_instance_fields():
            fields.append(field)

        return fields

    def _get_static_fields(self) -> list[Field]:
        # Cache for later reuse
        if self._static_fields is not None:
            return self._static_fields

        if self._class_data_offset == 0:
            return []

        cursor = self._buffer_wrapper.cursor
        self._buffer_wrapper.seek(self._class_data_offset)

        static_fields_size = self._buffer_wrapper.read_uleb128()
        self._buffer_wrapper.read_uleb128()  # instance_fields_size
        self._buffer_wrapper.read_uleb128()  # direct_methods_size
        self._buffer_wrapper.read_uleb128()  # virtual_methods_size

        fields = []
        last_index = 0

        for _ in range(static_fields_size):
            field_cursor = self._buffer_wrapper.cursor
            field_idx_diff = self._buffer_wrapper.read_uleb128()
            access_flags = self._buffer_wrapper.read_uleb128()
            field_overhead = self._buffer_wrapper.cursor - field_cursor

            field_index = last_index + field_idx_diff
            last_index = field_index

            if field_index < len(self._static_field_values):
                initial_value = self._static_field_values[field_index]
            else:
                initial_value = None

            field_parser = DexFieldParser(
                self._buffer_wrapper,
                self._header,
                field_index,
                initial_value,
                field_overhead,
                access_flags,
                self._get_annotations_directory(),
            )

            fields.append(field_parser.parse())

        self._buffer_wrapper.seek(cursor)
        self._static_fields = fields
        return fields

    def _get_instance_fields(self) -> list[Field]:
        # Cache for later reuse
        if self._instance_fields is not None:
            return self._instance_fields

        if self._class_data_offset == 0:
            return []

        cursor = self._buffer_wrapper.cursor
        self._buffer_wrapper.seek(self._class_data_offset)

        static_fields_size = self._buffer_wrapper.read_uleb128()
        instance_fields_size = self._buffer_wrapper.read_uleb128()
        self._buffer_wrapper.read_uleb128()  # direct_methods_size
        self._buffer_wrapper.read_uleb128()  # virtual_methods_size

        # Skip static fields
        for _ in range(static_fields_size):
            self._buffer_wrapper.read_uleb128()
            self._buffer_wrapper.read_uleb128()

        # Parse instance fields
        fields = []
        last_index = 0

        for _ in range(instance_fields_size):
            field_cursor = self._buffer_wrapper.cursor
            field_idx_diff = self._buffer_wrapper.read_uleb128()
            access_flags = self._buffer_wrapper.read_uleb128()
            field_overhead = self._buffer_wrapper.cursor - field_cursor

            field_index = last_index + field_idx_diff
            last_index = field_index

            field_parser = DexFieldParser(
                buffer_wrapper=self._buffer_wrapper,
                header=self._header,
                field_index=field_index,
                initial_value=None,  # Instance fields will always have a null initial value
                field_overhead=field_overhead,
                access_flags=access_flags,
                annotations_directory=self._get_annotations_directory(),
            )

            fields.append(field_parser.parse())

        self._buffer_wrapper.seek(cursor)
        self._instance_fields = fields
        return fields

    def _get_class_data_overhead_size(self) -> int:
        """Calculate overhead of class data item (not including method and field sizes).

        This includes only the class_data_item header overhead, not the actual
        field and method data which is counted separately.
        """
        if self._class_data_offset == 0:
            return 0

        cursor = self._buffer_wrapper.cursor

        self._buffer_wrapper.seek(self._class_data_offset)

        self._buffer_wrapper.read_uleb128()  # static_fields_size
        self._buffer_wrapper.read_uleb128()  # instance_fields_size
        self._buffer_wrapper.read_uleb128()  # direct_methods_size
        self._buffer_wrapper.read_uleb128()  # virtual_methods_size

        data_overhead_size = self._buffer_wrapper.cursor - self._class_data_offset

        self._buffer_wrapper.seek(cursor)

        return data_overhead_size

    # Only the overhead of the static values, not the actual values
    # Those are counted as part of the fields size
    def _get_static_values_overhead_size(self) -> int:
        if self._static_values_offset == 0:
            return 0

        cursor = self._buffer_wrapper.cursor
        self._buffer_wrapper.seek(self._static_values_offset)

        # Get the size of the static values array size, not the size field value or the values themselves
        static_values_size = self._buffer_wrapper.next_uleb128_size()

        self._buffer_wrapper.seek(cursor)

        return static_values_size

    def _skip_fields(self, buffer: BufferWrapper, count: int) -> None:
        """Skip field entries in class data."""
        for _ in range(count):
            buffer.read_uleb128()  # field_idx_diff
            buffer.read_uleb128()  # access_flags

    def _skip_methods(self, buffer: BufferWrapper, count: int) -> None:
        """Skip method entries in class data."""
        for _ in range(count):
            buffer.read_uleb128()  # method_idx_diff
            buffer.read_uleb128()  # access_flags
            buffer.read_uleb128()  # code_offset
