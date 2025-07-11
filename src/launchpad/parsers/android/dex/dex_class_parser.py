from launchpad.parsers.android.dex.dex_base_utils import DexBaseUtils
from launchpad.parsers.android.dex.types import (
    NO_INDEX,
    AccessFlag,
    Annotation,
    AnnotationsDirectory,
    DexFileHeader,
)
from launchpad.parsers.buffer_wrapper import BufferWrapper


class DexClassParser:
    def __init__(self, header: DexFileHeader, buffer_wrapper: BufferWrapper, offset: int):
        self._header = header
        self._buffer_wrapper = buffer_wrapper
        self._offset = offset

        self._buffer_wrapper.seek(self._offset)

        self._class_index = self._buffer_wrapper.read_u32()
        self._access_flags = self._buffer_wrapper.read_u32()
        self._superclass_index = self._buffer_wrapper.read_u32()
        self._interfaces_offset = self._buffer_wrapper.read_u32()
        self._source_file_idx = self._buffer_wrapper.read_u32()
        self._annotations_offset = self._buffer_wrapper.read_u32()
        self._class_data_offset = self._buffer_wrapper.read_u32()
        self._static_values_offset = self._buffer_wrapper.read_u32()

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

        # TODO: Methods size (direct & virtual)

        # TODO: Fields size (static & instance)

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

        return DexBaseUtils.get_annotations_directory(
            buffer_wrapper=self._buffer_wrapper,
            header=self._header,
            annotations_directory_offset=self._annotations_offset,
        )

    def get_annotations(self) -> list[Annotation]:
        annotations_directory = self._get_annotations_directory()
        if annotations_directory is None:
            return []

        return annotations_directory.class_annotations

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

    def _get_static_values_overhead_size(self) -> int:
        if self._static_values_offset == 0:
            return 0

        cursor = self._buffer_wrapper.cursor
        self._buffer_wrapper.seek(self._static_values_offset)

        static_values_size = self._buffer_wrapper.next_uleb128_size()

        self._buffer_wrapper.seek(cursor)

        return static_values_size
