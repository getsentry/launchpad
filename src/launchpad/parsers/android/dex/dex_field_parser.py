from launchpad.parsers.android.dex.dex_base_utils import DexBaseUtils
from launchpad.parsers.android.dex.types import (
    Annotation,
    AnnotationsDirectory,
    DexFileHeader,
    EncodedValue,
)
from launchpad.parsers.buffer_wrapper import BufferWrapper


class DexFieldParser:
    def __init__(
        self,
        buffer_wrapper: BufferWrapper,
        header: DexFileHeader,
        field_index: int,
        initial_value: EncodedValue | None,
        field_overhead: int,
        annotations_directory: AnnotationsDirectory | None,
    ):
        self._buffer_wrapper = buffer_wrapper
        self._header = header
        self._index = field_index
        self._initial_value = initial_value
        self._field_overhead = field_overhead
        self._annotations_directory = annotations_directory

        cursor = self._buffer_wrapper.cursor
        self._buffer_wrapper.seek(header.field_ids_off + self._index * 8)

        class_index = self._buffer_wrapper.read_u16()
        type_index = self._buffer_wrapper.read_u16()
        name_index = self._buffer_wrapper.read_u32()

        self._class_name = DexBaseUtils.get_type_name(self._buffer_wrapper, header, class_index)
        self._type_name = DexBaseUtils.get_type_name(self._buffer_wrapper, header, type_index)
        self._name = DexBaseUtils.get_string(self._buffer_wrapper, header, name_index)

        self._buffer_wrapper.seek(cursor)

    def get_signature(self) -> str:
        return f"{self._class_name}->{self._name}:{self._type_name}"

    def get_annotations(self) -> list[Annotation]:
        if self._annotations_directory is None:
            return []

        for field_annotation in self._annotations_directory.field_annotations:
            if field_annotation.field_index == self._index:
                return DexBaseUtils.get_annotation_set(
                    self._buffer_wrapper,
                    self._header,
                    field_annotation.annotations_offset,
                )

        return []

    def get_size(self) -> int:
        """Calculate private size contribution of this field.

        This includes only the field's private data (initial values, etc.)
        """
        size = self._field_overhead + 8  # 8 bytes for field reference

        # Add size for initial value if present (this is the field's private data)
        if self._initial_value is not None:
            size += self._initial_value.size

        # Add size for annotations if present
        annotations = self.get_annotations()
        for _ in annotations:
            size += 8  # 8 bytes for annotation reference

        return size
