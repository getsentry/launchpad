from launchpad.parsers.android.dex.dex_base_utils import DexBaseUtils
from launchpad.parsers.android.dex.types import (
    NO_INDEX,
    Annotation,
    AnnotationsDirectory,
    ClassDefinition,
    DexFileHeader,
)
from launchpad.parsers.buffer_wrapper import BufferWrapper


class DexClassParser:
    def __init__(self, header: DexFileHeader, buffer_wrapper: BufferWrapper):
        self.header = header
        self.buffer_wrapper = buffer_wrapper

    def parse(self, class_index: int) -> ClassDefinition:
        original_cursor = self.buffer_wrapper.cursor

        self.buffer_wrapper.seek(self.header.class_defs_off + class_index * 32)

        class_idx = self.buffer_wrapper.read_u32()
        access_flags = DexBaseUtils.parse_access_flags(self.buffer_wrapper.read_u32())
        self.buffer_wrapper.read_u32()  # superclass_index
        interfaces_offset = self.buffer_wrapper.read_u32()  # interfaces_offset

        interfaces_size = 0
        if interfaces_offset != 0:
            # Potentially leverage the actual interfaces list instead of size in the future
            interfaces_size = DexBaseUtils.get_type_list(
                buffer_wrapper=self.buffer_wrapper,
                header=self.header,
                type_list_offset=interfaces_offset,
            ).__len__()

        source_file_idx = self.buffer_wrapper.read_u32()
        annotations_offset = self.buffer_wrapper.read_u32()
        self.buffer_wrapper.read_u32()  # Class data offset
        self.buffer_wrapper.read_u32()  # static values offset
        signature = DexBaseUtils.get_type_name(
            buffer_wrapper=self.buffer_wrapper,
            header=self.header,
            type_index=class_idx,
        )

        source_file_name: str | None = None
        if source_file_idx != NO_INDEX:
            source_file_name = DexBaseUtils.get_string(
                buffer_wrapper=self.buffer_wrapper,
                header=self.header,
                string_index=source_file_idx,
            )

        annotations_directory = DexBaseUtils.get_annotations_directory(
            buffer_wrapper=self.buffer_wrapper,
            annotations_directory_offset=annotations_offset,
        )

        annotations: list[Annotation] = []
        if annotations_directory:
            annotations = DexBaseUtils.get_annotation_set(
                buffer_wrapper=self.buffer_wrapper,
                header=self.header,
                offset=annotations_directory.class_annotations_offset,
            )

        self.buffer_wrapper.seek(original_cursor)

        size = self.get_size(
            interface_size=interfaces_size,
            annotations_directory=annotations_directory,
        )

        return ClassDefinition(
            size=size,
            signature=signature,
            source_file_name=source_file_name,
            annotations=annotations,
            access_flags=access_flags,
        )

    def get_size(self, interface_size: int, annotations_directory: AnnotationsDirectory | None) -> int:
        size = 32  # class_def_item has 8 uint (4 byte) fields (class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off)
        size += 4  # type_ids size

        # add interface list size if any
        if interface_size > 0:
            # https://source.android.com/docs/core/runtime/dex-format#type-list
            size += 4
            # uint for size
            size += interface_size * 2
            # ushort per type_item

        # annotations directory size if it exists
        if annotations_directory is not None:
            # https://source.android.com/docs/core/runtime/dex-format#annotations-directory
            size += 4 * 4
            # 4 uints in annotations_directory_item

            class_annotations_size = annotations_directory.class_annotations.__len__()
            if class_annotations_size > 0:
                # https://source.android.com/docs/core/runtime/dex-format#annotation-set-item
                # uint for size
                size += 4
                # uint per annotation_off
                size += class_annotations_size * 4

        # TODO: Class data

        # TODO: Static values

        # TODO: Methods

        # TODO: Fields

        return size
