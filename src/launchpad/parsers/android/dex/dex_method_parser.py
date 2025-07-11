from launchpad.parsers.android.dex.dex_base_utils import DexBaseUtils
from launchpad.parsers.android.dex.types import (
    Annotation,
    AnnotationsDirectory,
    DexFileHeader,
    Method,
)
from launchpad.parsers.buffer_wrapper import BufferWrapper


class DexMethodParser:
    def __init__(
        self,
        buffer_wrapper: BufferWrapper,
        header: DexFileHeader,
        method_index: int,
        code_offset: int,
        method_overhead: int,
        access_flags: int,
        annotations_directory: AnnotationsDirectory | None,
    ):
        self._buffer_wrapper = buffer_wrapper
        self._header = header
        self._method_index = method_index
        self._code_offset = code_offset
        self._method_overhead = method_overhead
        self._access_flags = access_flags
        self._annotations_directory = annotations_directory

        cursor = self._buffer_wrapper.cursor
        self._buffer_wrapper.seek(header.field_ids_off + self._method_index * 8)

        class_index = self._buffer_wrapper.read_u16()
        proto_index = self._buffer_wrapper.read_u16()
        name_index = self._buffer_wrapper.read_u32()

        self._class_name = DexBaseUtils.get_type_name(self._buffer_wrapper, header, class_index)
        self._prototype = DexBaseUtils.get_prototype(self._buffer_wrapper, header, proto_index)
        self._name = DexBaseUtils.get_string(self._buffer_wrapper, header, name_index)
        self._signature = f"{self._class_name}.{self._name}:{self._prototype.return_type}"

        self._buffer_wrapper.seek(cursor)

    def parse(self) -> Method:
        return Method(
            size=self.get_size(),
            name=self._name,
            signature=self._signature,
            prototype=self._prototype,
            access_flags=DexBaseUtils.parse_access_flags(self._access_flags),
            annotations=self.get_annotations(),
            parameters=[],  # TODO: Implement when needed in future
        )

    def get_annotations(self) -> list[Annotation]:
        if self._annotations_directory is None:
            return []

        for method_annotation in self._annotations_directory.method_annotations:
            if method_annotation.method_index == self._method_index:
                return DexBaseUtils.get_annotation_set(
                    self._buffer_wrapper,
                    self._header,
                    method_annotation.annotations_offset,
                )

        return []

    def get_size(self) -> int:
        """Calculate private size contribution of this method.

        This includes only the method's private data (code, debug info, etc.)
        and not the encoded_method overhead which is counted in class_data_overhead.
        """
        size = self._method_overhead + 8  # 8 bytes for method reference

        # Add code item size if present (this is the method's private data)
        if self._code_offset != 0:
            size += self._get_code_item_size()

        return size

    def _get_code_item_size(self) -> int:
        """Calculate size of code item."""
        if self._code_offset == 0:
            return 0

        cursor = self._buffer_wrapper.cursor
        self._buffer_wrapper.seek(self._code_offset)

        self._buffer_wrapper.read_u16()  # registers_size
        self._buffer_wrapper.read_u16()  # ins_size
        self._buffer_wrapper.read_u16()  # outs_size
        tries_size = self._buffer_wrapper.read_u16()
        debug_info_off = self._buffer_wrapper.read_u32()
        insns_size = self._buffer_wrapper.read_u32()

        # Fixed overhead - 4 ushort (2b) + 2 uint (4b)
        size = 16

        # Instruction size
        size += self._get_encoded_code_size(insns_size, tries_size)

        # Add debug info size if present
        if debug_info_off != 0:
            size += self._get_debug_info_size(debug_info_off)

        self._buffer_wrapper.seek(cursor)
        return size

    # https://source.android.com/docs/core/runtime/dex-format#code-item
    # Handles instructions, padding, tries and catch handlers
    def _get_encoded_code_size(self, insns_size: int, tries_size: int) -> int:
        size = 0

        # Each instruction is a ushort (2 bytes)
        size += insns_size * 2
        self._buffer_wrapper.skip(insns_size * 2)

        # Add padding for alignment (instructions must be 4-byte aligned)
        if insns_size % 2 == 1:
            size += 2
            self._buffer_wrapper.skip(2)

        # Add try items size if present
        if tries_size > 0:
            # Each try_item is 8 bytes: start_addr (uint32), insn_count (uint16), handler_off (uint16)
            size += tries_size * 8
            self._buffer_wrapper.skip(tries_size * 8)

            # Parse encoded_catch_handler_list to calculate its size
            # https://source.android.com/docs/core/runtime/dex-format#encoded-catch-handler-list
            start_catch = self._buffer_wrapper.cursor
            list_size = self._buffer_wrapper.read_uleb128()
            for _ in range(list_size):
                # encoded_catch_handler
                self._get_encoded_catch_handler_size()
            end_catch = self._buffer_wrapper.cursor
            size += end_catch - start_catch

        return size

    def _get_encoded_catch_handler_size(self) -> int:
        start = self._buffer_wrapper.cursor

        # Read size (sleb128)
        size = self._buffer_wrapper.read_leb128()

        # Read handlers if size > 0
        if size > 0:
            for _ in range(size):
                # encoded_type_addr_pair: type_idx (uleb128) + addr (uleb128)
                self._buffer_wrapper.read_uleb128()  # type_idx
                self._buffer_wrapper.read_uleb128()  # addr
        else:
            # size <= 0 means catch-all handler
            # Read catch_all_addr
            self._buffer_wrapper.read_uleb128()

        end = self._buffer_wrapper.cursor
        return end - start

    # https://source.android.com/docs/core/runtime/dex-format#debug-info-item
    def _get_debug_info_size(self, debug_info_off: int) -> int:
        if debug_info_off <= 0:
            return 0

        cursor = self._buffer_wrapper.cursor
        self._buffer_wrapper.seek(debug_info_off)

        start = self._buffer_wrapper.cursor

        # line_start: uleb128
        self._buffer_wrapper.read_uleb128()
        # parameters_size: uleb128
        parameters_size = self._buffer_wrapper.read_uleb128()

        # parameter_names: parameters_size * uleb128
        for _ in range(parameters_size):
            self._buffer_wrapper.read_uleb128()

        # Now parse the debug bytecode state machine until DBG_END_SEQUENCE (opcode 0x00)
        while True:
            opcode = self._buffer_wrapper.read_u8()
            # DBG_END_SEQUENCE
            if opcode == 0x00:
                break
            elif opcode == 0x01:  # DBG_ADVANCE_PC
                self._buffer_wrapper.read_uleb128()
            elif opcode == 0x02:  # DBG_ADVANCE_LINE
                self._buffer_wrapper.read_leb128()
            elif opcode == 0x03:  # DBG_START_LOCAL
                self._buffer_wrapper.read_uleb128()  # register_num
                self._buffer_wrapper.read_uleb128()  # name_idx
                self._buffer_wrapper.read_uleb128()  # type_idx
            elif opcode == 0x04:  # DBG_START_LOCAL_EXTENDED
                self._buffer_wrapper.read_uleb128()  # register_num
                self._buffer_wrapper.read_uleb128()  # name_idx
                self._buffer_wrapper.read_uleb128()  # type_idx
                self._buffer_wrapper.read_uleb128()  # sig_idx
            elif opcode == 0x05:  # DBG_END_LOCAL
                self._buffer_wrapper.read_uleb128()  # register_num
            elif opcode == 0x06:  # DBG_RESTART_LOCAL
                self._buffer_wrapper.read_uleb128()  # register_num
            elif opcode == 0x07:  # DBG_SET_PROLOGUE_END
                pass
            elif opcode == 0x08:  # DBG_SET_EPILOGUE_BEGIN
                pass
            elif opcode == 0x09:  # DBG_SET_FILE
                self._buffer_wrapper.read_uleb128()  # name_idx
            else:
                # Special opcodes (0x0a..0xff) have no operands
                pass

        end = self._buffer_wrapper.cursor
        size = end - start

        self._buffer_wrapper.seek(cursor)
        return size
