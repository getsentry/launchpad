from launchpad.parsers.android.dex.dex_mapping import DexMapping
from launchpad.parsers.android.dex.types import (
    AccessFlag,
    Annotation,
    DexFileHeader,
    EncodedValue,
    Field,
)
from launchpad.parsers.buffer_wrapper import BufferWrapper


class DexFieldParser:
    def __init__(
        self,
        buffer_wrapper: BufferWrapper,
        header: DexFileHeader,
        initial_value: EncodedValue | None,
        field_overhead: int,
        class_name: str,
        type_name: str,
        name: str,
        access_flags: list[AccessFlag],
        annotations: list[Annotation],
        dex_mapping: DexMapping | None = None,
    ):
        self._buffer_wrapper = buffer_wrapper
        self._header = header
        self._initial_value = initial_value
        self._field_overhead = field_overhead
        self._class_name = class_name
        self._type_name = type_name
        self._name = name
        self._access_flags = access_flags
        self._annotations = annotations
        self._dex_mapping = dex_mapping

    def parse(self) -> Field:
        return Field(
            size=self.get_size(),
            signature=self.get_signature(),
            access_flags=self._access_flags,
            annotations=self._annotations,
        )

    def get_signature(self) -> str:
        class_name = self._class_name
        name = self._name
        type_name = self._type_name

        # Apply deobfuscation if mapping is available
        if self._dex_mapping is not None:
            # Deobfuscate class name
            deobfuscated_class = self._dex_mapping.deobfuscate(class_name)
            if deobfuscated_class is not None:
                class_name = deobfuscated_class

        return f"{class_name}->{name}:{type_name}"

    def get_size(self) -> int:
        """Calculate private size contribution of this field.

        This includes only the field's private data (initial values, etc.)
        """
        size = self._field_overhead + 8  # 8 bytes for field reference

        # Add size for initial value if present (this is the field's private data)
        if self._initial_value is not None:
            size += self._initial_value.size

        # Add size for annotations if present
        annotations = self._annotations
        for _ in annotations:
            size += 8  # 8 bytes for annotation reference

        return size
