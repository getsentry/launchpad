import re

from dataclasses import dataclass


@dataclass
class DexMappingClass:
    """Represents a deobfuscated class mapping."""

    # The deobfuscated FQN of the class
    name: str
    # The deobfuscated signature of the class
    signature: str
    # The obfuscated FQN of the class
    obfuscated_name: str
    # The fileName if present
    file_name: str | None = None
    # Start line within file. This may not be present even if fileName is present
    start_line: int | None = None


class DexMapping:
    def __init__(self, bytes: bytes) -> None:
        self._classes: dict[str, DexMappingClass] = {}

        classes: list[DexMappingClass] = []
        current_class: DexMappingClass | None = None
        lines: list[str] = []

        # Split buffer into lines
        start = 0
        for i, byte in enumerate(bytes):
            if byte == ord("\n"):
                sub = bytes[start:i]
                line = sub.decode("utf-8")
                lines.append(line)
                start = i + 1

        # Parse the 'sourceFile' lines. The format of these lines is:
        # # {"id":"sourceFile","fileName":"CoroutineDebugging.kt"}
        file_name_re = re.compile(r'"fileName":"([^"]*)')

        def parse_comment(line: str) -> None:
            """Parse comment lines for source file information."""
            # Ignore comments at the start of the file
            if not current_class:
                return
            match = file_name_re.search(line)
            if match:
                file_name = match.group(1)
                current_class.file_name = file_name

        def parse_method_or_member(line: str) -> None:
            """Parse method or member lines for line number information.

            Format is one of:
            - originalfieldtype originalfieldname -> obfuscatedfieldname
            - [startline:endline:]originalreturntype [originalclassname.]originalmethodname(originalargumenttype,...)[:originalstartline[:originalendline]] -> obfuscatedmethodname
            """
            if not current_class:
                return

            trimmed = line.strip()
            left = trimmed.split(" -> ")[0]
            parts = left.split(":")
            original_line_numbers: list[int] = []

            for i in range(min(2, len(parts))):
                part = parts[len(parts) - i - 1]
                try:
                    n = int(part)
                    original_line_numbers.insert(0, n)
                except ValueError:
                    continue

            if original_line_numbers:
                start_line = original_line_numbers[0]
                if current_class.start_line is None:
                    current_class.start_line = start_line
                elif current_class.start_line == 0:
                    current_class.start_line = start_line

        def parse_class(line: str) -> None:
            """Parse class mapping lines.

            Format: originalclassname -> obfuscatedclassname:
            """
            # Remove ':' suffix
            line = line[:-1]

            # Split the line into obfuscated and original class names
            parts = line.split(" -> ")
            if len(parts) == 2:
                name, obfuscated_name = parts
                if name and obfuscated_name:
                    signature = fqn_to_class_signature(name)
                    clazz = DexMappingClass(
                        name=name,
                        signature=signature,
                        obfuscated_name=obfuscated_name,
                    )
                    classes.append(clazz)
                    nonlocal current_class
                    current_class = clazz

        # Parse all lines
        for line in lines:
            if line.startswith("#"):
                parse_comment(line)
            elif line.startswith(" "):
                trimmed = line.strip()
                if trimmed.startswith("#"):
                    parse_comment(line)
                else:
                    parse_method_or_member(line)
            elif line.endswith(":"):
                parse_class(line)

        for clazz in classes:
            self._classes[clazz.obfuscated_name] = clazz

    def deobfuscate(self, obfuscated_class_name: str) -> str | None:
        clazz = self._classes.get(obfuscated_class_name)
        return clazz.name if clazz else None

    def deobfuscate_signature(self, obfuscated_signature: str) -> str | None:
        clazz = self.lookup_obfuscated_signature(obfuscated_signature)
        return clazz.signature if clazz else None

    def lookup_obfuscated_signature(self, obfuscated_signature: str) -> DexMappingClass | None:
        obfuscated_fqn = class_signature_to_fqn(obfuscated_signature)
        return self.lookup_obfuscated_class(obfuscated_fqn)

    def lookup_obfuscated_class(self, obfuscated_class_name: str) -> DexMappingClass | None:
        return self._classes.get(obfuscated_class_name)

    def lookup_deobfuscated_signature(self, deobfuscated_class_signature: str) -> DexMappingClass | None:
        for clazz in self._classes.values():
            if clazz.signature == deobfuscated_class_signature:
                return clazz
        return None


# TODO: Share
def class_signature_to_fqn(class_signature: str) -> str:
    # Remove leading 'L' and trailing ';' if they exist
    if class_signature.startswith("L"):
        class_signature = class_signature[1:]
    if class_signature.endswith(";"):
        class_signature = class_signature[:-1]

    return class_signature.replace("/", ".")


# TODO: Share``
def fqn_to_class_signature(fqn: str) -> str:
    """Convert a fully qualified name to a class signature.

    Args:
        fqn: Fully qualified name (e.g., "com.example.MyClass")

    Returns:
        Class signature (e.g., "Lcom/example/MyClass;")
    """
    fqn = fqn.replace(".", "/")
    return f"L{fqn};"


def remove_kotlin_suffix_from_signature(class_signature: str) -> str:
    return re.sub(r"Kt(?=[$/;])", "", class_signature)


def remove_kotlin_suffix_from_fqn(fqn: str) -> str:
    return re.sub(r"Kt(?=[$.]|\b)", "", fqn)
