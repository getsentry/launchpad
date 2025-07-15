import re

from dataclasses import dataclass

from launchpad.parsers.android.dex.android_code_utils import AndroidCodeUtils


@dataclass
class DexMappingClass:
    deobfuscated_fqn: str
    deobfuscated_signature: str
    obfuscated_fqn: str
    file_name: str | None = None
    # Start line within file. This may not be present even if fileName is present
    start_line: int | None = None


class DexMapping:
    def __init__(self, bytes: bytes) -> None:
        self._classes: dict[str, DexMappingClass] = {}

        classes: list[DexMappingClass] = []
        current_class: DexMappingClass | None = None
        pending_file_name: str | None = None

        lines = bytes.decode("utf-8").splitlines()

        for line in lines:
            if line.startswith("#"):
                pending_file_name = self._parse_comment(line, pending_file_name)
            elif line.startswith(" "):
                trimmed = line.strip()
                if trimmed.startswith("#"):
                    pending_file_name = self._parse_comment(line, pending_file_name)
                else:
                    current_class = self._parse_method_or_member(line, current_class)
            elif line.endswith(":"):
                current_class, pending_file_name = self._parse_class(line, current_class, pending_file_name, classes)

        for clazz in classes:
            self._classes[clazz.obfuscated_fqn] = clazz

    @staticmethod
    def _parse_comment(line: str, pending_file_name: str | None) -> str | None:
        # Parse the 'sourceFile' lines. The format of these lines is:
        # # {"id":"sourceFile","fileName":"CoroutineDebugging.kt"}
        file_name_re = re.compile(r'"fileName":"([^"]*)')
        match = file_name_re.search(line)
        if match:
            return match.group(1)
        return pending_file_name

    @staticmethod
    def _parse_method_or_member(line: str, current_class: DexMappingClass | None) -> DexMappingClass | None:
        """Parse method or member lines for line number information.

        Format is one of:
        - originalfieldtype originalfieldname -> obfuscatedfieldname
        - [startline:endline:]originalreturntype [originalclassname.]originalmethodname(originalargumenttype,...)[:originalstartline[:originalendline]] -> obfuscatedmethodname
        """
        if not current_class:
            return current_class

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

        return current_class

    @staticmethod
    def _parse_class(
        line: str,
        current_class: DexMappingClass | None,
        pending_file_name: str | None,
        classes: list[DexMappingClass],
    ) -> tuple[DexMappingClass | None, str | None]:
        """Parse class mapping lines.

        Format: originalclassname -> obfuscatedclassname:
        """
        # Remove ':' suffix
        line = line[:-1]

        # Split the line into obfuscated and original class names
        parts = line.split(" -> ")
        if len(parts) == 2:
            name, obfuscated_fqn = parts
            if name and obfuscated_fqn:
                signature = AndroidCodeUtils.fqn_to_class_signature(name)
                clazz = DexMappingClass(
                    deobfuscated_fqn=name,
                    deobfuscated_signature=signature,
                    obfuscated_fqn=obfuscated_fqn,
                )
                # If a pending file name was found in a comment before this class, assign it
                if pending_file_name is not None:
                    clazz.file_name = pending_file_name
                    pending_file_name = None
                classes.append(clazz)
                current_class = clazz
                return current_class, pending_file_name

        return current_class, pending_file_name

    def deobfuscate(self, obfuscated_class_name: str) -> str | None:
        clazz = self._classes.get(obfuscated_class_name)
        return clazz.deobfuscated_fqn if clazz else None

    def deobfuscate_signature(self, obfuscated_signature: str) -> str | None:
        clazz = self.lookup_obfuscated_signature(obfuscated_signature)
        return clazz.deobfuscated_signature if clazz else None

    def lookup_obfuscated_signature(self, obfuscated_signature: str) -> DexMappingClass | None:
        obfuscated_fqn = AndroidCodeUtils.class_signature_to_fqn(obfuscated_signature)
        return self.lookup_obfuscated_class(obfuscated_fqn)

    def lookup_obfuscated_class(self, obfuscated_class_name: str) -> DexMappingClass | None:
        return self._classes.get(obfuscated_class_name)

    def lookup_deobfuscated_signature(self, deobfuscated_class_signature: str) -> DexMappingClass | None:
        for clazz in self._classes.values():
            if clazz.deobfuscated_signature == deobfuscated_class_signature:
                return clazz
        return None
