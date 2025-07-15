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
    # Method and field mappings for this class
    methods: dict[str, str] | None = None  # obfuscated_name -> deobfuscated_name
    fields: dict[str, str] | None = None  # obfuscated_name -> deobfuscated_name


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
        parts = trimmed.split(" -> ")
        if len(parts) != 2:
            return current_class

        left, obfuscated_name = parts

        # Parse line numbers
        line_parts = left.split(":")
        original_line_numbers: list[int] = []

        for i in range(min(2, len(line_parts))):
            part = line_parts[len(line_parts) - i - 1]
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

        # Parse method/field mapping
        # Remove line numbers from the left side
        if original_line_numbers:
            # Find the last colon that has a number after it
            last_colon_idx = -1
            for i, part in enumerate(line_parts):
                try:
                    int(part)
                    last_colon_idx = i
                except ValueError:
                    break

            if last_colon_idx >= 0:
                left = ":".join(line_parts[last_colon_idx + 1 :])

        # Determine if this is a method or field
        if "(" in left and ")" in left:
            if current_class.methods is None:
                current_class.methods = {}
            # Extract method name (everything before the first parenthesis)
            # Remove return type if present
            method_decl = left.split("(")[0].strip()
            if " " in method_decl:
                # e.g. 'void doSomething' -> 'doSomething'
                method_name = method_decl.split()[-1]
            else:
                method_name = method_decl
            current_class.methods[obfuscated_name] = method_name
        else:
            if current_class.fields is None:
                current_class.fields = {}
            # Extract field name (last part after the type)
            field_name = left.split()[-1].strip()
            current_class.fields[obfuscated_name] = field_name

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

    def deobfuscate_method(self, class_name: str, obfuscated_method_name: str) -> str | None:
        """Deobfuscate a method name for a given class.

        Args:
            class_name: The class name (can be obfuscated or deobfuscated)
            obfuscated_method_name: The obfuscated method name

        Returns:
            The deobfuscated method name, or None if not found
        """
        # First try to find the class by obfuscated name
        clazz = self.lookup_obfuscated_class(class_name)
        if clazz is None:
            # Try to find by deobfuscated signature
            clazz = self.lookup_deobfuscated_signature(class_name)
            if clazz is None:
                # Try to match by deobfuscated FQN
                for c in self._classes.values():
                    if c.deobfuscated_fqn == class_name:
                        clazz = c
                        break
                if clazz is None:
                    return None

        if clazz.methods is None:
            return None

        return clazz.methods.get(obfuscated_method_name)

    def deobfuscate_field(self, class_name: str, obfuscated_field_name: str) -> str | None:
        """Deobfuscate a field name for a given class.

        Args:
            class_name: The class name (can be obfuscated or deobfuscated)
            obfuscated_field_name: The obfuscated field name

        Returns:
            The deobfuscated field name, or None if not found
        """
        # First try to find the class by obfuscated name
        clazz = self.lookup_obfuscated_class(class_name)
        if clazz is None:
            # Try to find by deobfuscated signature
            clazz = self.lookup_deobfuscated_signature(class_name)
            if clazz is None:
                # Try to match by deobfuscated FQN
                for c in self._classes.values():
                    if c.deobfuscated_fqn == class_name:
                        clazz = c
                        break
                if clazz is None:
                    return None

        if clazz.fields is None:
            return None

        return clazz.fields.get(obfuscated_field_name)
