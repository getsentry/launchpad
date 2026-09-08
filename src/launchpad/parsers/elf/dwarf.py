from __future__ import annotations

from pathlib import Path

from elftools.dwarf.die import DIE
from elftools.elf.elffile import ELFFile

from .types import DwarfOwner, OwnershipQuality

_OWNER_TAGS = {"DW_TAG_class_type", "DW_TAG_structure_type", "DW_TAG_union_type"}
_SYMBOL_TAGS = {"DW_TAG_subprogram", "DW_TAG_variable"}
_REFERENCE_ATTRIBUTES = ("DW_AT_specification", "DW_AT_abstract_origin")
_LINKAGE_ATTRIBUTES = ("DW_AT_linkage_name", "DW_AT_MIPS_linkage_name")


class DwarfOwnershipParser:
    def parse(self, path: Path) -> dict[str, DwarfOwner]:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            if not elf.has_dwarf_info():
                return {}
            owners: dict[str, DwarfOwner] = {}
            for compilation_unit in elf.get_dwarf_info().iter_CUs():
                for die in compilation_unit.iter_DIEs():
                    if die.tag not in _SYMBOL_TAGS:
                        continue
                    linkage_name = self._attribute_text(die, _LINKAGE_ATTRIBUTES)
                    if linkage_name is None:
                        continue
                    definition = self._referenced_definition(die)
                    owner = self._owner(definition)
                    if owner is not None:
                        owners[linkage_name] = owner
            return owners

    def _referenced_definition(self, die: DIE) -> DIE:
        current = die
        visited: set[int] = set()
        while current.offset not in visited:
            visited.add(current.offset)
            target = None
            for attribute in _REFERENCE_ATTRIBUTES:
                if attribute in current.attributes:
                    target = current.get_DIE_from_attribute(attribute)
                    break
            if target is None:
                return current
            current = target
        return current

    def _owner(self, die: DIE) -> DwarfOwner | None:
        components: list[str] = []
        has_class = False
        parent = die.get_parent()
        while parent is not None:
            if parent.tag in _OWNER_TAGS or parent.tag == "DW_TAG_namespace":
                name = self._attribute_text(parent, ("DW_AT_name",))
                if name:
                    components.append(name)
                if parent.tag in _OWNER_TAGS:
                    has_class = True
            parent = parent.get_parent()
        if not components:
            return None
        quality = OwnershipQuality.VERIFIED_CLASS if has_class else OwnershipQuality.NAMESPACE
        return DwarfOwner(name="::".join(reversed(components)), quality=quality)

    @staticmethod
    def _attribute_text(die: DIE, names: tuple[str, ...]) -> str | None:
        for name in names:
            attribute = die.attributes.get(name)
            if attribute is None:
                continue
            value = attribute.value
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            if isinstance(value, str):
                return value
        return None
