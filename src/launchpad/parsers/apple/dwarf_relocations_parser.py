"""Parser for DWARF relocations YAML files found in dSYM bundles."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

import yaml

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DwarfRelocation:
    offset: int
    size: int
    addend: int
    sym_name: str
    sym_obj_addr: int | None
    sym_bin_addr: int
    sym_size: int

    @classmethod
    def from_dict(cls, data: dict) -> DwarfRelocation:
        return cls(
            offset=data["offset"],
            size=data["size"],
            addend=data["addend"],
            sym_name=data["symName"],
            sym_obj_addr=data["symObjAddr"] if "symObjAddr" in data else None,
            sym_bin_addr=data["symBinAddr"],
            sym_size=data["symSize"],
        )


@dataclass
class DwarfRelocationsData:
    """Represents the complete DWARF relocations data for a binary from a dSYM bundle."""

    triple: str
    binary_path: str
    relocations: List[DwarfRelocation]

    @property
    def total_relocation_size(self) -> int:
        return sum(reloc.sym_size for reloc in self.relocations)

    def get_relocations_by_symbol(self, symbol_name: str) -> List[DwarfRelocation]:
        return [reloc for reloc in self.relocations if reloc.sym_name == symbol_name]


class DwarfRelocationsParser:
    """Parser for DWARF relocations YAML files."""

    @staticmethod
    def parse(relocations_file_path: Path) -> DwarfRelocationsData | None:
        if not relocations_file_path.exists():
            logger.debug(f"Relocations file not found: {relocations_file_path}")
            return None

        try:
            with open(relocations_file_path) as f:
                data = yaml.safe_load(f)

            if not data:
                logger.warning(f"Empty or invalid YAML file: {relocations_file_path}")
                return None

            relocations: List[DwarfRelocation] = []
            if "relocations" in data and data["relocations"]:
                for reloc_dict in data["relocations"]:
                    try:
                        relocation = DwarfRelocation.from_dict(reloc_dict)
                        relocations.append(relocation)
                    except (KeyError, TypeError):
                        logger.exception("Failed to parse relocation entry")
                        continue

            return DwarfRelocationsData(
                triple=data.get("triple", ""),
                binary_path=data.get("binary-path", ""),
                relocations=relocations,
            )

        except yaml.YAMLError:
            logger.exception("Failed to parse YAML file")
            return None
        except Exception:
            logger.exception("Unexpected error parsing relocations file")
            return None
