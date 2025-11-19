from __future__ import annotations

import bisect
import re

from dataclasses import dataclass, field
from pathlib import Path

import sentry_sdk

from ...utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class LinkmapObjectFile:
    file: str
    line_name: str
    library: str | None
    line: str
    syms: list[LinkmapSymbol] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"LinkmapObjectFile(file={self.file}, library={self.library})"


@dataclass
class LinkmapSymbol:
    addr: int
    name: str
    size: int
    obj_idx: int
    sect: LinkmapSection
    obj: LinkmapObjectFile | None = None

    def __repr__(self) -> str:
        return f"LinkmapSymbol(addr={hex(self.addr)}, name={self.name}, size={self.size}, obj={self.obj})"


@dataclass
class LinkmapSection:
    addr: int
    size: int
    seg: str
    name: str

    def __repr__(self) -> str:
        return f"LinkmapSection(addr={hex(self.addr)}, size={self.size}, seg={self.seg}, name={self.name})"


class LinkmapParser:
    """Parser for Xcode linkmap files.

    Linkmap files show how an executable's sections and symbols are laid out,
    including which object files contribute which symbols and their sizes.
    """

    _SYMBOL_PATTERN = re.compile(r"^(\S+)\s+(\S+)\s+\[(.*?)\]\s+(.*)")
    _LIBRARY_ARCHIVE_PATTERN = re.compile(r"^(.*)\((.*)\)$")

    def __init__(self, contents: str) -> None:
        self.objs: list[LinkmapObjectFile] = []
        self.syms: list[LinkmapSymbol] = []
        self._sects: list[LinkmapSection] = []

        self._parse(contents)

    @classmethod
    def from_path(cls, path: Path) -> LinkmapParser:
        with open(path, encoding="utf-8", errors="replace") as f:
            contents = f.read()
        return cls(contents)

    def symbolicate(self, addr: int) -> LinkmapSymbol | None:
        """Find the symbol that contains the given address using binary search."""
        if not self.syms:
            return None

        # Quick bounds check
        first_sym = self.syms[0]
        last_sym = self.syms[-1]
        if addr < first_sym.addr or addr > last_sym.addr + last_sym.size:
            return None

        # Binary search to find the symbol at or before this address
        # bisect_right gives us the insertion point; the symbol we want is at index-1
        idx = bisect.bisect_right(self.syms, addr, key=lambda sym: sym.addr)
        if idx == 0:
            return None

        # Check if addr falls within the symbol's range
        sym = self.syms[idx - 1]
        if sym.addr <= addr < sym.addr + sym.size:
            return sym

        return None

    @sentry_sdk.trace
    def _parse(self, contents: str) -> None:
        lines = [line for line in contents.split("\n") if line.strip()]

        obj_start = None
        sect_start = None
        sym_start = None
        strip_start = None

        for i, line in enumerate(lines):
            if line == "# Object files:":
                obj_start = i
            elif line == "# Sections:":
                sect_start = i
            elif line == "# Symbols:":
                sym_start = i
            elif line == "# Dead Stripped Symbols:":
                strip_start = i
                break  # This is typically the last section

        strip_start = strip_start or len(lines)

        if obj_start is None or sect_start is None or sym_start is None:
            logger.warning("Could not find required sections in linkmap file")
            return

        self._parse_sections(lines, sect_start + 1, sym_start)
        self._parse_object_files(lines, obj_start + 1, sect_start)
        self._parse_symbols(lines, sym_start + 2, strip_start)

        for sym in self.syms:
            if 0 <= sym.obj_idx < len(self.objs):
                obj = self.objs[sym.obj_idx]
                sym.obj = obj
                obj.syms.append(sym)

    def _parse_sections(self, lines: list[str], start: int, end: int) -> None:
        for i in range(start, end):
            line = lines[i]
            # Skip header lines
            if line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) >= 4:
                try:
                    addr = int(parts[0], 16)
                    size = int(parts[1], 16)
                    seg = parts[2]
                    name = parts[3]
                    self._sects.append(LinkmapSection(addr, size, seg, name))
                except ValueError:
                    # Skip lines that don't have valid hex addresses
                    logger.warning("Invalid section line", extra={"line": line})
                    continue

    def _parse_object_files(self, lines: list[str], start: int, end: int) -> None:
        for i in range(start, end):
            line = lines[i]
            bracket_end = line.find("]")
            if bracket_end == -1:
                continue

            line_name = line[bracket_end + 2 :]

            # Check if this is a library archive format: path/to/lib.a(object.o)
            match = self._LIBRARY_ARCHIVE_PATTERN.match(line_name)
            if match:
                library_path = match.group(1)
                file = match.group(2)

                # Extract library name, preserving .framework extension if present
                library_name = Path(library_path).name
                if ".framework" in library_path:
                    # For frameworks like /path/Sentry.framework/Sentry, extract "Sentry.framework"
                    parts = library_path.split("/")
                    for part in parts:
                        if ".framework" in part:
                            library_name = part
                            break

                obj = LinkmapObjectFile(
                    file=Path(file).name,
                    line_name=line_name,
                    library=library_name,
                    line=line,
                )
            else:
                obj = LinkmapObjectFile(
                    file=Path(line_name).name,
                    line_name=line_name,
                    library=None,
                    line=line,
                )

            self.objs.append(obj)

    def _parse_symbols(self, lines: list[str], start: int, end: int) -> None:
        for i in range(start, end):
            line = lines[i]
            match = self._SYMBOL_PATTERN.match(line)
            if not match:
                continue

            addr_str, size_str, obj_idx_str, name = match.groups()
            addr = int(addr_str, 16)
            size = int(size_str, 16)
            obj_idx = int(obj_idx_str)

            # Skip symbols with zero size
            if size == 0:
                continue

            # Find the section this symbol belongs to
            sect = self._find_section_for_address(addr)
            if not sect:
                logger.debug(f"Could not find section for symbol {name} at {hex(addr)}")
                continue

            sym = LinkmapSymbol(addr=addr, name=name, size=size, obj_idx=obj_idx, sect=sect)
            self.syms.append(sym)

    def _find_section_for_address(self, addr: int) -> LinkmapSection | None:
        for sect in self._sects:
            if sect.addr <= addr < sect.addr + sect.size:
                return sect
        return None
