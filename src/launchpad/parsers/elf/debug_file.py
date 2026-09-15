from __future__ import annotations

import zlib

from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection


class DebugFileMismatchError(ValueError):
    pass


class ELFDebugFileResolver:
    def resolve(self, binary_path: Path, explicit_path: Path | None = None) -> Path | None:
        if explicit_path is not None:
            self._validate(binary_path, explicit_path)
            return explicit_path

        debug_name, expected_crc = self._debug_link(binary_path)
        candidates: list[Path] = []
        if debug_name:
            candidates.extend((binary_path.parent / debug_name, binary_path.parent / ".debug" / debug_name))
        build_id = self._build_id(binary_path)
        if build_id and len(build_id) > 2:
            candidates.append(Path("/usr/lib/debug/.build-id") / build_id[:2] / f"{build_id[2:]}.debug")

        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                self._validate(binary_path, candidate, expected_crc)
            except DebugFileMismatchError:
                continue
            return candidate
        return None

    def build_id(self, path: Path) -> str | None:
        return self._build_id(path)

    def _validate(self, binary_path: Path, debug_path: Path, expected_crc: int | None = None) -> None:
        if not debug_path.is_file():
            raise FileNotFoundError(f"Debug file does not exist: {debug_path}")

        binary_build_id = self._build_id(binary_path)
        debug_build_id = self._build_id(debug_path)
        if binary_build_id and debug_build_id:
            if binary_build_id != debug_build_id:
                raise DebugFileMismatchError("Debug file build ID does not match the ELF file")
            return

        if expected_crc is None:
            _, expected_crc = self._debug_link(binary_path)
        if expected_crc is not None:
            actual_crc = zlib.crc32(debug_path.read_bytes()) & 0xFFFFFFFF
            if actual_crc != expected_crc:
                raise DebugFileMismatchError("Debug file CRC does not match .gnu_debuglink")
            return

        with binary_path.open("rb") as binary_stream, debug_path.open("rb") as debug_stream:
            binary = ELFFile(binary_stream)
            debug = ELFFile(debug_stream)
            identity = ("e_machine", "e_ident")
            if any(binary.header[key] != debug.header[key] for key in identity):
                raise DebugFileMismatchError("Debug file architecture does not match the ELF file")

    @staticmethod
    def _build_id(path: Path) -> str | None:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            for section in elf.iter_sections():
                if not isinstance(section, NoteSection):
                    continue
                for note in section.iter_notes():
                    if note["n_type"] != "NT_GNU_BUILD_ID":
                        continue
                    description = note["n_desc"]
                    if isinstance(description, bytes):
                        return description.hex()
                    return str(description).lower()
        return None

    @staticmethod
    def _debug_link(path: Path) -> tuple[str | None, int | None]:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            section = elf.get_section_by_name(".gnu_debuglink")
            if section is None:
                return None, None
            data = section.data()
            terminator = data.find(b"\0")
            if terminator < 0:
                return None, None
            name = data[:terminator].decode("utf-8", errors="replace")
            crc_offset = (terminator + 1 + 3) & ~3
            if crc_offset + 4 > len(data):
                return name, None
            byteorder = "little" if elf.little_endian else "big"
            return name, int.from_bytes(data[crc_offset : crc_offset + 4], byteorder)
