import json

from pathlib import Path

import pytest

from click.testing import CliRunner

from launchpad.cli import cli
from launchpad.parsers.elf.debug_file import DebugFileMismatchError
from launchpad.parsers.elf.types import OwnershipQuality, SymbolSource
from launchpad.size.models.elf import ELFAnalysisResults
from launchpad.size.runner import do_size


def test_elf_class_breakdown_and_file_accounting(elf_sample: Path) -> None:
    results = do_size(elf_sample)

    assert isinstance(results, ELFAnalysisResults)
    assert results.format == "elf"
    assert results.treemap.root.size == results.file_size
    assert sum(child.size for child in results.treemap.root.children) == results.file_size
    assert (
        results.exact_size + results.estimated_size + results.shared_size + results.unattributed_size
        == results.file_size
    )

    widget = next(item for item in results.classes if item.name == "launchpad::Widget")
    assert widget.ownership_quality == OwnershipQuality.VERIFIED_CLASS
    assert widget.size > 0
    assert any(
        symbol.special_kind == "vtable"
        and symbol.owner == "launchpad::Widget"
        and symbol.demangled_name == "vtable for launchpad::Widget"
        for symbol in results.symbols
    )
    assert any(section.section_type == "nobits" and section.file_size == 0 for section in results.sections)


def test_elf_without_dwarf_marks_ownership_as_inferred(elf_sample_no_debug: Path) -> None:
    results = do_size(elf_sample_no_debug)

    assert isinstance(results, ELFAnalysisResults)
    widget = next(item for item in results.classes if item.name == "launchpad::Widget")
    assert widget.ownership_quality == OwnershipQuality.INFERRED_CPP_SCOPE
    assert any("inferred" in warning for warning in results.warnings)


def test_elf_uses_matching_separate_debug_file(elf_sample: Path, elf_sample_no_debug: Path) -> None:
    results = do_size(elf_sample_no_debug, debug_file=elf_sample)

    assert isinstance(results, ELFAnalysisResults)
    assert results.debug_source == SymbolSource.SEPARATE_DEBUG
    widget = next(item for item in results.classes if item.name == "launchpad::Widget")
    assert widget.ownership_quality == OwnershipQuality.VERIFIED_CLASS


def test_elf_rejects_mismatched_debug_file(elf_sample: Path, tmp_path: Path) -> None:
    mismatched = tmp_path / "mismatched.debug"
    data = bytearray(elf_sample.read_bytes())
    data[18:20] = (183).to_bytes(2, "little")
    mismatched.write_bytes(data)

    with pytest.raises(DebugFileMismatchError, match="architecture does not match"):
        do_size(elf_sample, debug_file=mismatched)


@pytest.mark.parametrize("elf_type", [1, 4])
def test_elf_rejects_unsupported_file_types(elf_sample: Path, tmp_path: Path, elf_type: int) -> None:
    unsupported = tmp_path / "unsupported"
    data = bytearray(elf_sample.read_bytes())
    data[16:18] = elf_type.to_bytes(2, "little")
    unsupported.write_bytes(data)

    with pytest.raises(ValueError, match="Unsupported ELF type"):
        do_size(unsupported)


def test_elf_rejects_truncated_input(elf_sample: Path, tmp_path: Path) -> None:
    truncated = tmp_path / "truncated"
    truncated.write_bytes(elf_sample.read_bytes()[:64])

    with pytest.raises(ValueError, match="Failed to parse ELF file"):
        do_size(truncated)


def test_elf_cli_auto_detects_input(elf_sample: Path, tmp_path: Path) -> None:
    output = tmp_path / "analysis.json"
    result = CliRunner().invoke(cli, ["size", str(elf_sample), "--quiet", "--output", str(output)])

    assert result.exit_code == 0, result.output
    data = json.loads(output.read_text())
    assert data["format"] == "elf"
    assert data["treemap"]["platform"] == "elf"
