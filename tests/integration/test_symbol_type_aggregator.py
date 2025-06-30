"""Integration tests for SymbolTypeAggregator using real Mach-O binaries."""

import os

from pathlib import Path
from typing import List

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.parsers.apple.macho_symbol_sizes import MachOSymbolSizes, SymbolSize
from launchpad.parsers.apple.swift_symbol_type_aggregator import SwiftSymbolTypeAggregator


def is_darwin() -> bool:
    """Check if running on macOS."""
    return os.name == "posix" and os.uname().sysname == "Darwin"


def create_symbol_sizes_from_xcarchive(xcarchive_path: Path) -> List[SymbolSize]:
    """Create symbol sizes from an xcarchive for testing."""
    archive = ZippedXCArchive(xcarchive_path)

    binary_infos = archive.get_all_binary_paths()
    assert len(binary_infos) > 0, "Failed to find binaries in xcarchive"

    # Find the HackerNews main binary (should be the first one, which is the main executable)
    hackernews_binary_info = None
    for binary_info in binary_infos:
        if binary_info.name == "HackerNews" or "HackerNews" in binary_info.name:
            hackernews_binary_info = binary_info
            break

    # If we can't find HackerNews specifically, use the first binary (main executable)
    if hackernews_binary_info is None:
        hackernews_binary_info = binary_infos[0]

    # Use the dSYM file if available, otherwise fall back to the main binary
    binary_path = hackernews_binary_info.dsym_path if hackernews_binary_info.dsym_path else hackernews_binary_info.path

    import lief

    fat_binary = lief.MachO.parse(str(binary_path))  # type: ignore
    assert fat_binary is not None, "Failed to parse binary with LIEF"

    binary = fat_binary.at(0)
    symbol_sizes = MachOSymbolSizes(binary).get_symbol_sizes()
    return symbol_sizes


@pytest.mark.skipif(not is_darwin(), reason="cwl-demangle is only available on macOS")
class TestSymbolTypeAggregator:
    """Integration test cases for the SymbolTypeAggregator class using real binaries."""

    @pytest.fixture
    def sample_app_path(self) -> Path:
        return Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")

    def test_init(self):
        """Test SymbolTypeAggregator initialization."""
        aggregator = SwiftSymbolTypeAggregator()
        assert aggregator.demangler is not None

    def test_aggregate_symbols_with_real_binary(self, sample_app_path: Path) -> None:
        """Test aggregation of symbols using real HackerNews app binary."""
        symbol_sizes = create_symbol_sizes_from_xcarchive(sample_app_path)
        assert len(symbol_sizes) == 24466

        aggregator = SwiftSymbolTypeAggregator()
        result = aggregator.aggregate_symbols(symbol_sizes)
        assert len(result) == 708

        hackernews_app_view_model_group = None
        for group in result:
            if group.module == "HackerNews" and group.type_name == "AppViewModel":
                hackernews_app_view_model_group = group
                break
        assert hackernews_app_view_model_group is not None, "Expected to find HackerNews.AppViewModel group"

        assert hackernews_app_view_model_group.module == "HackerNews"
        assert hackernews_app_view_model_group.type_name == "AppViewModel"
        assert hackernews_app_view_model_group.symbol_count == 99
        assert len(hackernews_app_view_model_group.symbols) == 99
        assert hackernews_app_view_model_group.total_size == 16436

    def test_aggregate_symbols_empty_input(self) -> None:
        """Test aggregation with empty input."""
        aggregator = SwiftSymbolTypeAggregator()
        result = aggregator.aggregate_symbols([])

        assert result == []
