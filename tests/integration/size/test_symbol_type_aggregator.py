"""Integration tests for SymbolTypeAggregator using real Mach-O binaries."""

import lief

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.size.symbols.macho_symbol_sizes import MachOSymbolSizes
from launchpad.size.symbols.swift_aggregator import SwiftSymbolTypeAggregator


class TestSymbolTypeAggregator:
    """Integration test cases for the SymbolTypeAggregator class using real binaries."""

    def test_init(self):
        """Test SymbolTypeAggregator initialization."""
        aggregator = SwiftSymbolTypeAggregator()
        assert aggregator.demangler is not None

    def test_aggregate_symbols_with_real_binary(self, hackernews_xcarchive_obj: ZippedXCArchive) -> None:
        """Test aggregation of symbols using real HackerNews app binary."""

        binary_infos = hackernews_xcarchive_obj.get_all_binary_paths()
        assert len(binary_infos) > 0, "Failed to find binaries in xcarchive"

        hackernews_binary_info = None
        for binary_info in binary_infos:
            if binary_info.name == "HackerNews":
                hackernews_binary_info = binary_info
                break

        assert hackernews_binary_info is not None, "Failed to find HackerNews binary"

        with open(hackernews_binary_info.dsym_path, "rb") as f:
            fat_binary = lief.MachO.parse(f)  # type: ignore
        assert fat_binary is not None, "Failed to parse binary with LIEF"

        binary = fat_binary.at(0)
        symbol_sizes = MachOSymbolSizes(binary).get_symbol_sizes()

        assert len(symbol_sizes) == 24465

        aggregator = SwiftSymbolTypeAggregator()
        result = aggregator.aggregate_symbols(symbol_sizes)
        assert len(result) == 708

        hackernews_app_view_model_group = next(
            group for group in result if group.module == "HackerNews" and group.type_name == "AppViewModel"
        )
        assert hackernews_app_view_model_group is not None, "Expected to find AppViewModel"

        assert hackernews_app_view_model_group.symbol_count == 99
        assert len(hackernews_app_view_model_group.symbols) == 99
        assert hackernews_app_view_model_group.total_size == 16436

    def test_aggregate_symbols_empty_input(self) -> None:
        """Test aggregation with empty input."""
        aggregator = SwiftSymbolTypeAggregator()
        result = aggregator.aggregate_symbols([])

        assert result == []
