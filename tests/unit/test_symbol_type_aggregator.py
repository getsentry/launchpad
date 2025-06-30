from unittest.mock import Mock, patch

from launchpad.parsers.apple.macho_symbol_sizes import (
    SymbolSize,
    SymbolTypeAggregator,
    SymbolTypeGroup,
)
from launchpad.utils.cwl_demangle import CwlDemangleResult


class TestSymbolTypeAggregator:
    """Test cases for the SymbolTypeAggregator class."""

    def test_init(self):
        """Test SymbolTypeAggregator initialization."""
        aggregator = SymbolTypeAggregator()
        assert aggregator.demangler is not None

    @patch("launchpad.parsers.apple.macho_symbol_sizes.CwlDemangler")
    def test_aggregate_symbols_success(self, mock_demangler_class: Mock) -> None:
        """Test successful aggregation of symbols by type."""
        # Mock the demangler
        mock_demangler = Mock()
        mock_demangler_class.return_value = mock_demangler

        # Create mock demangled results
        mock_results = {
            "_$s6Module4Type1C": CwlDemangleResult(
                name="Module.Type1",
                type="class",
                identifier="Type1",
                module="Module",
                testName=["Module", "Type1"],
                typeName="Type1",
                description="Module.Type1",
                mangled="_$s6Module4Type1C",
            ),
            "_$s6Module4Type2C": CwlDemangleResult(
                name="Module.Type2",
                type="class",
                identifier="Type2",
                module="Module",
                testName=["Module", "Type2"],
                typeName="Type2",
                description="Module.Type2",
                mangled="_$s6Module4Type2C",
            ),
            "_$s7Unknown4Type3C": CwlDemangleResult(
                name="Unknown.Type3",
                type="class",
                identifier="Type3",
                module="Unknown",
                testName=["Unknown", "Type3"],
                typeName="Type3",
                description="Unknown.Type3",
                mangled="_$s7Unknown4Type3C",
            ),
        }
        mock_demangler.demangle_all.return_value = mock_results

        # Create test symbol sizes
        symbol_sizes = [
            SymbolSize(
                mangled_name="_$s6Module4Type1C", demangled_name="Module.Type1", section=None, address=0x1000, size=100
            ),
            SymbolSize(
                mangled_name="_$s6Module4Type1C", demangled_name="Module.Type1", section=None, address=0x2000, size=150
            ),
            SymbolSize(
                mangled_name="_$s6Module4Type2C", demangled_name="Module.Type2", section=None, address=0x3000, size=200
            ),
            SymbolSize(
                mangled_name="_$s7Unknown4Type3C", demangled_name="Unknown.Type3", section=None, address=0x4000, size=75
            ),
            SymbolSize(
                mangled_name="unmangled_symbol",
                demangled_name="unmangled_symbol",
                section=None,
                address=0x5000,
                size=50,
            ),
        ]

        aggregator = SymbolTypeAggregator()
        result = aggregator.aggregate_symbols(symbol_sizes)

        # Verify demangler was called correctly
        mock_demangler.add_name.assert_called()
        mock_demangler.demangle_all.assert_called_once()

        # Verify results
        assert len(result) == 4  # 3 demangled types + 1 unknown

        # Find the Type1 group (should have 2 symbols, total size 250)
        type1_group = next(g for g in result if g.type_name == "Type1" and g.module == "Module")
        assert type1_group.total_size == 250
        assert type1_group.symbol_count == 2
        assert len(type1_group.symbols) == 2

        # Find the Type2 group (should have 1 symbol, total size 200)
        type2_group = next(g for g in result if g.type_name == "Type2" and g.module == "Module")
        assert type2_group.total_size == 200
        assert type2_group.symbol_count == 1
        assert len(type2_group.symbols) == 1

        # Find the Type3 group (should have 1 symbol, total size 75)
        type3_group = next(g for g in result if g.type_name == "Type3" and g.module == "Unknown")
        assert type3_group.total_size == 75
        assert type3_group.symbol_count == 1

        # Find the unknown group (should have 1 symbol, total size 50)
        unknown_group = next(g for g in result if g.type_name == "Unknown" and g.module == "Unknown")
        assert unknown_group.total_size == 50
        assert unknown_group.symbol_count == 1

        # Verify sorting by total size (descending)
        assert result[0].total_size >= result[1].total_size
        assert result[1].total_size >= result[2].total_size
        assert result[2].total_size >= result[3].total_size

    @patch("launchpad.parsers.apple.macho_symbol_sizes.CwlDemangler")
    def test_aggregate_symbols_empty_input(self, mock_demangler_class: Mock) -> None:
        """Test aggregation with empty input."""
        mock_demangler = Mock()
        mock_demangler_class.return_value = mock_demangler
        mock_demangler.demangle_all.return_value = {}

        aggregator = SymbolTypeAggregator()
        result = aggregator.aggregate_symbols([])

        assert result == []
        mock_demangler.add_name.assert_not_called()
        mock_demangler.demangle_all.assert_called_once()

    @patch("launchpad.parsers.apple.macho_symbol_sizes.CwlDemangler")
    def test_aggregate_symbols_no_demangling_results(self, mock_demangler_class: Mock) -> None:
        """Test aggregation when demangling returns no results."""
        mock_demangler = Mock()
        mock_demangler_class.return_value = mock_demangler
        mock_demangler.demangle_all.return_value = {}

        symbol_sizes = [
            SymbolSize(
                mangled_name="unmangled_symbol1",
                demangled_name="unmangled_symbol1",
                section=None,
                address=0x1000,
                size=100,
            ),
            SymbolSize(
                mangled_name="unmangled_symbol2",
                demangled_name="unmangled_symbol2",
                section=None,
                address=0x2000,
                size=200,
            ),
        ]

        aggregator = SymbolTypeAggregator()
        result = aggregator.aggregate_symbols(symbol_sizes)

        # Should group all symbols under "Unknown" module and type
        assert len(result) == 1
        unknown_group = result[0]
        assert unknown_group.module == "Unknown"
        assert unknown_group.type_name == "Unknown"
        assert unknown_group.total_size == 300
        assert unknown_group.symbol_count == 2

    def test_symbol_type_group_dataclass(self) -> None:
        """Test SymbolTypeGroup dataclass creation and attributes."""
        symbols = [
            SymbolSize(mangled_name="test_symbol", demangled_name="test_symbol", section=None, address=0x1000, size=100)
        ]

        group = SymbolTypeGroup(module="TestModule", type_name="TestType", symbol_count=1, symbols=symbols)

        assert group.module == "TestModule"
        assert group.type_name == "TestType"
        assert group.total_size == 100
        assert group.symbol_count == 1
        assert len(group.symbols) == 1
        assert group.symbols[0].mangled_name == "test_symbol"
