from launchpad.size.symbols.macho_symbol_sizes import SymbolSize
from launchpad.size.symbols.swift_aggregator import SwiftSymbolTypeAggregator
from launchpad.size.symbols.types import SwiftSymbolList


class TestSwiftSymbolTypeAggregator:
    """Test cases for the SwiftSymbolTypeAggregator class."""

    def test_init(self):
        """Test aggregator initialization."""
        aggregator = SwiftSymbolTypeAggregator()
        assert aggregator.demangler is not None

    def test_aggregate_symbols_empty(self):
        """Test aggregating empty symbol list."""
        aggregator = SwiftSymbolTypeAggregator()
        result = aggregator.aggregate_symbols(SwiftSymbolList())
        assert result == []

    def test_is_swift_symbol_modern_mangling(self):
        """Test Swift symbol detection for modern mangling (_$s prefix)."""
        # Modern Swift mangling
        assert SwiftSymbolTypeAggregator.is_swift_symbol("_$s6Sentry0A14OnDemandReplayC")
        assert SwiftSymbolTypeAggregator.is_swift_symbol("_$s6Sentry0A18UserFeedbackWidgetC5showVyF")
        assert SwiftSymbolTypeAggregator.is_swift_symbol("_$s10HackerNews11AppViewModelC")

    def test_is_swift_symbol_old_mangling(self):
        """Test Swift symbol detection for older mangling (_Tt prefix)."""
        # Older Swift mangling
        assert SwiftSymbolTypeAggregator.is_swift_symbol("_TtC6Sentry14OnDemandReplay")
        assert SwiftSymbolTypeAggregator.is_swift_symbol("_Tt")

    def test_is_swift_symbol_objc_metadata(self):
        """Test Swift symbol detection for ObjC runtime metadata."""
        # Swift classes exposed to ObjC with metadata
        assert SwiftSymbolTypeAggregator.is_swift_symbol("__IVARS__TtC6Sentry14OnDemandReplay")
        assert SwiftSymbolTypeAggregator.is_swift_symbol("__DATA__TtC6Sentry14OnDemandReplay")
        assert SwiftSymbolTypeAggregator.is_swift_symbol("_OBJC_CLASS_$__TtC6Sentry14OnDemandReplay")

    def test_is_swift_symbol_non_swift(self):
        """Test that non-Swift symbols are correctly identified."""
        # Objective-C symbols
        assert not SwiftSymbolTypeAggregator.is_swift_symbol("-[NSString stringByAppendingString:]")
        assert not SwiftSymbolTypeAggregator.is_swift_symbol("+[NSArray arrayWithObject:]")
        assert not SwiftSymbolTypeAggregator.is_swift_symbol("_OBJC_CLASS_$_NSString")

        # C++ symbols
        assert not SwiftSymbolTypeAggregator.is_swift_symbol("_ZN6sentry10profiling12ProfilerImplC1Ev")
        assert not SwiftSymbolTypeAggregator.is_swift_symbol(
            "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeEv"
        )

        # C functions
        assert not SwiftSymbolTypeAggregator.is_swift_symbol("_malloc")
        assert not SwiftSymbolTypeAggregator.is_swift_symbol("_free")
        assert not SwiftSymbolTypeAggregator.is_swift_symbol("_main")

        # Compiler-generated
        assert not SwiftSymbolTypeAggregator.is_swift_symbol("_OUTLINED_FUNCTION_123")
        assert not SwiftSymbolTypeAggregator.is_swift_symbol("_globalinit_token")

    def test_aggregate_symbols_with_swift_symbols(self):
        """Test aggregating Swift symbols (basic test without demangling verification)."""
        aggregator = SwiftSymbolTypeAggregator()

        symbols = [
            SymbolSize(
                mangled_name="_$s6Sentry0A14OnDemandReplayC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x1000,
                size=100,
            ),
            SymbolSize(
                mangled_name="_$s6Sentry0A18UserFeedbackWidgetC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x2000,
                size=200,
            ),
            SymbolSize(
                mangled_name="_$s10HackerNews11AppViewModelC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x3000,
                size=150,
            ),
        ]

        result = aggregator.aggregate_symbols(SwiftSymbolList(symbols))

        # Should have grouped the symbols (exact grouping depends on demangling)
        assert len(result) >= 1

        # Total size should be preserved
        total_size = sum(group.total_size for group in result)
        assert total_size == 450  # 100 + 200 + 150

        # Each group should have at least one symbol
        for group in result:
            assert group.symbol_count >= 1
            assert len(group.symbols) >= 1
            assert group.total_size > 0

    def test_aggregate_symbols_mixed_modules(self):
        """Test aggregating Swift symbols from different modules."""
        aggregator = SwiftSymbolTypeAggregator()

        symbols = [
            # Sentry module
            SymbolSize(
                mangled_name="_$s6Sentry0A14OnDemandReplayC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x1000,
                size=100,
            ),
            # HackerNews module
            SymbolSize(
                mangled_name="_$s10HackerNews11AppViewModelC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x2000,
                size=200,
            ),
            # Another Sentry symbol
            SymbolSize(
                mangled_name="_$s6Sentry0A18UserFeedbackWidgetC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x3000,
                size=150,
            ),
        ]

        result = aggregator.aggregate_symbols(SwiftSymbolList(symbols))

        # Should have at least 2 groups (one per module minimum)
        assert len(result) >= 2

        # Total size should be preserved
        total_size = sum(group.total_size for group in result)
        assert total_size == 450  # 100 + 200 + 150

    def test_aggregate_symbols_with_size_zero(self):
        """Test that symbols with zero size are handled correctly."""
        aggregator = SwiftSymbolTypeAggregator()

        symbols = [
            SymbolSize(
                mangled_name="_$s6Sentry0A14OnDemandReplayC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x1000,
                size=0,
            ),
            SymbolSize(
                mangled_name="_$s6Sentry0A18UserFeedbackWidgetC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x2000,
                size=100,
            ),
        ]

        result = aggregator.aggregate_symbols(SwiftSymbolList(symbols))

        # Should still aggregate symbols even if some have zero size
        assert len(result) >= 1

        # Total size should only count non-zero symbols
        total_size = sum(group.total_size for group in result)
        assert total_size == 100

    def test_symbol_type_group_properties(self):
        """Test that SwiftSymbolTypeGroup properties work correctly."""
        aggregator = SwiftSymbolTypeAggregator()

        symbols = [
            SymbolSize(
                mangled_name="_$s6Sentry0A14OnDemandReplayC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x1000,
                size=100,
            ),
        ]

        result = aggregator.aggregate_symbols(SwiftSymbolList(symbols))

        # Should have at least one group
        assert len(result) >= 1

        # Verify group properties
        for group in result:
            assert group.module is not None
            assert group.type_name is not None
            assert group.components is not None
            assert isinstance(group.components, list)
            assert group.symbol_count == len(group.symbols)
            assert group.total_size == sum(s.size for s in group.symbols)
