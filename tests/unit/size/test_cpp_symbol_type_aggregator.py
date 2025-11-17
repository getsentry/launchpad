from launchpad.size.symbols.cpp_aggregator import CppSymbolTypeAggregator
from launchpad.size.symbols.macho_symbol_sizes import SymbolSize
from launchpad.size.symbols.types import CppSymbolList


class TestCppSymbolTypeAggregator:
    def test_aggregate_symbols_empty(self):
        """Test aggregating empty symbol list."""
        aggregator = CppSymbolTypeAggregator()
        result = aggregator.aggregate_symbols(CppSymbolList())
        assert result == []

    def test_aggregate_symbols_only_swift(self):
        """Test aggregating symbols with only Swift symbols (treated as global namespace)."""
        aggregator = CppSymbolTypeAggregator()

        swift_symbols = [
            SymbolSize(
                mangled_name="_$s6Sentry0A14OnDemandReplayC",
                section_name=None,
                segment_name=None,
                address=0x1000,
                size=100,
            ),
            SymbolSize(
                mangled_name="_$s6Sentry0A18UserFeedbackWidgetC",
                section_name=None,
                segment_name=None,
                address=0x2000,
                size=200,
            ),
        ]

        result = aggregator.aggregate_symbols(CppSymbolList(swift_symbols))
        # Non-C++ symbols are grouped as "(global)" namespace
        assert len(result) == 2
        assert all(g.namespace == "(global)" for g in result)

    def test_aggregate_symbols_only_objc(self):
        """Test aggregating symbols with only Objective-C symbols (treated as global namespace)."""
        aggregator = CppSymbolTypeAggregator()

        objc_symbols = [
            SymbolSize(
                mangled_name="-[NSString stringByAppendingString:]",
                section_name=None,
                segment_name=None,
                address=0x1000,
                size=100,
            ),
            SymbolSize(
                mangled_name="+[NSArray arrayWithObject:]",
                section_name=None,
                segment_name=None,
                address=0x2000,
                size=200,
            ),
        ]

        result = aggregator.aggregate_symbols(CppSymbolList(objc_symbols))
        # Non-C++ symbols are grouped as "(global)" namespace
        assert len(result) == 2
        assert all(g.namespace == "(global)" for g in result)

    def test_aggregate_symbols_std_namespace(self):
        """Test aggregating C++ symbols from std namespace."""
        aggregator = CppSymbolTypeAggregator()

        symbols = [
            SymbolSize(
                mangled_name="_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeEv",
                section_name=None,
                segment_name=None,
                address=0x1000,
                size=100,
            ),
            SymbolSize(
                mangled_name="_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_",
                section_name=None,
                segment_name=None,
                address=0x2000,
                size=150,
            ),
            SymbolSize(
                mangled_name="_ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backERKi",
                section_name=None,
                segment_name=None,
                address=0x3000,
                size=80,
            ),
        ]

        result = aggregator.aggregate_symbols(CppSymbolList(symbols))

        # Should have grouped the symbols (namespace extraction may vary)
        assert len(result) >= 1
        total_size = sum(g.total_size for g in result)
        assert total_size == 330  # 100 + 150 + 80

    def test_aggregate_symbols_custom_namespace(self):
        """Test aggregating C++ symbols from custom namespaces."""
        aggregator = CppSymbolTypeAggregator()

        symbols = [
            SymbolSize(
                mangled_name="_ZN6sentry10profiling12ProfilerImplC1Ev",
                section_name=None,
                segment_name=None,
                address=0x1000,
                size=200,
            ),
            SymbolSize(
                mangled_name="_ZN6sentry10profiling12ProfilerImpl5startEv",
                section_name=None,
                segment_name=None,
                address=0x2000,
                size=150,
            ),
            SymbolSize(
                mangled_name="_ZN6sentry10profiling12ProfilerImpl4stopEv",
                section_name=None,
                segment_name=None,
                address=0x3000,
                size=180,
            ),
        ]

        result = aggregator.aggregate_symbols(CppSymbolList(symbols))

        # Should have groups under sentry::profiling namespace
        sentry_profiling_groups = [g for g in result if "sentry" in g.namespace and "profiling" in g.namespace]
        assert len(sentry_profiling_groups) >= 1
        total_size = sum(g.total_size for g in sentry_profiling_groups)
        assert total_size == 530  # 200 + 150 + 180

    def test_aggregate_symbols_mixed_namespaces(self):
        """Test aggregating C++ symbols from multiple namespaces."""
        aggregator = CppSymbolTypeAggregator()

        symbols = [
            # std namespace
            SymbolSize(
                mangled_name="_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeEv",
                section_name=None,
                segment_name=None,
                address=0x1000,
                size=100,
            ),
            # sentry namespace
            SymbolSize(
                mangled_name="_ZN6sentry10profiling12ProfilerImplC1Ev",
                section_name=None,
                segment_name=None,
                address=0x2000,
                size=200,
            ),
            # another std namespace symbol
            SymbolSize(
                mangled_name="_ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backERKi",
                section_name=None,
                segment_name=None,
                address=0x3000,
                size=80,
            ),
        ]

        result = aggregator.aggregate_symbols(CppSymbolList(symbols))

        assert len(result) >= 1
        total_size = sum(g.total_size for g in result)
        assert total_size == 380  # 100 + 200 + 80

    def test_is_cpp_symbol(self):
        """Test C++ symbol detection."""
        # C++ mangled names
        assert CppSymbolTypeAggregator.is_cpp_symbol("_ZN6sentry10profiling12ProfilerImplC1Ev")
        assert CppSymbolTypeAggregator.is_cpp_symbol(
            "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeEv"
        )

        # Non-C++ symbols
        assert not CppSymbolTypeAggregator.is_cpp_symbol("_$s6Sentry0A14OnDemandReplayC")  # Swift
        assert not CppSymbolTypeAggregator.is_cpp_symbol("-[NSString stringByAppendingString:]")  # ObjC
        assert not CppSymbolTypeAggregator.is_cpp_symbol("_some_c_function")  # C function
