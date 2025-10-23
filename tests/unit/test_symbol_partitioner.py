from launchpad.size.symbols.macho_symbol_sizes import SymbolSize
from launchpad.size.symbols.partitioner import SymbolInfo


class TestSymbolPartitioner:
    """Test cases for symbol partitioning logic."""

    def test_partition_empty_symbols(self):
        """Test partitioning with no symbols."""
        symbol_info = SymbolInfo.from_symbol_sizes([])

        assert len(symbol_info.symbol_sizes) == 0
        assert len(symbol_info.swift_type_groups) == 0
        assert len(symbol_info.objc_type_groups) == 0
        assert len(symbol_info.cpp_type_groups) == 0
        assert len(symbol_info.other_symbols) == 0
        assert len(symbol_info.compiler_generated_symbols) == 0

    def test_partition_swift_symbols(self):
        """Test that Swift symbols are correctly partitioned."""
        symbols = [
            SymbolSize(
                mangled_name="_$s6Sentry0A14OnDemandReplayC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x1000,
                size=100,
            ),
            SymbolSize(
                mangled_name="_$s6Sentry0A18UserFeedbackWidgetC5showVyF",
                section_name="__text",
                segment_name="__TEXT",
                address=0x2000,
                size=200,
            ),
        ]

        symbol_info = SymbolInfo.from_symbol_sizes(symbols)

        assert len(symbol_info.swift_type_groups) > 0
        assert len(symbol_info.objc_type_groups) == 0
        assert len(symbol_info.cpp_type_groups) == 0
        assert len(symbol_info.other_symbols) == 0
        assert len(symbol_info.compiler_generated_symbols) == 0

    def test_partition_objc_symbols(self):
        """Test that Objective-C symbols are correctly partitioned."""
        symbols = [
            SymbolSize(
                mangled_name="-[NSString stringByAppendingString:]",
                section_name="__text",
                segment_name="__TEXT",
                address=0x1000,
                size=150,
            ),
            SymbolSize(
                mangled_name="+[NSArray arrayWithObject:]",
                section_name="__text",
                segment_name="__TEXT",
                address=0x2000,
                size=120,
            ),
        ]

        symbol_info = SymbolInfo.from_symbol_sizes(symbols)

        assert len(symbol_info.swift_type_groups) == 0
        assert len(symbol_info.objc_type_groups) > 0
        assert len(symbol_info.cpp_type_groups) == 0
        assert len(symbol_info.other_symbols) == 0
        assert len(symbol_info.compiler_generated_symbols) == 0

    def test_partition_cpp_symbols(self):
        """Test that C++ symbols are correctly partitioned."""
        symbols = [
            SymbolSize(
                mangled_name="_ZN6sentry10profiling12ProfilerImplC1Ev",
                section_name="__text",
                segment_name="__TEXT",
                address=0x1000,
                size=200,
            ),
            SymbolSize(
                mangled_name="_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeEv",
                section_name="__text",
                segment_name="__TEXT",
                address=0x2000,
                size=100,
            ),
        ]

        symbol_info = SymbolInfo.from_symbol_sizes(symbols)

        assert len(symbol_info.swift_type_groups) == 0
        assert len(symbol_info.objc_type_groups) == 0
        assert len(symbol_info.cpp_type_groups) > 0
        assert len(symbol_info.other_symbols) == 0
        assert len(symbol_info.compiler_generated_symbols) == 0

    def test_partition_compiler_generated_symbols(self):
        """Test that compiler-generated symbols are correctly partitioned."""
        symbols = [
            SymbolSize(
                mangled_name="_OUTLINED_FUNCTION_123",
                section_name="__text",
                segment_name="__TEXT",
                address=0x1000,
                size=50,
            ),
            SymbolSize(
                mangled_name="_globalinit_token",
                section_name="__data",
                segment_name="__DATA",
                address=0x2000,
                size=8,
            ),
            SymbolSize(
                mangled_name="___Block_byref_id_object_copy_",
                section_name="__text",
                segment_name="__TEXT",
                address=0x3000,
                size=40,
            ),
        ]

        symbol_info = SymbolInfo.from_symbol_sizes(symbols)

        assert len(symbol_info.swift_type_groups) == 0
        assert len(symbol_info.objc_type_groups) == 0
        assert len(symbol_info.cpp_type_groups) == 0
        assert len(symbol_info.other_symbols) == 0
        assert len(symbol_info.compiler_generated_symbols) == 3

    def test_partition_other_symbols(self):
        """Test that other symbols (C functions) are correctly partitioned."""
        symbols = [
            SymbolSize(
                mangled_name="_malloc",
                section_name="__text",
                segment_name="__TEXT",
                address=0x1000,
                size=100,
            ),
            SymbolSize(
                mangled_name="_free",
                section_name="__text",
                segment_name="__TEXT",
                address=0x2000,
                size=80,
            ),
        ]

        symbol_info = SymbolInfo.from_symbol_sizes(symbols)

        assert len(symbol_info.swift_type_groups) == 0
        assert len(symbol_info.objc_type_groups) == 0
        assert len(symbol_info.cpp_type_groups) == 0
        assert len(symbol_info.other_symbols) == 2
        assert len(symbol_info.compiler_generated_symbols) == 0

    def test_partition_mixed_symbols(self):
        """Test that mixed symbol types are correctly partitioned."""
        symbols = [
            # Swift
            SymbolSize(
                mangled_name="_$s6Sentry0A14OnDemandReplayC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x1000,
                size=100,
            ),
            # Objective-C
            SymbolSize(
                mangled_name="-[NSString stringByAppendingString:]",
                section_name="__text",
                segment_name="__TEXT",
                address=0x2000,
                size=150,
            ),
            # C++
            SymbolSize(
                mangled_name="_ZN6sentry10profiling12ProfilerImplC1Ev",
                section_name="__text",
                segment_name="__TEXT",
                address=0x3000,
                size=200,
            ),
            # Compiler-generated
            SymbolSize(
                mangled_name="_OUTLINED_FUNCTION_123",
                section_name="__text",
                segment_name="__TEXT",
                address=0x4000,
                size=50,
            ),
            # C function
            SymbolSize(
                mangled_name="_malloc",
                section_name="__text",
                segment_name="__TEXT",
                address=0x5000,
                size=100,
            ),
        ]

        symbol_info = SymbolInfo.from_symbol_sizes(symbols)

        # Each category should have at least one symbol
        assert len(symbol_info.swift_type_groups) > 0
        assert len(symbol_info.objc_type_groups) > 0
        assert len(symbol_info.cpp_type_groups) > 0
        assert len(symbol_info.other_symbols) == 1
        assert len(symbol_info.compiler_generated_symbols) == 1

    def test_is_compiler_generated(self):
        """Test compiler-generated symbol detection."""
        # Compiler-generated patterns
        assert SymbolInfo._is_compiler_generated("_OUTLINED_FUNCTION_123")
        assert SymbolInfo._is_compiler_generated("_globalinit_token")
        assert SymbolInfo._is_compiler_generated("___Block_byref_id_object_copy_")
        assert SymbolInfo._is_compiler_generated("___copy_helper_block_")
        assert SymbolInfo._is_compiler_generated("___destroy_helper_block_")
        assert SymbolInfo._is_compiler_generated("___swift_instantiateConcreteTypeFromMangledName")
        assert SymbolInfo._is_compiler_generated("_objectdestroy.123")

        # Non-compiler-generated symbols
        assert not SymbolInfo._is_compiler_generated("_malloc")
        assert not SymbolInfo._is_compiler_generated("_$s6Sentry0A14OnDemandReplayC")
        assert not SymbolInfo._is_compiler_generated("-[NSString stringByAppendingString:]")
        assert not SymbolInfo._is_compiler_generated("_ZN6sentry10profiling12ProfilerImplC1Ev")

    def test_no_double_counting(self):
        """Test that symbols are not double-counted across categories."""
        symbols = [
            SymbolSize(
                mangled_name="_$s6Sentry0A14OnDemandReplayC",
                section_name="__text",
                segment_name="__TEXT",
                address=0x1000,
                size=100,
            ),
            SymbolSize(
                mangled_name="-[NSString stringByAppendingString:]",
                section_name="__text",
                segment_name="__TEXT",
                address=0x2000,
                size=150,
            ),
            SymbolSize(
                mangled_name="_ZN6sentry10profiling12ProfilerImplC1Ev",
                section_name="__text",
                segment_name="__TEXT",
                address=0x3000,
                size=200,
            ),
            SymbolSize(
                mangled_name="_OUTLINED_FUNCTION_123",
                section_name="__text",
                segment_name="__TEXT",
                address=0x4000,
                size=50,
            ),
            SymbolSize(
                mangled_name="_malloc",
                section_name="__text",
                segment_name="__TEXT",
                address=0x5000,
                size=100,
            ),
        ]

        symbol_info = SymbolInfo.from_symbol_sizes(symbols)

        # Calculate total size from all partitions
        swift_total = sum(g.total_size for g in symbol_info.swift_type_groups)
        objc_total = sum(g.total_size for g in symbol_info.objc_type_groups)
        cpp_total = sum(g.total_size for g in symbol_info.cpp_type_groups)
        other_total = sum(s.size for s in symbol_info.other_symbols)
        compiler_total = sum(s.size for s in symbol_info.compiler_generated_symbols)

        # Sum should equal total input
        total_partitioned = swift_total + objc_total + cpp_total + other_total + compiler_total
        total_input = sum(s.size for s in symbols)
        assert total_partitioned == total_input
