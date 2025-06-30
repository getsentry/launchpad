from launchpad.parsers.apple.macho_symbol_sizes import SymbolSize
from launchpad.parsers.apple.objc_symbol_type_aggregator import ObjCSymbolTypeAggregator, ObjCSymbolTypeGroup


class TestObjCSymbolTypeAggregator:
    """Test cases for the ObjCSymbolTypeAggregator class."""

    def test_init(self):
        """Test ObjCSymbolTypeAggregator initialization."""
        aggregator = ObjCSymbolTypeAggregator()
        assert aggregator.objc_method_pattern is not None

    def test_aggregate_symbols_empty(self):
        """Test aggregating empty symbol list."""
        aggregator = ObjCSymbolTypeAggregator()
        result = aggregator.aggregate_symbols([])
        assert result == []

    def test_aggregate_symbols_only_swift(self):
        """Test aggregating symbols with only Swift symbols (should be filtered out)."""
        aggregator = ObjCSymbolTypeAggregator()

        swift_symbols = [
            SymbolSize(mangled_name="_$s6Sentry0A14OnDemandReplayC", section=None, address=0x1000, size=100),
            SymbolSize(mangled_name="_$s6Sentry0A18UserFeedbackWidgetC", section=None, address=0x2000, size=200),
        ]

        result = aggregator.aggregate_symbols(swift_symbols)
        assert result == []

    def test_aggregate_symbols_only_cpp(self):
        """Test aggregating symbols with only C++ symbols (should be filtered out)."""
        aggregator = ObjCSymbolTypeAggregator()

        cpp_symbols = [
            SymbolSize(
                mangled_name="_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeEv",
                section=None,
                address=0x1000,
                size=100,
            ),
            SymbolSize(
                mangled_name="_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_",
                section=None,
                address=0x2000,
                size=200,
            ),
        ]

        result = aggregator.aggregate_symbols(cpp_symbols)
        assert result == []

    def test_aggregate_symbols_mixed(self):
        """Test aggregating symbols with both Swift and Objective-C symbols."""
        aggregator = ObjCSymbolTypeAggregator()

        mixed_symbols = [
            # Swift symbols (should be filtered out)
            SymbolSize(mangled_name="_$s6Sentry0A14OnDemandReplayC", section=None, address=0x1000, size=100),
            SymbolSize(mangled_name="_$s6Sentry0A18UserFeedbackWidgetC", section=None, address=0x2000, size=200),
            # Objective-C symbols
            SymbolSize(mangled_name="-[NSString stringByAppendingString:]", section=None, address=0x3000, size=150),
            SymbolSize(
                mangled_name="-[NSString stringByAppendingPathComponent:]", section=None, address=0x4000, size=180
            ),
            SymbolSize(mangled_name="+[NSArray arrayWithObject:]", section=None, address=0x5000, size=120),
            SymbolSize(mangled_name="_OBJC_CLASS_$_NSString", section=None, address=0x6000, size=300),
        ]

        result = aggregator.aggregate_symbols(mixed_symbols)

        # Should have 4 groups: NSString methods (2 separate), NSArray methods, NSString metadata
        assert len(result) == 4

        # Find the NSString stringByAppendingString: method group
        nsstring_append_string = next(
            (
                group
                for group in result
                if group.class_name == "NSString" and group.method_name == "stringByAppendingString:"
            ),
            None,
        )
        assert nsstring_append_string is not None
        assert nsstring_append_string.symbol_count == 1
        assert nsstring_append_string.total_size == 150

        # Find the NSString stringByAppendingPathComponent: method group
        nsstring_append_path = next(
            (
                group
                for group in result
                if group.class_name == "NSString" and group.method_name == "stringByAppendingPathComponent:"
            ),
            None,
        )
        assert nsstring_append_path is not None
        assert nsstring_append_path.symbol_count == 1
        assert nsstring_append_path.total_size == 180

        # Find the NSArray methods group
        nsarray_methods = next((group for group in result if group.class_name == "NSArray"), None)
        assert nsarray_methods is not None
        assert nsarray_methods.symbol_count == 1
        assert nsarray_methods.total_size == 120

        # Find the NSString metadata group
        nsstring_metadata = next(
            (group for group in result if group.class_name == "NSString" and group.method_name is None), None
        )
        assert nsstring_metadata is not None
        assert nsstring_metadata.symbol_count == 1
        assert nsstring_metadata.total_size == 300

    def test_aggregate_symbols_with_categories(self):
        """Test aggregating symbols with Objective-C categories."""
        aggregator = ObjCSymbolTypeAggregator()

        symbols = [
            SymbolSize(mangled_name="-[NSString(MyCategory) customMethod]", section=None, address=0x1000, size=100),
            SymbolSize(mangled_name="-[NSString stringByAppendingString:]", section=None, address=0x2000, size=150),
            SymbolSize(
                mangled_name="-[NSString(AnotherCategory) anotherMethod]", section=None, address=0x3000, size=120
            ),
        ]

        result = aggregator.aggregate_symbols(symbols)

        # Should group each method separately (categories are stripped from class names)
        assert len(result) == 3

        # Find the customMethod group
        custom_method = next(
            (group for group in result if group.class_name == "NSString" and group.method_name == "customMethod"), None
        )
        assert custom_method is not None
        assert custom_method.symbol_count == 1
        assert custom_method.total_size == 100

        # Find the stringByAppendingString: group
        append_string = next(
            (
                group
                for group in result
                if group.class_name == "NSString" and group.method_name == "stringByAppendingString:"
            ),
            None,
        )
        assert append_string is not None
        assert append_string.symbol_count == 1
        assert append_string.total_size == 150

        # Find the anotherMethod group
        another_method = next(
            (group for group in result if group.class_name == "NSString" and group.method_name == "anotherMethod"), None
        )
        assert another_method is not None
        assert another_method.symbol_count == 1
        assert another_method.total_size == 120

    def test_aggregate_symbols_with_metadata(self):
        """Test aggregating symbols with Objective-C metadata symbols."""
        aggregator = ObjCSymbolTypeAggregator()

        symbols = [
            SymbolSize(mangled_name="_OBJC_CLASS_$_NSString", section=None, address=0x1000, size=300),
            SymbolSize(mangled_name="_OBJC_METACLASS_$_NSString", section=None, address=0x2000, size=200),
            SymbolSize(mangled_name="_OBJC_IVAR_$_NSString._internalString", section=None, address=0x3000, size=50),
            SymbolSize(mangled_name="-[NSString stringByAppendingString:]", section=None, address=0x4000, size=150),
        ]

        result = aggregator.aggregate_symbols(symbols)

        # Should have 3 groups: NSString metadata (class + metaclass), NSString method, NSString ivar
        assert len(result) == 3

        # Find the NSString metadata group (class + metaclass)
        nsstring_metadata = next(
            (
                group
                for group in result
                if group.class_name == "NSString" and group.method_name is None and group.symbol_count == 2
            ),
            None,
        )
        assert nsstring_metadata is not None
        assert nsstring_metadata.symbol_count == 2
        assert nsstring_metadata.total_size == 500  # 300 + 200

        # Find the NSString method group
        nsstring_method = next(
            (
                group
                for group in result
                if group.class_name == "NSString" and group.method_name == "stringByAppendingString:"
            ),
            None,
        )
        assert nsstring_method is not None
        assert nsstring_method.symbol_count == 1
        assert nsstring_method.total_size == 150

        # Find the NSString ivar group
        nsstring_ivar = next(
            (group for group in result if group.class_name == "NSString._internalString" and group.method_name is None),
            None,
        )
        assert nsstring_ivar is not None
        assert nsstring_ivar.symbol_count == 1
        assert nsstring_ivar.total_size == 50

    def test_objc_symbol_type_group_total_size(self):
        """Test ObjCSymbolTypeGroup total_size property."""
        symbols = [
            SymbolSize(mangled_name="test1", section=None, address=0x1000, size=100),
            SymbolSize(mangled_name="test2", section=None, address=0x2000, size=200),
            SymbolSize(mangled_name="test3", section=None, address=0x3000, size=300),
        ]

        group = ObjCSymbolTypeGroup(class_name="TestClass", method_name="testMethod", symbol_count=3, symbols=symbols)

        assert group.total_size == 600  # 100 + 200 + 300
