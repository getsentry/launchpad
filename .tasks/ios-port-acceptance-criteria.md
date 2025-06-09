# iOS Size Analysis - Acceptance Criteria & Integration Tests

This document defines specific, measurable acceptance criteria for each component that can be validated against the legacy Swift implementation using the sample apps in `test/artifacts`.

## 🧪 Test Strategy

**Primary Test Artifact**: Use the cleanroom sample apps in `test/artifacts/`
**Validation Method**: Compare outputs with legacy Swift implementation
**Success Criteria**: Match legacy output within 5% variance for size calculations

---

## 📋 Phase 1: Core Infrastructure

### 1. Range Mapping System

**Acceptance Criteria:**
- [ ] **100% Binary Coverage**: Every byte in the binary must be mapped to a category (no unmapped regions > 1KB)
- [ ] **Conflict Detection**: Report any overlapping ranges and total conflict size
- [ ] **Category Consistency**: Total mapped size = file size - unmapped regions
- [ ] **Performance**: Process 100MB binary in < 30 seconds

**Integration Test:**
```python
def test_range_mapping_coverage():
    analyzer = IOSAnalyzer("sample_app.xcarchive.zip")
    results = analyzer.analyze()

    # Total mapped + unmapped should equal file size
    assert results.range_map.total_mapped + results.range_map.unmapped_size == results.binary_size

    # No large unmapped regions
    assert max(results.range_map.unmapped_regions) < 1024

    # Compare total sizes by category with legacy output
    assert_category_sizes_match_legacy(results.range_map.category_sizes)
```

### 2. Treemap Generation System

**Acceptance Criteria:**
- [ ] **Valid JSON Structure**: Output must validate against treemap schema
- [ ] **Size Consistency**: Parent size = sum of children sizes for all nodes
- [ ] **Hierarchy Depth**: Support at least 5 levels of nesting (App > Module > Class > Method > Details)
- [ ] **Module Grouping**: Correctly group modules by type (Swift, ObjC, Third-party, etc.)

**Integration Test:**
```python
def test_treemap_generation():
    treemap = generate_treemap("sample_app.xcarchive.zip")

    # Validate JSON structure
    assert validate_treemap_schema(treemap.to_json())

    # Check size consistency recursively
    assert validate_size_consistency(treemap.root)

    # Compare top-level sizes with legacy
    legacy_sizes = load_legacy_treemap("sample_app_legacy.json")
    assert compare_top_level_sizes(treemap, legacy_sizes, tolerance=0.05)

    # Verify module count and types
    assert count_modules_by_type(treemap) == expected_module_counts
```

### 3. Binary Module Classification

**Acceptance Criteria:**
- [ ] **Module Count Match**: Same number of modules as legacy implementation
- [ ] **Type Classification**: Correctly classify modules as Swift/ObjC/Third-party/C++
- [ ] **Third-party Detection**: Identify known libraries (Firebase, RxSwift, etc.)
- [ ] **Path Generation**: Generate valid hierarchical paths for all modules

**Integration Test:**
```python
def test_module_classification():
    modules = classify_modules("sample_app.xcarchive.zip")
    legacy_modules = load_legacy_modules("sample_app_modules.json")

    # Same module count by type
    assert count_by_type(modules) == count_by_type(legacy_modules)

    # Third-party libraries detected
    assert "Firebase" in [m.name for m in modules if m.type == ModuleType.THIRD_PARTY]

    # All modules have valid paths
    assert all(len(m.path) > 0 for m in modules)
```

---

## 📋 Phase 2: Content Analysis

### 4. Comprehensive String Processing

**Acceptance Criteria:**
- [ ] **String Count Match**: ±5% of legacy string counts by category
- [ ] **CFString Detection**: Find all CFStrings with correct sizes
- [ ] **Swift File Detection**: Identify .swift file paths with ±1 count accuracy
- [ ] **Method Signature Parsing**: Validate 95%+ of ObjC method signatures

**Integration Test:**
```python
def test_string_analysis():
    strings = analyze_strings("sample_app.xcarchive.zip")
    legacy_strings = load_legacy_strings("sample_app_strings.json")

    # String counts by category within 5%
    for category in StringCategory:
        assert abs(strings.count[category] - legacy_strings.count[category]) <= legacy_strings.count[category] * 0.05

    # CFString total size within 1KB
    assert abs(strings.cfstring_size - legacy_strings.cfstring_size) <= 1024

    # Swift files detected
    swift_files = [s for s in strings.all if s.endswith('.swift')]
    assert len(swift_files) == legacy_strings.swift_file_count
```

### 5. Objective-C Class and Method Analysis

**Acceptance Criteria:**
- [ ] **Class Count Exact**: Find exact same number of ObjC classes as legacy
- [ ] **Method Count**: ±2% of legacy method count per class
- [ ] **Protocol Count**: Exact match with legacy protocol count
- [ ] **Category Detection**: Find all categories with correct conforming classes

**Integration Test:**
```python
def test_objc_analysis():
    objc_data = analyze_objc_runtime("sample_app.xcarchive.zip")
    legacy_objc = load_legacy_objc("sample_app_objc.json")

    # Exact class count
    assert len(objc_data.classes) == len(legacy_objc.classes)

    # Method counts per class within 2%
    for class_name in objc_data.classes:
        legacy_methods = legacy_objc.classes[class_name].method_count
        current_methods = objc_data.classes[class_name].method_count
        assert abs(current_methods - legacy_methods) <= legacy_methods * 0.02

    # Protocol count exact
    assert len(objc_data.protocols) == len(legacy_objc.protocols)

    # Category conformance matches
    assert objc_data.category_conformances == legacy_objc.category_conformances
```

### 6-7. Property and Protocol Analysis

**Acceptance Criteria:**
- [ ] **Property Count**: ±1% of legacy property count per class/protocol
- [ ] **Protocol Inheritance**: Correctly map protocol hierarchies
- [ ] **Method Types**: Parse instance, class, and optional methods correctly

**Integration Test:**
```python
def test_objc_properties_protocols():
    data = analyze_objc_properties_protocols("sample_app.xcarchive.zip")
    legacy = load_legacy_properties_protocols("sample_app_props_protos.json")

    # Property counts within 1%
    assert abs(data.total_properties - legacy.total_properties) <= legacy.total_properties * 0.01

    # Protocol method counts by type
    for proto_name in data.protocols:
        proto = data.protocols[proto_name]
        legacy_proto = legacy.protocols[proto_name]
        assert proto.instance_methods == legacy_proto.instance_methods
        assert proto.class_methods == legacy_proto.class_methods
        assert proto.optional_methods == legacy_proto.optional_methods
```

### 8-11. Swift Metadata Analysis

**Acceptance Criteria:**
- [ ] **Type Count**: Find same number of Swift types (classes, structs, enums) as legacy
- [ ] **Protocol Conformances**: ±1% of legacy conformance count
- [ ] **Generic Constraints**: Parse all generic requirements correctly
- [ ] **Field Descriptors**: Extract all field names and types

**Integration Test:**
```python
def test_swift_metadata():
    swift_data = analyze_swift_metadata("sample_app.xcarchive.zip")
    legacy_swift = load_legacy_swift("sample_app_swift.json")

    # Type counts by kind
    for type_kind in ['class', 'struct', 'enum', 'protocol']:
        assert swift_data.type_counts[type_kind] == legacy_swift.type_counts[type_kind]

    # Protocol conformances within 1%
    conformance_diff = abs(swift_data.conformance_count - legacy_swift.conformance_count)
    assert conformance_diff <= legacy_swift.conformance_count * 0.01

    # Field parsing completeness
    assert swift_data.parsed_field_count >= legacy_swift.parsed_field_count * 0.95

    # Generic constraint count
    assert swift_data.generic_constraints == legacy_swift.generic_constraints
```

---

## 📋 Phase 3: Advanced Analysis

### 12-13. Function/Method Analysis & Symbol Resolution

**Acceptance Criteria:**
- [ ] **Method Size Attribution**: Total method sizes within 5% of legacy
- [ ] **Function Boundary Detection**: 95%+ accuracy on function start/end detection
- [ ] **Symbol Resolution**: Resolve 90%+ of symbols when DSYM available
- [ ] **Branch Analysis**: Correctly follow control flow for size calculation

**Integration Test:**
```python
def test_function_analysis():
    functions = analyze_functions("sample_app.xcarchive.zip", "sample_app.dSYM")
    legacy_functions = load_legacy_functions("sample_app_functions.json")

    # Total method size within 5%
    size_diff = abs(functions.total_size - legacy_functions.total_size)
    assert size_diff <= legacy_functions.total_size * 0.05

    # Function count within 10% (some edge cases in boundary detection)
    count_diff = abs(functions.count - legacy_functions.count)
    assert count_diff <= legacy_functions.count * 0.10

    # Symbol resolution rate
    if functions.dsym_available:
        assert functions.resolved_symbols / functions.total_symbols >= 0.90

    # Large method detection
    large_methods = [f for f in functions.all if f.size > 10000]
    legacy_large = [f for f in legacy_functions.all if f.size > 10000]
    assert len(large_methods) >= len(legacy_large) * 0.95
```

### 14-15. Enhanced Mach-O Support & Memory Layout

**Acceptance Criteria:**
- [ ] **Load Command Parsing**: Parse all LC_DYLD_* commands correctly
- [ ] **Chained Fixups**: Support modern chained fixup format
- [ ] **Address Mapping**: VM address ↔ file offset mapping with 100% accuracy
- [ ] **Import Resolution**: Resolve external symbol imports

**Integration Test:**
```python
def test_enhanced_macho():
    macho_data = analyze_enhanced_macho("sample_app.xcarchive.zip")
    legacy_macho = load_legacy_macho("sample_app_macho.json")

    # Load command parsing completeness
    assert macho_data.load_commands_parsed == legacy_macho.load_commands_parsed

    # Address mapping accuracy
    test_addresses = legacy_macho.test_vm_addresses
    for vm_addr in test_addresses:
        file_offset = macho_data.vm_to_file_offset(vm_addr)
        assert file_offset == legacy_macho.vm_to_file_offset_map[vm_addr]

    # Import resolution
    if macho_data.uses_chained_fixups:
        assert macho_data.resolved_imports >= legacy_macho.total_imports * 0.95

    # DYLD info sizes
    for dyld_type in ['rebase', 'bind', 'lazy_bind', 'exports']:
        assert macho_data.dyld_sizes[dyld_type] == legacy_macho.dyld_sizes[dyld_type]
```

---

## 📋 Phase 4: Integration & Output

### 16-17. Size Attribution & Treemap Generation

**Acceptance Criteria:**
- [ ] **Size Attribution Accuracy**: 95%+ of binary bytes correctly attributed to modules
- [ ] **Unmapped Region Analysis**: Unmapped regions < 5% of total binary size
- [ ] **Treemap Visualization**: Generate valid D3.js compatible JSON
- [ ] **Module Hierarchy**: Correct parent-child relationships in treemap

**Integration Test:**
```python
def test_size_attribution_treemap():
    results = full_analysis("sample_app.xcarchive.zip")
    legacy_results = load_legacy_full("sample_app_full.json")

    # Size attribution accuracy
    attributed_size = sum(results.module_sizes.values())
    assert attributed_size >= results.binary_size * 0.95

    # Unmapped regions small
    assert results.unmapped_size <= results.binary_size * 0.05

    # Treemap module sizes within 5%
    for module_name in results.module_sizes:
        if module_name in legacy_results.module_sizes:
            size_diff = abs(results.module_sizes[module_name] - legacy_results.module_sizes[module_name])
            assert size_diff <= legacy_results.module_sizes[module_name] * 0.05

    # JSON validation
    treemap_json = results.generate_treemap_json()
    assert validate_d3_treemap_schema(treemap_json)

    # Hierarchy consistency
    assert validate_treemap_hierarchy(treemap_json)
```

### 18. Performance & Error Handling

**Acceptance Criteria:**
- [ ] **Performance**: Process 100MB app in < 5 minutes
- [ ] **Memory Usage**: Peak memory < 2GB for large apps
- [ ] **Error Graceful**: Handle corrupted binaries without crashing
- [ ] **Progress Reporting**: Report progress every 10% completion

**Integration Test:**
```python
def test_performance_error_handling():
    import time
    import psutil

    # Performance test
    start_time = time.time()
    start_memory = psutil.Process().memory_info().rss

    results = analyze_large_app("large_sample_app.xcarchive.zip")  # ~100MB

    end_time = time.time()
    peak_memory = psutil.Process().memory_info().rss

    # Performance criteria
    assert end_time - start_time < 300  # 5 minutes
    assert peak_memory - start_memory < 2 * 1024 * 1024 * 1024  # 2GB

    # Error handling
    try:
        analyze_corrupted_app("corrupted_app.zip")
        assert False, "Should have raised exception"
    except AnalysisError as e:
        assert "corrupted" in str(e).lower()

    # Progress reporting
    progress_reports = []
    def progress_callback(percent):
        progress_reports.append(percent)

    analyze_with_progress("sample_app.xcarchive.zip", progress_callback)
    assert len(progress_reports) >= 10  # At least 10% increments
```

---

## 🎯 Overall Integration Test Suite

**Final Acceptance Criteria:**
```python
def test_full_integration_vs_legacy():
    """
    Ultimate test: Full analysis should produce results that match
    legacy Swift implementation within acceptable tolerances.
    """
    # Run full analysis
    python_results = analyze_ios_app("comprehensive_test_app.xcarchive.zip")

    # Load legacy results
    swift_results = load_legacy_results("comprehensive_test_app_legacy.json")

    # Key metrics must match within tolerance
    assertions = [
        # File analysis
        abs(python_results.file_count - swift_results.file_count) <= 5,
        abs(python_results.total_size - swift_results.total_size) <= 1024,

        # Binary analysis
        python_results.architectures == swift_results.architectures,
        abs(python_results.executable_size - swift_results.executable_size) <= 1024,

        # String analysis
        abs(python_results.string_analysis.cfstring_size - swift_results.string_analysis.cfstring_size) <= 2048,

        # ObjC analysis
        python_results.objc_analysis.class_count == swift_results.objc_analysis.class_count,
        abs(python_results.objc_analysis.method_count - swift_results.objc_analysis.method_count) <= swift_results.objc_analysis.method_count * 0.02,

        # Swift analysis
        python_results.swift_analysis.type_count == swift_results.swift_analysis.type_count,

        # Treemap structure
        python_results.treemap.total_size == swift_results.treemap.total_size,
        len(python_results.treemap.children) == len(swift_results.treemap.children),
    ]

    # All assertions must pass
    assert all(assertions), f"Failed assertions: {[i for i, a in enumerate(assertions) if not a]}"

    # Generate comparison report
    generate_comparison_report(python_results, swift_results)
```

## 🚦 Success Metrics

**Ready for Production When:**
- [ ] All phase integration tests pass
- [ ] Full integration test passes on 3+ different sample apps
- [ ] Performance targets met on apps up to 200MB
- [ ] Memory usage remains stable during analysis
- [ ] Treemap visualization renders correctly in browser
- [ ] Results are within 5% variance of legacy implementation for all major metrics

This testing strategy ensures each component works correctly and the final result matches the legacy Swift implementation's accuracy and completeness.
