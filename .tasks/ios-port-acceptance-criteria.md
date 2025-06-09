# iOS Size Analysis - Acceptance Criteria & Integration Tests

This document defines specific, measurable acceptance criteria for each component that can be validated against the legacy Swift implementation using the sample apps in `test/artifacts`.

## 🧪 Test Strategy

**Primary Test Artifact**: Use the cleanroom sample apps in `test/artifacts/`
**Baseline Reference**: `tests/artifacts/hackernews-results.json` - Complete legacy Swift analysis results
**Validation Method**: Compare Python implementation outputs with legacy results
**Success Criteria**: Match legacy output within 5% variance for size calculations

### 📋 **Testing Philosophy**

**Values Matter, Structure Doesn't**: The new Python implementation should produce equivalent size calculations and analysis results, but can use a cleaner, more modern JSON structure. The legacy JSON contains considerable cruft that should be cleaned up.

**Baseline Validation**: Each test should load `tests/artifacts/hackernews-results.json` as the source of truth for expected values, but adapt the comparisons to work with the new, improved output structure.

**Example Validation Pattern**:
```python
# Load legacy baseline
legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

# Run new implementation
python_results = analyze_ios_app("hackernews_sample.xcarchive.zip")

# Compare values (not structure)
assert python_results.app_size == legacy_data["app"]["value"]
assert python_results.download_size == legacy_data["app_store_file_sizes"]["mainApp"]["downloadSize"]

# Treemap comparison - extract values from different structures
legacy_modules = extract_module_sizes(legacy_data["app"]["children"])
python_modules = python_results.treemap.get_module_sizes()
assert compare_module_sizes(python_modules, legacy_modules, tolerance=0.05)
```

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

    # Load legacy baseline
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

    # Total mapped + unmapped should equal file size
    assert results.range_map.total_mapped + results.range_map.unmapped_size == results.binary_size

    # No large unmapped regions
    assert max(results.range_map.unmapped_regions) < 1024

    # Compare total app size with legacy baseline
    assert abs(results.total_size - legacy_data["app"]["value"]) <= 1024
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
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

    # Validate JSON structure (new, clean format)
    assert validate_treemap_schema(treemap.to_json())

    # Check size consistency recursively
    assert validate_size_consistency(treemap.root)

    # Compare total size with legacy baseline
    assert treemap.total_size == legacy_data["app"]["value"]

    # Extract and compare major categories from different structures
    legacy_categories = extract_categories_from_legacy(legacy_data["app"]["children"])
    python_categories = treemap.get_top_level_categories()
    assert compare_category_sizes(python_categories, legacy_categories, tolerance=0.05)
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
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

    # Extract module information from legacy structure
    legacy_modules = extract_modules_from_legacy_treemap(legacy_data["app"]["children"])

    # Compare module counts by type (values, not exact structure)
    assert count_modules_by_type(modules) == count_modules_by_type(legacy_modules)

    # Third-party libraries detected (adapt to frameworks found in legacy data)
    legacy_frameworks = extract_frameworks_from_dylibs(legacy_data["dylibs"])
    python_frameworks = [m.name for m in modules if m.type == ModuleType.THIRD_PARTY]
    assert frameworks_detected_correctly(python_frameworks, legacy_frameworks)
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
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

    # Extract string information from legacy treemap structure
    legacy_string_sizes = extract_string_sizes_from_legacy(legacy_data["app"]["children"])

    # Compare total string sizes by category within 5%
    for category in StringCategory:
        legacy_size = legacy_string_sizes.get(category, 0)
        python_size = strings.size_by_category[category]
        assert abs(python_size - legacy_size) <= legacy_size * 0.05
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
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

    # Extract ObjC metrics from legacy structure
    legacy_objc_metrics = extract_objc_metrics_from_legacy(legacy_data)

    # Compare class/method counts (values from different structures)
    assert objc_data.total_classes == legacy_objc_metrics["class_count"]
    assert abs(objc_data.total_methods - legacy_objc_metrics["method_count"]) <= legacy_objc_metrics["method_count"] * 0.02
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
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

    # Extract property/protocol metrics from legacy data
    legacy_metrics = extract_property_protocol_metrics(legacy_data)

    # Compare values within tolerance
    assert abs(data.total_properties - legacy_metrics["property_count"]) <= legacy_metrics["property_count"] * 0.01
    assert data.protocol_count == legacy_metrics["protocol_count"]
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
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

    # Extract Swift metadata metrics from legacy structure
    legacy_swift_metrics = extract_swift_metrics_from_legacy(legacy_data)

    # Compare type counts and conformances
    assert swift_data.type_counts == legacy_swift_metrics["type_counts"]
    conformance_diff = abs(swift_data.conformance_count - legacy_swift_metrics["conformance_count"])
    assert conformance_diff <= legacy_swift_metrics["conformance_count"] * 0.01
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
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

    # Extract function size information from legacy data
    legacy_function_sizes = extract_function_sizes_from_legacy(legacy_data)

    # Compare total method size within 5%
    size_diff = abs(functions.total_size - legacy_function_sizes["total_size"])
    assert size_diff <= legacy_function_sizes["total_size"] * 0.05
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
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

    # Extract Mach-O metrics from legacy structure
    legacy_macho_metrics = extract_macho_metrics_from_legacy(legacy_data)

    # Compare DYLD info sizes and import counts
    for dyld_type in ['rebase', 'bind', 'lazy_bind', 'exports']:
        assert abs(macho_data.dyld_sizes[dyld_type] - legacy_macho_metrics[dyld_type]) <= 1024
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
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

    # Compare total app size
    assert abs(results.total_size - legacy_data["app"]["value"]) <= 1024

    # Compare download size
    assert abs(results.download_size - legacy_data["app_store_file_sizes"]["mainApp"]["downloadSize"]) <= 1024

    # Extract and compare module breakdown (values from different structures)
    legacy_breakdown = extract_size_breakdown_from_legacy(legacy_data["app"]["children"])
    python_breakdown = results.get_size_breakdown()

    for category in ['modules', 'macho', 'codeSignature', 'strings']:
        legacy_size = legacy_breakdown.get(category, 0)
        python_size = python_breakdown.get(category, 0)
        if legacy_size > 0:
            assert abs(python_size - legacy_size) <= legacy_size * 0.05
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

    # Performance test using baseline data size as reference
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))
    expected_size = legacy_data["app"]["value"]  # ~6MB app

    start_time = time.time()
    results = analyze_app("sample_app.xcarchive.zip")
    end_time = time.time()

    # Performance should scale reasonably with app size
    max_time = (expected_size / 1_000_000) * 30  # 30 seconds per MB
    assert end_time - start_time < max_time
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

    # Load legacy baseline
    legacy_data = json.load(open("tests/artifacts/hackernews-results.json"))

    # Key metrics must match within tolerance (comparing values, not structure)
    assertions = [
        # App size
        abs(python_results.total_size - legacy_data["app"]["value"]) <= 1024,

        # Download size
        abs(python_results.download_size - legacy_data["app_store_file_sizes"]["mainApp"]["downloadSize"]) <= 1024,

        # Install size
        abs(python_results.install_size - legacy_data["app_store_file_sizes"]["mainApp"]["installSize"]) <= 1024,

        # Dynamic libraries count
        len(python_results.dylibs) == len(legacy_data["dylibs"]),

        # Major category sizes (extract from different structures)
        validate_category_sizes(python_results, legacy_data, tolerance=0.05),

        # Treemap structure integrity (new structure should be valid)
        validate_treemap_structure(python_results.treemap),
    ]

    # All assertions must pass
    assert all(assertions), f"Failed assertions: {[i for i, a in enumerate(assertions) if not a]}"

    # Generate comparison report showing old vs new structure
    generate_comparison_report(python_results, legacy_data)
```

## 🚦 Success Metrics

**Ready for Production When:**
- [ ] All phase integration tests pass using `tests/artifacts/hackernews-results.json` as baseline
- [ ] Full integration test passes comparing values (not structure) with legacy data
- [ ] Performance targets met relative to baseline app size
- [ ] Memory usage remains stable during analysis
- [ ] New treemap JSON structure is cleaner and more maintainable than legacy format
- [ ] Results are within 5% variance of legacy implementation for all major size metrics

**Note**: The new implementation can and should use a cleaner JSON structure than the legacy format. Tests should focus on validating that the essential values (sizes, counts, classifications) match, while allowing for structural improvements and removal of legacy cruft.
