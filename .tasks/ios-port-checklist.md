# iOS Size Analysis Port Checklist

This checklist outlines the functionality that needs to be ported from the legacy Swift code (`BinarySeparator.swift` and related files) to the new Python implementation (`ios.py`) to achieve comprehensive size analysis and treemap generation.

## ✅ Already Implemented in Python
- [x] Basic app info extraction from Info.plist
- [x] File analysis (counting, duplicate detection, largest files)
- [x] Basic binary analysis using LIEF (architectures, linked libraries, sections)
- [x] Basic symbol extraction
- [x] Simple Swift metadata extraction structure

## 🔲 Core Infrastructure Needed

### 1. **Range Mapping System**
- [ ] `RangeMap` class for tracking file offset to content type mapping
- [ ] `BinaryTag` enum system for categorizing binary content types:
  - [ ] Strings (CFStrings, Swift file paths, method signatures, etc.)
  - [ ] Headers
  - [ ] External methods
  - [ ] Code signature
  - [ ] Function starts
  - [ ] DYLD info (rebase, bind, lazy bind, exports, fixups)
  - [ ] Binary modules/classes
- [ ] Conflict detection and partial range handling
- [ ] Red-black tree implementation for efficient range queries

### 2. **Treemap Generation System**
- [ ] `BinaryTreemapElement` class for hierarchical size breakdown
- [ ] `TreemapType` enum for visualization categories
- [ ] Hierarchical path building for modules/classes/methods
- [ ] JSON serialization for treemap visualization
- [ ] Size aggregation and unmapped size handling

### 3. **Binary Module Classification**
- [ ] `BinaryModule` and `ModuleType` classes
- [ ] Module type detection:
  - [ ] Swift modules
  - [ ] Objective-C prefix modules
  - [ ] Third-party libraries
  - [ ] C++ modules
  - [ ] Grouping modules
- [ ] Third-party library identification patterns
- [ ] Module hierarchy and path generation

## 🔲 Enhanced String Analysis

### 4. **Comprehensive String Processing**
- [ ] C string section analysis with smart categorization
- [ ] CFString detection and parsing (`__cfstring` section)
- [ ] Swift file path detection (`.swift` suffix)
- [ ] Method signature parsing and validation
- [ ] Objective-C type string identification
- [ ] String size attribution to appropriate modules
- [ ] Large string identification and reporting

## 🔲 Objective-C Runtime Analysis

### 5. **Class and Method Analysis**
- [ ] Class list parsing (`__objc_classlist`, `__objc_nlclslist` sections)
- [ ] Method list parsing with support for:
  - [ ] Regular method lists
  - [ ] Small method lists (relative offsets)
  - [ ] Method name, type, and implementation extraction
- [ ] Class hierarchy parsing (superclass relationships)
- [ ] Category parsing (`__objc_catlist`, `__objc_nlcatlist`)
- [ ] Protocol conformance analysis

### 6. **Property and Variable Analysis**
- [ ] Property list parsing from classes/protocols
- [ ] Instance variable (ivar) parsing
- [ ] Property attribute string parsing
- [ ] Variable type encoding analysis

### 7. **Protocol Analysis**
- [ ] Protocol list parsing (`__objc_protolist`)
- [ ] Protocol method parsing (instance, class, optional)
- [ ] Protocol inheritance hierarchy
- [ ] Extended method types parsing

## 🔲 Deep Swift Metadata Analysis

### 8. **Swift Type System**
- [ ] Swift type descriptors parsing (`__swift5_types` section)
- [ ] Context descriptor parsing:
  - [ ] Module descriptors
  - [ ] Class descriptors
  - [ ] Struct descriptors
  - [ ] Enum descriptors
  - [ ] Protocol descriptors
  - [ ] Extension descriptors
  - [ ] Anonymous descriptors
- [ ] Generic context handling
- [ ] VTable descriptor parsing for classes

### 9. **Swift Protocol System**
- [ ] Protocol descriptors parsing (`__swift5_protos` section)
- [ ] Protocol conformances parsing (`__swift5_proto` section)
- [ ] Protocol requirements parsing
- [ ] Associated type handling
- [ ] Witness table analysis

### 10. **Swift Field and Generic Analysis**
- [ ] Field descriptor parsing
- [ ] Generic requirement descriptor parsing
- [ ] Singleton metadata initialization parsing
- [ ] Field record parsing (field names, types)

### 11. **Swift Symbol Demangling**
- [ ] Swift mangled name parsing (integrate with existing demanglers)
- [ ] Module extraction from mangled symbols
- [ ] Type name extraction
- [ ] Function signature parsing
- [ ] Path generation for Swift symbols

## 🔲 Function/Method Analysis

### 12. **Disassembly and Control Flow**
- [ ] ARM64 instruction disassembly (integrate Capstone)
- [ ] Function boundary detection
- [ ] Branch instruction analysis:
  - [ ] Standard branches (`b`, `b.ne`, etc.)
  - [ ] Branch links (`bl`)
  - [ ] Conditional branches (`cbz`, `cbnz`, etc.)
  - [ ] Relative addressing (`adr`)
- [ ] Return instruction detection for function end
- [ ] Method size calculation
- [ ] Outlined function detection

### 13. **Symbol Resolution**
- [ ] DSYM file integration for enhanced symbol names
- [ ] Symbol address resolution
- [ ] Function start detection
- [ ] Method attribution to classes/modules

## 🔲 Advanced Load Command Processing

### 14. **Enhanced Mach-O Support**
- [ ] Comprehensive load command parsing beyond LIEF:
  - [ ] `LC_DYLD_INFO_ONLY` processing
  - [ ] `LC_DYLD_CHAINED_FIXUPS` support
  - [ ] `LC_FUNCTION_STARTS` parsing
  - [ ] `LC_DATA_IN_CODE` handling
- [ ] DYLD bind symbol processing
- [ ] Chained fixups support (newer format)
- [ ] Import symbol resolution

### 15. **Memory Layout Analysis**
- [ ] VM address to file offset mapping
- [ ] Section boundary detection
- [ ] Segment analysis beyond basic LIEF support
- [ ] Memory layout validation

## 🔲 Integration and Output

### 16. **Size Attribution System**
- [ ] Accurate size attribution to modules/classes/methods
- [ ] Overlap detection and resolution
- [ ] Unmapped region identification
- [ ] Size aggregation by category

### 17. **Treemap Generation**
- [ ] Hierarchical tree building from analysis results
- [ ] Module grouping (Feature, Service, UI, etc.)
- [ ] Size-based filtering and hiding small elements
- [ ] JSON output format for visualization
- [ ] Metadata and detail information inclusion

### 18. **Performance Optimizations**
- [ ] Efficient memory usage for large binaries
- [ ] Progress reporting for long-running analysis
- [ ] Caching of expensive computations
- [ ] Optional analysis components (skip Swift metadata, symbols, etc.)

## 🔲 Testing and Validation

### 19. **Integration Tests**
- [ ] Test with sample apps in `test/artifacts`
- [ ] Compare outputs with legacy Swift implementation
- [ ] Performance benchmarking
- [ ] Memory usage validation

### 20. **Error Handling**
- [ ] Graceful handling of corrupted binaries
- [ ] Encrypted binary detection and handling
- [ ] Missing section handling
- [ ] Invalid data structure handling

## � Critical Data Structures to Implement

### Objective-C Runtime Structures (from `BinaryModels.swift`)
- [ ] `ObjCClass` - Class metadata structure
- [ ] `ClassRoT` - Class read-only data
- [ ] `ObjcMethod` / `ObjcRelativeMethod` - Method descriptors
- [ ] `ObjcProtocol` - Protocol metadata
- [ ] `ObjcCategory` - Category descriptors
- [ ] `ObjcIVar` - Instance variable descriptors
- [ ] `BaseProperty` - Property descriptors

### Swift Metadata Structures (from `SwiftMetadata.swift`)
- [ ] `ProtocolConformanceDescriptor` - Protocol conformance data
- [ ] `ProtocolDescriptor` - Protocol metadata
- [ ] `TargetClassDescriptor` - Swift class metadata
- [ ] `StructDescriptor` / `EnumDescriptor` - Value type metadata
- [ ] `FieldDescriptor` / `FieldRecord` - Field metadata
- [ ] `TargetGenericRequirementDescriptor` - Generic constraints
- [ ] `TargetMethodDescriptor` - Method descriptors
- [ ] `TargetVTableDescriptorHeader` - Virtual method tables
- [ ] `RelativePointer` - Swift relative pointer resolution

### Load Command Structures
- [ ] `dyld_chained_fixups_header` - Modern fixup format
- [ ] Custom load command parsing for DYLD info
- [ ] Enhanced segment/section analysis

## �📊 Expected Deliverables

After implementing all items:
1. **Treemap JSON Output**: Hierarchical size breakdown suitable for visualization
2. **Detailed Analysis Report**: Module-by-module size breakdown
3. **String Analysis**: Categorized string usage analysis
4. **Method Analysis**: Function/method size attribution
5. **Performance Metrics**: Analysis runtime and memory usage
6. **Comparison Tools**: Ability to compare with legacy Swift output

## 🎯 Implementation Priority

**Phase 1 (Core Infrastructure)**:
- Items 1-3: Range mapping, treemap generation, module classification

**Phase 2 (Content Analysis)**:
- Items 4-11: String analysis, Objective-C runtime, Swift metadata

**Phase 3 (Advanced Analysis)**:
- Items 12-15: Function analysis, advanced Mach-O support

**Phase 4 (Polish)**:
- Items 16-20: Integration, output, testing, optimization

This represents a significant porting effort but will result in a comprehensive iOS size analysis tool that matches or exceeds the capabilities of the legacy Swift implementation.
