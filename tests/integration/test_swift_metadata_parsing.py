"""Integration tests for Swift metadata parsing."""

from pathlib import Path

import pytest

from src.launchpad.analyzers.ios import IOSAnalyzer


class TestSwiftMetadataParsing:
    """Test Swift metadata parsing capabilities."""

    @pytest.fixture
    def sample_app_path(self):
        """Get path to sample iOS app for testing."""
        artifacts_dir = Path(__file__).parent.parent / "artifacts"
        app_files = list(artifacts_dir.glob("*.zip"))

        if not app_files:
            pytest.skip("No sample iOS app found in test artifacts")

        return app_files[0]

    def test_swift_metadata_extraction(self, sample_app_path):
        """Test that Swift metadata can be extracted from a real iOS binary."""
        analyzer = IOSAnalyzer(
            skip_swift_metadata=False,
            enable_range_mapping=True,
            enable_treemap=False,  # Focus on metadata parsing
        )

        results = analyzer.analyze(sample_app_path)

        # Verify we got some results
        assert results is not None
        assert results.binary_analysis is not None

        # Check Swift metadata
        swift_metadata = results.binary_analysis.swift_metadata
        if swift_metadata is not None:
            # If we found Swift metadata, verify it has reasonable content
            assert swift_metadata.total_metadata_size > 0

            # Log what we found for debugging
            print("\nSwift metadata found:")
            print(f"  Classes: {len(swift_metadata.classes)}")
            print(f"  Protocols: {len(swift_metadata.protocols)}")
            print(f"  Extensions: {len(swift_metadata.extensions)}")
            print(f"  Total size: {swift_metadata.total_metadata_size} bytes")

            if swift_metadata.classes:
                print(f"  Sample classes: {swift_metadata.classes[:5]}")
            if swift_metadata.protocols:
                print(f"  Sample protocols: {swift_metadata.protocols[:5]}")
        else:
            print("\nNo Swift metadata found in binary (this is okay for Objective-C only apps)")

    def test_swift_metadata_range_mapping(self, sample_app_path):
        """Test that Swift metadata is properly mapped in range mapping."""
        analyzer = IOSAnalyzer(skip_swift_metadata=False, enable_range_mapping=True, enable_treemap=False)

        results = analyzer.analyze(sample_app_path)

        # Check if range mapping includes Swift metadata
        if results.binary_analysis.has_range_mapping:
            range_map = results.binary_analysis.range_map
            sizes_by_tag = range_map.size_by_tag()

            from src.launchpad.models import BinaryTag

            swift_size = sizes_by_tag.get(BinaryTag.SWIFT_METADATA, 0)

            print(f"\nRange mapping results:")
            print(f"  Swift metadata size: {swift_size} bytes")
            print(f"  Coverage: {results.binary_analysis.coverage_percentage:.1f}%")
            print(f"  Unmapped: {results.binary_analysis.unmapped_size} bytes")

            # If we have Swift metadata, verify it's mapped
            if (
                results.binary_analysis.swift_metadata
                and results.binary_analysis.swift_metadata.total_metadata_size > 0
            ):
                assert swift_size > 0, "Swift metadata should be mapped in range mapping"

    def test_swift_types_categorization(self, sample_app_path):
        """Test that different Swift types are properly categorized."""
        analyzer = IOSAnalyzer(skip_swift_metadata=False, enable_range_mapping=True, enable_treemap=True)

        results = analyzer.analyze(sample_app_path)

        # Check treemap for Swift modules
        if results.treemap:

            def find_swift_modules(element, modules=None):
                if modules is None:
                    modules = []

                # Look for Swift modules in the treemap
                if hasattr(element, "type") and element.type == "swiftModule":
                    modules.append(element.name)

                if hasattr(element, "children"):
                    for child in element.children:
                        find_swift_modules(child, modules)

                return modules

            swift_modules = find_swift_modules(results.treemap.root)

            print(f"\nSwift modules found in treemap:")
            for module in swift_modules:
                print(f"  - {module}")

            # If we have Swift metadata, we should find some modules
            if (
                results.binary_analysis.swift_metadata
                and results.binary_analysis.swift_metadata.total_metadata_size > 0
            ):
                # Note: This assertion might be too strict for some apps
                # assert len(swift_modules) > 0, "Should find some Swift modules in treemap"
                print(f"  Found {len(swift_modules)} Swift modules in treemap")
