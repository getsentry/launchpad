"""Integration tests for treemap generation functionality."""

import json
from pathlib import Path
from typing import List

import pytest

from launchpad.analyzers.ios import IOSAnalyzer
from launchpad.models.treemap import TreemapElement


class TestTreemapGeneration:
    """Test treemap generation functionality."""

    @pytest.fixture
    def sample_app_path(self) -> Path:
        """Path to sample iOS app for testing."""
        return Path(__file__).parent.parent / "artifacts" / "HackerNews.xcarchive.zip"

    def test_treemap_generation_basic(self, sample_app_path: Path) -> None:
        """Test basic treemap generation functionality."""
        # Skip if test file doesn't exist
        if not sample_app_path.exists():
            pytest.skip(f"Test file {sample_app_path} not found")

        # Create analyzer with treemap enabled
        analyzer = IOSAnalyzer(enable_treemap=True)

        # Analyze the sample app
        results = analyzer.analyze(sample_app_path)

        # Verify treemap was generated
        assert results.treemap is not None
        treemap = results.treemap
        assert treemap.file_count > 0
        assert treemap.total_install_size > 0
        assert treemap.total_download_size > 0

        # Verify root element
        root = treemap.root
        assert root.name == results.app_info.name
        assert len(root.children) > 0

        # Verify size calculations work
        assert root.total_install_size > 0
        assert root.total_download_size > 0
        assert root.total_download_size <= root.total_install_size  # Download should be <= install

    def test_treemap_json_serialization(self, sample_app_path: Path) -> None:
        """Test that treemap can be serialized to JSON."""
        # Skip if test file doesn't exist
        if not sample_app_path.exists():
            pytest.skip(f"Test file {sample_app_path} not found")

        # Create analyzer with treemap enabled
        analyzer = IOSAnalyzer(enable_treemap=True)

        # Analyze the sample app
        results = analyzer.analyze(sample_app_path)

        # Verify treemap was generated
        assert results.treemap is not None
        treemap = results.treemap

        # Convert treemap to JSON
        treemap_json = treemap.to_json_dict()

        # Verify JSON structure
        assert "app" in treemap_json
        assert "metadata" in treemap_json

        # Verify app structure
        app_data = treemap_json["app"]
        assert "name" in app_data
        assert "value" in app_data  # Install size (primary value)
        assert "downloadSize" in app_data
        assert "installSize" in app_data
        assert "children" in app_data

        # Verify children have expected structure
        children = app_data["children"]
        assert len(children) > 0

        for child in children:
            assert "name" in child
            assert "value" in child
            assert "downloadSize" in child
            assert "installSize" in child

        # Verify metadata
        metadata = treemap_json["metadata"]
        assert "totalInstallSize" in metadata
        assert "totalDownloadSize" in metadata
        assert "fileCount" in metadata
        assert "categoryBreakdown" in metadata

        # Test that it's actually serializable to JSON
        json_str = json.dumps(treemap_json)
        assert len(json_str) > 0

        # Test deserialization works
        parsed = json.loads(json_str)
        assert parsed == treemap_json

    def test_treemap_category_breakdown(self, sample_app_path: Path) -> None:
        """Test that category breakdown is correctly calculated."""
        # Skip if test file doesn't exist
        if not sample_app_path.exists():
            pytest.skip(f"Test file {sample_app_path} not found")

        # Create analyzer with treemap enabled
        analyzer = IOSAnalyzer(enable_treemap=True)

        # Analyze the sample app
        results = analyzer.analyze(sample_app_path)

        # Verify treemap was generated
        assert results.treemap is not None
        treemap = results.treemap

        # Check category breakdown
        breakdown = treemap.category_breakdown
        assert len(breakdown) > 0

        # Each category should have install and download sizes
        for _category, sizes in breakdown.items():
            assert "install" in sizes
            assert "download" in sizes
            assert sizes["install"] > 0
            assert sizes["download"] > 0
            assert sizes["download"] <= sizes["install"]  # Download should be <= install

        # Verify total sizes match
        total_install = sum(sizes["install"] for sizes in breakdown.values())
        total_download = sum(sizes["download"] for sizes in breakdown.values())

        assert total_install == treemap.total_install_size
        assert total_download == treemap.total_download_size

    def test_treemap_file_hierarchy(self, sample_app_path: Path) -> None:
        """Test that file hierarchy is correctly built."""
        # Skip if test file doesn't exist
        if not sample_app_path.exists():
            pytest.skip(f"Test file {sample_app_path} not found")

        # Create analyzer with treemap enabled
        analyzer = IOSAnalyzer(enable_treemap=True)

        # Analyze the sample app
        results = analyzer.analyze(sample_app_path)

        # Verify treemap was generated
        assert results.treemap is not None
        treemap = results.treemap

        # Helper function to find leaf nodes (files)
        def find_leaf_nodes(element: TreemapElement) -> List[TreemapElement]:
            """Recursively find all leaf nodes."""
            if element.is_leaf:
                return [element]

            leaves: List[TreemapElement] = []
            for child in element.children:
                leaves.extend(find_leaf_nodes(child))
            return leaves

        # Get all leaf nodes
        leaf_nodes = find_leaf_nodes(treemap.root)

        # Verify we have files
        assert len(leaf_nodes) > 0

        # Verify leaf nodes represent actual files
        for leaf in leaf_nodes:
            assert leaf.is_leaf
            assert leaf.path is not None  # Files should have paths
            assert leaf.install_size > 0  # Files should have size
            assert "fileType" in leaf.details  # Files should have type info

        # Verify total file count matches
        assert len(leaf_nodes) == treemap.file_count
