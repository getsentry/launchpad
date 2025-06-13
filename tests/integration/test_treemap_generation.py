"""Integration tests for treemap generation."""

import json
from pathlib import Path

import pytest

from launchpad.analyzers.ios import IOSAnalyzer


class TestTreemapGeneration:
    """Test treemap generation functionality."""

    @pytest.fixture
    def sample_app_path(self) -> Path:
        """Path to sample iOS app for testing."""
        return Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")

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

        # Convert treemap to JSON using Pydantic's standard serialization
        treemap_dict = treemap.model_dump()

        # Verify standard Pydantic structure
        assert "root" in treemap_dict
        assert "total_install_size" in treemap_dict
        assert "total_download_size" in treemap_dict
        assert "file_count" in treemap_dict
        assert "category_breakdown" in treemap_dict
        assert "platform" in treemap_dict

        # Verify root structure
        root_data = treemap_dict["root"]
        assert "name" in root_data
        assert "install_size" in root_data
        assert "download_size" in root_data
        assert "is_directory" in root_data
        assert "children" in root_data

        # Verify children have expected structure
        children = root_data["children"]
        assert len(children) > 0

        for child in children:
            assert "name" in child
            assert "install_size" in child
            assert "download_size" in child
            assert "is_directory" in child

        # Test that it's actually serializable to JSON
        json_str = json.dumps(treemap_dict)
        assert len(json_str) > 0

        # Test deserialization works
        parsed = json.loads(json_str)
        assert parsed == treemap_dict

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
