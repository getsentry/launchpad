"""Integration tests for iOS binary component analysis system."""

import json

from pathlib import Path
from typing import Any, Dict, cast

import pytest

from launchpad.artifacts.artifact import AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.binary_component import BinaryTag


class TestIOSBinaryComponentAnalysis:
    """Test the iOS binary component analysis system against acceptance criteria."""

    @pytest.fixture
    def sample_app_path(self) -> Path:
        """Path to the sample HackerNews app."""
        return Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")

    @pytest.fixture
    def legacy_baseline(self) -> Dict[str, Any]:
        """Load the legacy baseline results for comparison."""
        baseline_path = Path("tests/_fixtures/ios/hackernews-results.json")
        with open(baseline_path, "r") as f:
            data: Dict[str, Any] = json.load(f)
            return data

    def test_hackernews_component_analysis_regression(self, sample_app_path: Path) -> None:
        """Test binary component analysis against known HackerNews app structure to detect regressions.

        This test asserts against the specific section sizes and categorizations we expect
        from the HackerNews sample app to catch any regressions in the component analysis logic.
        """
        analyzer = AppleAppAnalyzer(skip_range_mapping=False)
        artifact = ArtifactFactory.from_path(sample_app_path)
        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Get the first binary analysis result since we know there's only one binary
        binary_analysis = results.binary_analysis[0]
        component_analysis = binary_analysis.binary_analysis
        assert component_analysis is not None

        # Get sizes by tag from the component analysis
        size_by_tag = component_analysis.size_by_tag()

        # Expected sizes for different component categories
        # Note: These are baseline expectations that may need adjustment as the categorization
        # logic is refined, but they serve as regression tests for major changes
        expected_sizes = {
            BinaryTag.TEXT_SEGMENT: 1842548,
            BinaryTag.OBJC_CLASSES: 430336,
            BinaryTag.DATA_SEGMENT: 114666,
            BinaryTag.C_STRINGS: 200543,
            BinaryTag.SWIFT_METADATA: 114830,
            BinaryTag.CONST_DATA: 79511,
            BinaryTag.UNMAPPED: 0,
            BinaryTag.UNWIND_INFO: 59076,
            BinaryTag.CODE_SIGNATURE: 43488,
            BinaryTag.FUNCTION_STARTS: 13584,
            BinaryTag.LOAD_COMMANDS: 8312,
            BinaryTag.HEADERS: 32,
        }

        for tag, expected_size in expected_sizes.items():
            actual_size = size_by_tag.get(tag, 0)
            assert actual_size == expected_size, (
                f"Component {tag.name} size should be {expected_size}, got {actual_size}"
            )

    def test_component_analysis_completeness(self, sample_app_path: Path) -> None:
        """Test that components are properly analyzed in real binary."""
        analyzer = AppleAppAnalyzer(skip_range_mapping=False)
        artifact = ArtifactFactory.from_path(sample_app_path)
        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Get the first binary analysis result since we know there's only one binary
        binary_analysis = results.binary_analysis[0]
        component_analysis = binary_analysis.binary_analysis
        assert component_analysis is not None

        # Verify we have components for different categories
        text_components = component_analysis.get_components_by_tag(BinaryTag.TEXT_SEGMENT)
        data_components = component_analysis.get_components_by_tag(BinaryTag.DATA_SEGMENT)

        assert len(text_components) >= 1, "Should have at least one TEXT segment component"
        assert len(data_components) >= 1, "Should have at least one DATA segment component"

        # Verify components have positive sizes and valid names
        for component in component_analysis.components:
            assert component.size > 0, f"Component {component.name} should have positive size"
            assert component.name, "Component should have a non-empty name"

        # Verify reasonable coverage of the binary
        assert component_analysis.coverage_percentage > 80, "Should analyze most of the binary"
