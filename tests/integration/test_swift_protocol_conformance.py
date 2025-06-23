"""Integration tests for Swift protocol conformance parsing."""

from pathlib import Path
from typing import cast

import pytest

from launchpad.analyzers.apple import AppleAppAnalyzer
from launchpad.artifacts.artifact import AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory


class TestSwiftProtocolConformance:
    """Test Swift protocol conformance parsing against real binaries."""

    @pytest.fixture
    def sample_app_path(self) -> Path:
        """Path to the sample HackerNews app."""
        return Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")

    def test_hackernews_protocol_conformance_parsing(self, sample_app_path: Path) -> None:
        """Test protocol conformance parsing against HackerNews app.

        This test verifies that we can extract protocol conformance information
        from the Swift metadata in the HackerNews binary. The HackerNews app
        should contain 286 protocol conformances.
        """
        analyzer = AppleAppAnalyzer(skip_swift_metadata=False)
        artifact = ArtifactFactory.from_path(sample_app_path)
        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Get the first binary analysis result since we know there's only one binary
        binary_analysis = results.binary_analysis[0]

        # Test that we get exactly 286 protocol conformances
        protocol_conformances = (
            binary_analysis.swift_metadata.protocol_conformances if binary_analysis.swift_metadata else []
        )
        assert (
            len(protocol_conformances) == 286
        ), f"Expected 286 protocol conformances, got {len(protocol_conformances)}"

        assert protocol_conformances[0] == "_$ss22KeyedDecodingContainerV6decode_6forKeyS2im_xtKF"

    def test_protocol_conformance_structure(self, sample_app_path: Path) -> None:
        """Test that protocol conformance data has the expected structure."""
        analyzer = AppleAppAnalyzer(skip_swift_metadata=False)
        artifact = ArtifactFactory.from_path(sample_app_path)
        results = analyzer.analyze(cast(AppleArtifact, artifact))

        binary_analysis = results.binary_analysis[0]
        swift_metadata = binary_analysis.swift_metadata

        assert swift_metadata is not None, "Swift metadata should be present"
        assert swift_metadata.protocol_conformances is not None, "Protocol conformances should be present"

        # Test that protocol conformances is a list
        assert isinstance(swift_metadata.protocol_conformances, list), "Protocol conformances should be a list"
