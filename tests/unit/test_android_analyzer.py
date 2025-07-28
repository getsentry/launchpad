"""Tests for Android analyzer with duplicate file detection."""

from pathlib import Path
from typing import cast

import pytest

from launchpad.artifacts.artifact import AndroidArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.android import AndroidAnalyzer


@pytest.fixture
def test_apk_path() -> Path:
    return Path("tests/_fixtures/android/hn.apk")


@pytest.fixture
def android_analyzer() -> AndroidAnalyzer:
    return AndroidAnalyzer()


class TestAndroidAnalyzer:
    def test_analyze_with_duplicate_detection(self, test_apk_path: Path, android_analyzer: AndroidAnalyzer) -> None:
        """Test that Android analyzer includes duplicate file detection."""
        artifact = ArtifactFactory.from_path(test_apk_path)
        android_artifact = cast(AndroidArtifact, artifact)
        results = android_analyzer.analyze(android_artifact)

        assert results.app_info.name == "Hacker News"
        assert results.app_info.app_id == "com.emergetools.hackernews"
        assert results.file_analysis is not None
        assert len(results.file_analysis.files) > 0

        assert results.insights is not None
        assert results.insights.duplicate_files is not None

        duplicate_insight = results.insights.duplicate_files
        assert hasattr(duplicate_insight, "groups")
        assert hasattr(duplicate_insight, "total_savings")
        assert isinstance(duplicate_insight.total_savings, int)
        assert duplicate_insight.total_savings == 51709

    def test_duplicate_files_have_hashes(self, test_apk_path: Path, android_analyzer: AndroidAnalyzer) -> None:
        """Test that all files have MD5 hashes for duplicate detection."""
        artifact = ArtifactFactory.from_path(test_apk_path)
        android_artifact = cast(AndroidArtifact, artifact)
        results = android_analyzer.analyze(android_artifact)

        for file_info in results.file_analysis.files:
            assert file_info.hash is not None
            assert len(file_info.hash) > 0
