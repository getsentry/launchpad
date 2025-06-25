"""Integration tests for WebP asset optimization insights."""

from pathlib import Path

import pytest

from launchpad.analyzers.android import AndroidAnalyzer
from launchpad.artifacts.artifact_factory import ArtifactFactory


@pytest.fixture
def fixtures_dir() -> Path:
    return Path("tests/_fixtures/")


@pytest.fixture
def android_fixtures(fixtures_dir: Path) -> dict[str, Path]:
    android_dir = fixtures_dir / "android"
    return {
        "aab": android_dir / "hn.aab",
        "zipped_aab": android_dir / "zipped_aab.zip",
        "apk": android_dir / "hn.apk",
        "zipped_apk": android_dir / "zipped_apk.zip",
        "app-debug.apk": android_dir / "app-debug.apk",
    }


@pytest.fixture
def android_analyzer() -> AndroidAnalyzer:
    return AndroidAnalyzer()


class TestWebpAssetIntegration:
    """Integration tests for WebP asset optimization insights."""

    def test_webp_asset_insight_with_hackernews_apk(self, android_fixtures: dict[str, Path]):
        """Test WebP asset insight with the Hacker News APK."""
        apk_path = android_fixtures["app-debug.apk"]

        artifact = ArtifactFactory.from_path(apk_path)
        analyzer = AndroidAnalyzer(skip_insights=False)

        results = analyzer.analyze(artifact)

        assert results.insights is not None
        assert results.insights.webp_assets is not None

        webp_insight = results.insights.webp_assets
        assert isinstance(webp_insight.optimization_opportunities, list)
        assert isinstance(webp_insight.total_potential_savings, int)
        assert webp_insight.total_potential_savings > 0

        opportunity = webp_insight.optimization_opportunities[0]
        assert "file_path" in opportunity
        assert "original_size" in opportunity
        assert "webp_size" in opportunity
        assert "potential_savings" in opportunity
        assert "compression_ratio" in opportunity
        assert "file_type" in opportunity

        assert isinstance(opportunity["file_path"], str)
        assert isinstance(opportunity["original_size"], int)
        assert isinstance(opportunity["webp_size"], int)
        assert isinstance(opportunity["potential_savings"], int)
        assert isinstance(opportunity["compression_ratio"], float)
        assert isinstance(opportunity["file_type"], str)

        # Verify logical constraints
        assert opportunity["original_size"] == 48061
        assert opportunity["webp_size"] == 34370
        assert opportunity["potential_savings"] == 13691
