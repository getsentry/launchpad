"""Integration tests for WebP optimization insight with real Android artifacts."""

from pathlib import Path
from typing import cast

from launchpad.analyzers.android import AndroidAnalyzer
from launchpad.artifacts.artifact import AndroidArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.models.common import FileInfo
from launchpad.models.treemap import TreemapType


class TestWebpOptimizationIntegration:
    """Integration tests for WebP optimization insight."""

    def test_webp_optimization_with_hackernews_apk(self):
        """Test WebP optimization insight with the HackerNews APK fixture."""
        apk_path = Path("tests/_fixtures/android/app-debug.apk")

        artifact = ArtifactFactory.from_path(apk_path)
        analyzer = AndroidAnalyzer(skip_insights=False)

        results = analyzer.analyze(cast(AndroidArtifact, artifact))

        assert results.insights is not None
        assert results.insights.image_optimization is not None

        insight = results.insights.image_optimization
        assert hasattr(insight, "images")
        assert hasattr(insight, "total_savings")
        assert isinstance(insight.total_savings, int)
        assert insight.total_savings == 14400
        print(insight.images)
        assert insight.images == [
            FileInfo(
                path="res/mipmap-anydpi-v21/png_test.png",
                size=13691,
                treemap_type=TreemapType.ASSETS,
                file_type="png",
                hash_md5="",
            ),
            FileInfo(
                path="res/drawable-hdpi-v4/notification_oversize_large_icon_bg.png",
                size=709,
                treemap_type=TreemapType.ASSETS,
                file_type="png",
                hash_md5="",
            ),
        ]

        if insight.images:
            savings = [img.size for img in insight.images]  # Size stores the savings
            assert savings == sorted(savings, reverse=True)

            for img in insight.images:
                assert img.size >= 500

            print(f"Found {len(insight.images)} optimizable images with total savings of {insight.total_savings} bytes")
        else:
            print("No optimizable images found in the test APK")

    def test_webp_optimization_with_aab(self):
        """Test WebP optimization insight with the HackerNews AAB fixture."""
        aab_path = Path("tests/_fixtures/android/hn.aab")

        artifact = ArtifactFactory.from_path(aab_path)
        analyzer = AndroidAnalyzer(skip_insights=False)

        results = analyzer.analyze(cast(AndroidArtifact, artifact))

        assert results.insights is not None
        assert results.insights.image_optimization is not None

        insight = results.insights.image_optimization
        assert hasattr(insight, "images")
        assert hasattr(insight, "total_savings")
        assert isinstance(insight.total_savings, int)
        assert insight.total_savings >= 0
