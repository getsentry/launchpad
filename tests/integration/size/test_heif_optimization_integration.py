"""Integration tests for HEIF optimization insight."""

from pathlib import Path

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.insights.apple.heif_optimization import HEIFOptimizationInsight
from launchpad.size.insights.insight import InsightsInput


@pytest.fixture
def hackernews_artifact() -> ZippedXCArchive:
    """Get the HackerNews test artifact."""
    fixture_path = Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")
    if not fixture_path.exists():
        pytest.skip(f"Test fixture not found: {fixture_path}")
    return ZippedXCArchive(fixture_path)


def test_heif_optimization_insight_integration(hackernews_artifact: ZippedXCArchive):
    """Test HEIF optimization insight with real HackerNews app."""
    analyzer = AppleAppAnalyzer(skip_swift_metadata=True, skip_symbols=True, skip_range_mapping=True, skip_treemap=True)

    # Preprocess to get app info
    app_info = analyzer.preprocess(hackernews_artifact)

    # Analyze files
    file_analysis = analyzer._analyze_files(hackernews_artifact)

    # Create insights input
    insights_input = InsightsInput(
        app_info=app_info,
        file_analysis=file_analysis,
        binary_analysis=[],
        treemap=None,
    )

    # Generate HEIF optimization insights
    heif_insight = HEIFOptimizationInsight()
    result = heif_insight.generate(insights_input)

    # Verify the result structure
    assert result is not None
    assert hasattr(result, "optimizeable_image_files")
    assert hasattr(result, "total_savings")
    assert isinstance(result.total_savings, int)
    assert result.total_savings >= 0

    # Log some information about what we found
    print(f"Found {len(result.optimizeable_image_files)} optimizable images")
    print(f"Total potential savings: {result.total_savings} bytes")

    # Check each optimizable image
    for image_file in result.optimizeable_image_files:
        assert image_file.file_info is not None
        assert image_file.potential_savings > 0
        assert image_file.potential_savings >= 4096  # 4KB minimum

        # Verify the file type is one we expect
        assert image_file.file_info.file_type in ["png", "jpg", "jpeg", "heic"]

        # Verify the file path doesn't contain stickerpack
        assert ".stickerpack" not in str(image_file.file_info.full_path)

        print(f"  - {image_file.file_info.full_path}: {image_file.potential_savings} bytes savings")


def test_heif_optimization_with_full_analyzer(hackernews_artifact: ZippedXCArchive):
    """Test HEIF optimization insight as part of full analyzer."""
    analyzer = AppleAppAnalyzer(
        skip_swift_metadata=True, skip_symbols=True, skip_range_mapping=True, skip_treemap=True, skip_insights=False
    )

    # Run full analysis
    results = analyzer.analyze(hackernews_artifact)

    # Verify insights were generated
    assert results.insights is not None
    assert results.insights.heif_optimization is not None

    heif_result = results.insights.heif_optimization

    # Verify the result structure
    assert hasattr(heif_result, "optimizeable_image_files")
    assert hasattr(heif_result, "total_savings")
    assert isinstance(heif_result.total_savings, int)
    assert heif_result.total_savings >= 0

    print(f"Full analyzer found {len(heif_result.optimizeable_image_files)} optimizable images")
    print(f"Total potential savings: {heif_result.total_savings} bytes")

    # Verify total savings matches sum of individual savings
    calculated_total = sum(img.potential_savings for img in heif_result.optimizeable_image_files)
    assert heif_result.total_savings == calculated_total
