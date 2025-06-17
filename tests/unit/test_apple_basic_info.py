from pathlib import Path

from launchpad.analyzers.apple import AppleAppAnalyzer
from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive


class TestAppleBasicInfo:
    """Test Apple analyzer basic info extraction."""

    def test_basic_info(self) -> None:
        """Test that range mapping is enabled by default."""
        analyzer = AppleAppAnalyzer()
        with open(Path("tests/_fixtures/ios/HackerNews.xcarchive.zip"), "rb") as f:
            archive = ZippedXCArchive(f.read())

        basic_info = analyzer.preprocess(archive)
        assert basic_info.name == "HackerNews"
        assert basic_info.version == "3.8"
        assert basic_info.build == "1"
        assert basic_info.executable == "HackerNews"
        assert basic_info.minimum_os_version == "17.5"
        assert basic_info.supported_platforms == ["iPhoneOS"]
        assert basic_info.sdk_version == "iphoneos18.4"
        assert basic_info.is_simulator is False
        assert basic_info.codesigning_type == "development"
