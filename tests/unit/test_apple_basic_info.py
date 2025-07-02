from pathlib import Path

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.size.analyzers.apple import AppleAppAnalyzer


class TestAppleBasicInfo:
    """Test Apple analyzer basic info extraction."""

    def test_basic_info(self) -> None:
        """Test that range mapping is enabled by default."""
        analyzer = AppleAppAnalyzer()
        path = Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")
        archive = ZippedXCArchive(path)

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
        assert basic_info.is_code_signature_valid is True
        assert basic_info.code_signature_errors == []
