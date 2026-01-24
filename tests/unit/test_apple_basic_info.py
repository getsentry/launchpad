from pathlib import Path

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.size.analyzers.apple import AppleAppAnalyzer, _detect_apple_platform


class TestAppleBasicInfo:
    """Test Apple analyzer basic info extraction."""

    def test_basic_info(self, hackernews_xcarchive: Path) -> None:
        """Test that range mapping is enabled by default."""
        analyzer = AppleAppAnalyzer()
        archive = ZippedXCArchive(hackernews_xcarchive)

        basic_info = analyzer.preprocess(archive)
        assert basic_info.name == "HackerNews"
        assert basic_info.version == "3.8"
        assert basic_info.build == "1"
        assert basic_info.executable == "HackerNews"
        assert basic_info.minimum_os_version == "17.5"
        assert basic_info.supported_platforms == ["iPhoneOS"]
        assert basic_info.platform == "ios"
        assert basic_info.sdk_version == "iphoneos18.4"
        assert basic_info.build_date is not None
        assert basic_info.build_date == "2025-05-19T16:15:12"
        assert basic_info.is_simulator is False
        assert basic_info.codesigning_type == "development"
        assert basic_info.is_code_signature_valid is True
        assert basic_info.code_signature_errors == []
        assert basic_info.main_binary_uuid == "BEB3C0D6-2518-343D-BB6F-FF5581C544E8"
        assert basic_info.profile_expiration_date is not None
        assert basic_info.profile_expiration_date == "2025-12-02T18:15:00"
        assert basic_info.certificate_expiration_date is not None
        assert basic_info.certificate_expiration_date == "2025-01-01T17:56:11+00:00"


class TestDetectApplePlatform:
    """Test Apple platform detection from Info.plist."""

    @pytest.mark.parametrize(
        "plist,expected",
        [
            # iOS device
            ({"DTPlatformName": "iphoneos18.0", "CFBundleSupportedPlatforms": ["iPhoneOS"]}, "ios"),
            # iOS simulator
            ({"DTPlatformName": "iphonesimulator", "CFBundleSupportedPlatforms": ["iphonesimulator"]}, "ios"),
            # Mac Catalyst (treated as iOS)
            ({"DTPlatformName": "maccatalyst", "CFBundleSupportedPlatforms": ["iPhoneOS", "MacOSX"]}, "ios"),
            # macOS native
            ({"DTPlatformName": "macosx14.0", "CFBundleSupportedPlatforms": ["MacOSX"]}, "macos"),
            # tvOS
            ({"DTPlatformName": "appletvos18.0", "CFBundleSupportedPlatforms": ["AppleTVOS"]}, "tvos"),
            # tvOS simulator
            ({"DTPlatformName": "appletvsimulator", "CFBundleSupportedPlatforms": ["AppleTVSimulator"]}, "tvos"),
            # watchOS
            ({"DTPlatformName": "watchos11.0", "CFBundleSupportedPlatforms": ["WatchOS"]}, "watchos"),
            # watchOS simulator
            ({"DTPlatformName": "watchsimulator", "CFBundleSupportedPlatforms": ["WatchSimulator"]}, "watchos"),
        ],
    )
    def test_detect_platform_from_dt_platform_name(self, plist: dict, expected: str) -> None:
        """Test platform detection using DTPlatformName (primary method)."""
        assert _detect_apple_platform(plist) == expected

    @pytest.mark.parametrize(
        "plist,expected",
        [
            # Fallback to CFBundleSupportedPlatforms when DTPlatformName is missing
            ({"CFBundleSupportedPlatforms": ["iPhoneOS"]}, "ios"),
            ({"CFBundleSupportedPlatforms": ["iphonesimulator"]}, "ios"),
            ({"CFBundleSupportedPlatforms": ["MacOSX"]}, "macos"),
            ({"CFBundleSupportedPlatforms": ["AppleTVOS"]}, "tvos"),
            ({"CFBundleSupportedPlatforms": ["WatchOS"]}, "watchos"),
        ],
    )
    def test_detect_platform_fallback_to_supported_platforms(self, plist: dict, expected: str) -> None:
        """Test platform detection falls back to CFBundleSupportedPlatforms."""
        assert _detect_apple_platform(plist) == expected

    def test_detect_platform_empty_plist_defaults_to_ios(self) -> None:
        """Test that empty plist defaults to iOS for backwards compatibility."""
        assert _detect_apple_platform({}) == "ios"

    def test_detect_platform_unknown_values_default_to_ios(self) -> None:
        """Test that unknown platform values default to iOS."""
        plist = {"DTPlatformName": "unknownplatform", "CFBundleSupportedPlatforms": ["UnknownPlatform"]}
        assert _detect_apple_platform(plist) == "ios"
