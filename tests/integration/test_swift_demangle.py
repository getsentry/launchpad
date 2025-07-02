import os

import pytest

from launchpad.utils.apple.swift_demangle import SwiftDemangler


def is_darwin() -> bool:
    """Check if running on macOS."""
    return os.name == "posix" and os.uname().sysname == "Darwin"


@pytest.mark.skipif(not is_darwin(), reason="swift-demangle is _currently_ only available on macOS")
class TestSwiftDemangler:
    """Integration test cases for the SwiftDemangler class."""

    def test_init(self):
        """Test SwiftDemangler initialization."""
        demangler = SwiftDemangler(remangle=True)
        assert demangler.remangle is True
        assert demangler.queue == []

    def test_add_name(self):
        """Test adding names to the queue."""
        demangler = SwiftDemangler()
        demangler.add_name("_$s3foo3barBaz")
        demangler.add_name("_$s3foo3quxQux")

        assert demangler.queue == ["_$s3foo3barBaz", "_$s3foo3quxQux"]

    def test_demangle_all_empty_queue(self):
        """Test demangle_all with empty queue."""
        demangler = SwiftDemangler()
        result = demangler.demangle_all()
        assert result == {}

    def test_demangle_all_success(self):
        """Test successful demangling with real swift-demangle."""
        demangler = SwiftDemangler()
        demangler.add_name(
            "_$s6Sentry0A14OnDemandReplayC8addFrame33_70FE3B80E922CEF5576FF378226AFAE1LL5image9forScreenySo7UIImageC_SSSgtF"
        )
        demangler.add_name(
            "_$s6Sentry0A18UserFeedbackWidgetC18RootViewControllerC6config6buttonAeA0abC13ConfigurationC_AA0abcd6ButtonF0Ctcfc"
        )

        result = demangler.demangle_all()

        assert len(result) == 2
        assert (
            "_$s6Sentry0A14OnDemandReplayC8addFrame33_70FE3B80E922CEF5576FF378226AFAE1LL5image9forScreenySo7UIImageC_SSSgtF"
            in result
        )
        assert (
            "_$s6Sentry0A18UserFeedbackWidgetC18RootViewControllerC6config6buttonAeA0abC13ConfigurationC_AA0abcd6ButtonF0Ctcfc"
            in result
        )
        assert (
            result[
                "_$s6Sentry0A14OnDemandReplayC8addFrame33_70FE3B80E922CEF5576FF378226AFAE1LL5image9forScreenySo7UIImageC_SSSgtF"
            ]
            == "Sentry.SentryOnDemandReplay.(addFrame in _70FE3B80E922CEF5576FF378226AFAE1)(image: __C.UIImage, forScreen: Swift.String?) -> ()"
        )
        assert (
            result[
                "_$s6Sentry0A18UserFeedbackWidgetC18RootViewControllerC6config6buttonAeA0abC13ConfigurationC_AA0abcd6ButtonF0Ctcfc"
            ]
            == "Sentry.SentryUserFeedbackWidget.RootViewController.init(config: Sentry.SentryUserFeedbackConfiguration, button: Sentry.SentryUserFeedbackWidgetButtonView) -> Sentry.SentryUserFeedbackWidget.RootViewController"
        )

    def test_demangle_all_chunked_processing(self):
        """Test that chunked processing works with many names."""
        demangler = SwiftDemangler()

        # Add more than 500 names to test chunking
        for i in range(600):
            demangler.add_name(f"_$s3foo3bar{i}Baz")

        result = demangler.demangle_all()

        # Should process all names
        assert len(result) == 600
        # All names should be processed (even if some fail, they should be in the result)
        for i in range(600):
            assert f"_$s3foo3bar{i}Baz" in result
