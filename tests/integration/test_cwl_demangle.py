import os

import pytest

from launchpad.utils.cwl_demangle import CwlDemangler, CwlDemangleResult


def is_darwin() -> bool:
    """Check if running on macOS."""
    return os.name == "posix" and os.uname().sysname == "Darwin"


@pytest.mark.skipif(not is_darwin(), reason="cwl-demangle is only available on macOS")
class TestCwlDemangler:
    """Integration test cases for the CwlDemangler class."""

    def test_init(self):
        """Test CwlDemangler initialization."""
        demangler = CwlDemangler(is_type=True)
        assert demangler.is_type is True
        assert demangler.queue == []

    def test_add_name(self):
        """Test adding names to the queue."""
        demangler = CwlDemangler()
        demangler.add_name("_$s3foo3barBaz")
        demangler.add_name("_$s3foo3quxQux")

        assert demangler.queue == ["_$s3foo3barBaz", "_$s3foo3quxQux"]

    def test_demangle_all_empty_queue(self):
        """Test demangle_all with empty queue."""
        demangler = CwlDemangler()
        result = demangler.demangle_all()
        assert result == {}

    def test_demangle_all_success(self):
        """Test successful demangling with real cwl-demangle."""
        demangler = CwlDemangler()
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

        # Check that results are CwlDemangleResult instances
        first_result = result[
            "_$s6Sentry0A14OnDemandReplayC8addFrame33_70FE3B80E922CEF5576FF378226AFAE1LL5image9forScreenySo7UIImageC_SSSgtF"
        ]
        assert isinstance(first_result, CwlDemangleResult)
        assert first_result.mangled == "_$s6Sentry0A14OnDemandReplayC8addFrame33_70FE3B80E922CEF5576FF378226AFAE1LL5image9forScreenySo7UIImageC_SSSgtF"

        second_result = result[
            "_$s6Sentry0A18UserFeedbackWidgetC18RootViewControllerC6config6buttonAeA0abC13ConfigurationC_AA0abcd6ButtonF0Ctcfc"
        ]
        assert isinstance(second_result, CwlDemangleResult)
        assert second_result.mangled == "_$s6Sentry0A18UserFeedbackWidgetC18RootViewControllerC6config6buttonAeA0abC13ConfigurationC_AA0abcd6ButtonF0Ctcfc"

    def test_demangle_all_chunked_processing(self):
        """Test that chunked processing works with many names."""
        demangler = CwlDemangler()

        # Add more than 500 names to test chunking
        for i in range(600):
            demangler.add_name(f"_$s3foo3bar{i}Baz")

        result = demangler.demangle_all()

        # Should process all names
        assert len(result) == 600
        # All names should be processed (even if some fail, they should be in the result)
        for i in range(600):
            mangled_name = f"_$s3foo3bar{i}Baz"
            assert mangled_name in result
            # Check that each result is a CwlDemangleResult instance
            assert isinstance(result[mangled_name], CwlDemangleResult)
            assert result[mangled_name].mangled == mangled_name