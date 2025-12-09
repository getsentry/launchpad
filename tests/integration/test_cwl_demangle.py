import os

from unittest import mock

from launchpad.utils.apple.cwl_demangle import CwlDemangler, CwlDemangleResult


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
        assert (
            first_result.mangled
            == "_$s6Sentry0A14OnDemandReplayC8addFrame33_70FE3B80E922CEF5576FF378226AFAE1LL5image9forScreenySo7UIImageC_SSSgtF"
        )

        second_result = result[
            "_$s6Sentry0A18UserFeedbackWidgetC18RootViewControllerC6config6buttonAeA0abC13ConfigurationC_AA0abcd6ButtonF0Ctcfc"
        ]
        assert isinstance(second_result, CwlDemangleResult)
        assert (
            second_result.mangled
            == "_$s6Sentry0A18UserFeedbackWidgetC18RootViewControllerC6config6buttonAeA0abC13ConfigurationC_AA0abcd6ButtonF0Ctcfc"
        )

    def test_parallel_processing(self):
        """Test demangling with 20k+ symbols (covers chunking and parallel mode)."""
        demangler = CwlDemangler(continue_on_error=True)

        # Generate 20k symbols (4 chunks at 5k each)
        symbols_needed = 20000
        symbols = self._generate_symbols(symbols_needed)
        for symbol in symbols:
            demangler.add_name(symbol)

        result = demangler.demangle_all()

        assert len(result) == symbols_needed
        # Spot check some symbols
        for symbol in symbols[::1000]:  # Every 1000th symbol
            assert symbol in result
            assert isinstance(result[symbol], CwlDemangleResult)

    def test_environment_variable_disables_parallel(self):
        """Test LAUNCHPAD_NO_PARALLEL_DEMANGLE env var disables parallel."""
        # Test with env var unset
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LAUNCHPAD_NO_PARALLEL_DEMANGLE", None)
            demangler = CwlDemangler()
            assert demangler.use_parallel is True

        # Test with "true"
        with mock.patch.dict(os.environ, {"LAUNCHPAD_NO_PARALLEL_DEMANGLE": "true"}):
            demangler = CwlDemangler()
            assert demangler.use_parallel is False

    def _generate_symbols(self, count: int) -> list[str]:
        """Generate valid Swift mangled symbols."""
        letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        symbols = []
        for i in range(count):
            letter1 = letters[i % len(letters)]
            letter2 = letters[(i // len(letters)) % len(letters)]
            letter3 = letters[(i // (len(letters) * len(letters))) % len(letters)]
            module_name = f"Test{letter1}{letter2}"
            symbol_name = f"Symbol{letter3}{i % 100}"
            mangled_name = f"_$s{len(module_name)}{module_name}{len(symbol_name)}{symbol_name}"
            symbols.append(mangled_name)
        return symbols
