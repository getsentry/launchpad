import os

from unittest import mock

import pytest

from launchpad.utils.apple.cwl_demangle import DEFAULT_DEMANGLE_TIMEOUT, CwlDemangler, CwlDemangleResult


class TestCwlDemangler:
    """Integration test cases for the CwlDemangler class."""

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

    def test_demangle_all_success(self, caplog: pytest.LogCaptureFixture):
        """Test successful demangling with real cwl-demangle."""
        caplog.set_level("INFO", logger="launchpad.utils.apple.cwl_demangle")
        demangler = CwlDemangler()
        first_symbol = "_$s6Sentry0A14OnDemandReplayC8addFrame33_70FE3B80E922CEF5576FF378226AFAE1LL5image9forScreenySo7UIImageC_SSSgtF"
        second_symbol = "_$s6Sentry0A18UserFeedbackWidgetC18RootViewControllerC6config6buttonAeA0abC13ConfigurationC_AA0abcd6ButtonF0Ctcfc"
        demangler.add_name(first_symbol)
        demangler.add_name(second_symbol)

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
        first_result = result[first_symbol]
        assert isinstance(first_result, CwlDemangleResult)
        assert first_result.mangled is first_symbol
        assert first_result.module == "Sentry"
        assert first_result.typeName == "SentryOnDemandReplay"
        assert first_result.testName == ["Sentry", "SentryOnDemandReplay", "addFrame(image,forScreen)"]

        second_result = result[second_symbol]
        assert isinstance(second_result, CwlDemangleResult)
        assert second_result.mangled is second_symbol
        assert first_result.module is second_result.module

        completed = next(
            record for record in caplog.records if record.getMessage() == "size.apple.swift_demangling_completed"
        )
        assert completed.symbol_count == 2
        assert completed.chunk_count == 1
        assert completed.timeout_s == DEFAULT_DEMANGLE_TIMEOUT
        assert completed.successful_chunk_subprocess_duration_max_s > 0

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

    def test_timeout_configuration(self):
        """Test LAUNCHPAD_DEMANGLE_TIMEOUT env var configures timeout."""
        demangler = CwlDemangler()

        # Test with custom timeout
        with mock.patch.dict(os.environ, {"LAUNCHPAD_DEMANGLE_TIMEOUT": "10"}):
            # Generate a few symbols to trigger sequential processing
            symbols = self._generate_symbols(100)
            for symbol in symbols:
                demangler.add_name(symbol)

            result = demangler.demangle_all()
            # Should succeed with custom timeout
            assert len(result) == 100

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
