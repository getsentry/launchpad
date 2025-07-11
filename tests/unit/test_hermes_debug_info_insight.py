"""Tests for Hermes debug info insight."""

from pathlib import Path
from unittest.mock import Mock

from launchpad.size.hermes.reporter import HermesReport
from launchpad.size.insights.common import HermesDebugInfoInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import BaseAppInfo, FileAnalysis, FileInfo
from launchpad.size.models.insights import HermesDebugInfoInsightResult
from launchpad.size.models.treemap import TreemapType


class TestHermesDebugInfoInsight:
    def setup_method(self):
        self.insight = HermesDebugInfoInsight()

    def test_generate_with_hermes_files_with_debug_info(self):
        """Test that insight is generated when Hermes files have debug info."""
        # Create a Hermes file with debug info
        hermes_file = FileInfo(
            full_path=Path("assets/index.jsbundle"),
            path="assets/index.jsbundle",
            size=1024 * 1024,  # 1MB
            file_type="jsbundle",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )

        # Create Hermes report with debug info
        hermes_report: HermesReport = {
            "sections": {
                "Header": {"bytes": 128, "percentage": 0.1},
                "Function table": {"bytes": 1024, "percentage": 1.0},
                "String Kinds": {"bytes": 512, "percentage": 0.5},
                "Identifier hashes": {"bytes": 256, "percentage": 0.25},
                "String table": {"bytes": 2048, "percentage": 2.0},
                "Overflow String table": {"bytes": 0, "percentage": 0.0},
                "String storage": {"bytes": 10240, "percentage": 10.0},
                "Array buffer": {"bytes": 0, "percentage": 0.0},
                "Object key buffer": {"bytes": 0, "percentage": 0.0},
                "Object value buffer": {"bytes": 0, "percentage": 0.0},
                "BigInt storage": {"bytes": 0, "percentage": 0.0},
                "Regular expression table": {"bytes": 0, "percentage": 0.0},
                "Regular expression storage": {"bytes": 0, "percentage": 0.0},
                "CommonJS module table": {"bytes": 0, "percentage": 0.0},
                "Function body": {"bytes": 81920, "percentage": 80.0},
                "Function info": {"bytes": 1024, "percentage": 1.0},
                "Debug info": {"bytes": 2048, "percentage": 2.0},  # Debug info present
                "Function Source table": {"bytes": 0, "percentage": 0.0},
            },
            "unattributed": {"bytes": 0, "percentage": 0.0},
            "file_size": 102400,
        }

        file_analysis = FileAnalysis(files=[hermes_file])
        hermes_reports = {"assets/index.jsbundle": hermes_report}

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
            hermes_reports=hermes_reports,
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, HermesDebugInfoInsightResult)
        assert len(result.files) == 1
        assert result.files[0].path == "assets/index.jsbundle"
        assert result.total_savings == 2048  # Debug info size

    def test_generate_with_hermes_files_without_debug_info(self):
        """Test that no insight is generated when Hermes files have no debug info."""
        # Create a Hermes file without debug info
        hermes_file = FileInfo(
            full_path=Path("assets/index.jsbundle"),
            path="assets/index.jsbundle",
            size=1024 * 1024,  # 1MB
            file_type="jsbundle",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )

        # Create Hermes report without debug info
        hermes_report: HermesReport = {
            "sections": {
                "Header": {"bytes": 128, "percentage": 0.1},
                "Function table": {"bytes": 1024, "percentage": 1.0},
                "String Kinds": {"bytes": 512, "percentage": 0.5},
                "Identifier hashes": {"bytes": 256, "percentage": 0.25},
                "String table": {"bytes": 2048, "percentage": 2.0},
                "Overflow String table": {"bytes": 0, "percentage": 0.0},
                "String storage": {"bytes": 10240, "percentage": 10.0},
                "Array buffer": {"bytes": 0, "percentage": 0.0},
                "Object key buffer": {"bytes": 0, "percentage": 0.0},
                "Object value buffer": {"bytes": 0, "percentage": 0.0},
                "BigInt storage": {"bytes": 0, "percentage": 0.0},
                "Regular expression table": {"bytes": 0, "percentage": 0.0},
                "Regular expression storage": {"bytes": 0, "percentage": 0.0},
                "CommonJS module table": {"bytes": 0, "percentage": 0.0},
                "Function body": {"bytes": 81920, "percentage": 80.0},
                "Function info": {"bytes": 1024, "percentage": 1.0},
                "Debug info": {"bytes": 0, "percentage": 0.0},  # No debug info
                "Function Source table": {"bytes": 0, "percentage": 0.0},
            },
            "unattributed": {"bytes": 0, "percentage": 0.0},
            "file_size": 102400,
        }

        file_analysis = FileAnalysis(files=[hermes_file])
        hermes_reports = {"assets/index.jsbundle": hermes_report}

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
            hermes_reports=hermes_reports,
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, HermesDebugInfoInsightResult)
        assert len(result.files) == 0
        assert result.total_savings == 0

    def test_generate_with_non_hermes_files(self):
        """Test that non-Hermes files are ignored."""
        # Create a non-Hermes file
        non_hermes_file = FileInfo(
            full_path=Path("assets/image.png"),
            path="assets/image.png",
            size=1024 * 1024,  # 1MB
            file_type="png",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )

        file_analysis = FileAnalysis(files=[non_hermes_file])
        hermes_reports: dict[str, HermesReport] = {}

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
            hermes_reports=hermes_reports,
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, HermesDebugInfoInsightResult)
        assert len(result.files) == 0
        assert result.total_savings == 0

    def test_generate_with_no_hermes_reports(self):
        """Test that insight returns empty result when no Hermes reports are provided."""
        hermes_file = FileInfo(
            full_path=Path("assets/index.jsbundle"),
            path="assets/index.jsbundle",
            size=1024 * 1024,  # 1MB
            file_type="jsbundle",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )

        file_analysis = FileAnalysis(files=[hermes_file])

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
            hermes_reports=None,
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, HermesDebugInfoInsightResult)
        assert len(result.files) == 0
        assert result.total_savings == 0

    def test_generate_with_multiple_hermes_files(self):
        """Test that multiple Hermes files with debug info are handled correctly."""
        # Create two Hermes files with different debug info sizes
        hermes_file_1 = FileInfo(
            full_path=Path("assets/index.jsbundle"),
            path="assets/index.jsbundle",
            size=1024 * 1024,  # 1MB
            file_type="jsbundle",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash1",
        )
        hermes_file_2 = FileInfo(
            full_path=Path("assets/vendor.hbc"),
            path="assets/vendor.hbc",
            size=512 * 1024,  # 512KB
            file_type="hbc",
            treemap_type=TreemapType.ASSETS,
            hash_md5="hash2",
        )

        # Create Hermes reports with different debug info sizes
        hermes_report_1: HermesReport = {
            "sections": {
                "Header": {"bytes": 128, "percentage": 0.1},
                "Function table": {"bytes": 1024, "percentage": 1.0},
                "Debug info": {"bytes": 1024, "percentage": 1.0},  # Smaller debug info
                "Function Source table": {"bytes": 0, "percentage": 0.0},
            },
            "unattributed": {"bytes": 0, "percentage": 0.0},
            "file_size": 102400,
        }
        hermes_report_2: HermesReport = {
            "sections": {
                "Header": {"bytes": 128, "percentage": 0.1},
                "Function table": {"bytes": 1024, "percentage": 1.0},
                "Debug info": {"bytes": 2048, "percentage": 2.0},  # Larger debug info
                "Function Source table": {"bytes": 0, "percentage": 0.0},
            },
            "unattributed": {"bytes": 0, "percentage": 0.0},
            "file_size": 102400,
        }

        file_analysis = FileAnalysis(files=[hermes_file_1, hermes_file_2])
        hermes_reports = {
            "assets/index.jsbundle": hermes_report_1,
            "assets/vendor.hbc": hermes_report_2,
        }

        insights_input = InsightsInput(
            app_info=Mock(spec=BaseAppInfo),
            file_analysis=file_analysis,
            treemap=Mock(),
            binary_analysis=[],
            hermes_reports=hermes_reports,
        )

        result = self.insight.generate(insights_input)

        assert isinstance(result, HermesDebugInfoInsightResult)
        assert len(result.files) == 2
        # Should be sorted by debug info size (largest first)
        assert result.files[0].path == "assets/vendor.hbc"  # Larger debug info
        assert result.files[1].path == "assets/index.jsbundle"  # Smaller debug info
        assert result.total_savings == 3072  # 1024 + 2048
