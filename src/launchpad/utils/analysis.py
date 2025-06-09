"""
Analysis utilities for converting CLI results to web API format.
"""

from typing import List

import structlog

from app_size_analyzer.models.ios import IOSAnalysisResults
from launchpad.models.analysis import AnalysisResult, ComponentSize

logger = structlog.get_logger(__name__)


def convert_cli_results_to_api_format(cli_results: IOSAnalysisResults, artifact_path: str) -> AnalysisResult:
    """Convert CLI analysis results to web API format."""

    # For now, only handle iOS results
    if not isinstance(cli_results, IOSAnalysisResults):
        raise ValueError(f"Unsupported analysis results type: {type(cli_results)}")

    platform = "ios"

    # Convert to component breakdown
    components = _convert_to_components(cli_results)

    # Create summary
    summary = _create_summary(cli_results)

    # Create metadata
    metadata = _create_metadata(cli_results)

    return AnalysisResult(
        artifact_path=artifact_path,
        platform=platform,
        total_file_size=cli_results.file_analysis.total_size,
        total_download_size=cli_results.file_analysis.total_size,
        components=components,
        summary=summary,
        metadata=metadata,
    )


def _convert_to_components(cli_results: IOSAnalysisResults) -> List[ComponentSize]:
    """Convert CLI results to ComponentSize list."""
    components: List[ComponentSize] = []
    total_size = cli_results.file_analysis.total_size

    # Convert file type analysis
    for file_type, size in cli_results.file_analysis.file_type_sizes.items():
        percentage = (size / total_size) * 100 if total_size > 0 else 0
        components.append(
            ComponentSize(
                name=file_type or "unknown",
                file_size=size,
                download_size=size,
                percentage=percentage,
                path=None,  # File type summary doesn't have specific path
                type="file_type",
            )
        )

    # Add iOS binary information
    if cli_results.binary_analysis.executable_size > 0:
        binary_percentage = (cli_results.binary_analysis.executable_size / total_size) * 100 if total_size > 0 else 0
        components.append(
            ComponentSize(
                name="Executable",
                file_size=cli_results.binary_analysis.executable_size,
                download_size=cli_results.binary_analysis.executable_size,
                percentage=binary_percentage,
                path=None,
                type="binary",
            )
        )

    return components


def _create_summary(cli_results: IOSAnalysisResults) -> dict:
    """Create summary statistics from CLI results."""
    return {
        "total_size": cli_results.file_analysis.total_size,
        "executable_size": cli_results.binary_analysis.executable_size,
        "file_count": cli_results.file_analysis.file_count,
        "duplicate_files": len(cli_results.file_analysis.duplicate_files),
        "potential_savings": cli_results.file_analysis.total_duplicate_savings,
        **cli_results.file_analysis.file_type_sizes,
    }


def _create_metadata(cli_results: IOSAnalysisResults) -> dict:
    """Create metadata from CLI results."""
    return {
        "analyzer": "IOSAnalyzer",
        "app_name": cli_results.app_info.name,
        "bundle_id": cli_results.app_info.bundle_id,
        "version": cli_results.app_info.version,
        "architectures": cli_results.binary_analysis.architectures,
        "analysis_duration": getattr(cli_results, "analysis_duration", None),
    }
