"""
Analysis service for coordinating artifact analysis.
"""

import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import structlog

from app_size_analyzer.analyzers import IOSAnalyzer
from app_size_analyzer.models.ios import IOSAnalysisResults
from launchpad.models.analysis import AnalysisResult
from launchpad.settings import get_settings
from launchpad.utils.analysis import convert_cli_results_to_api_format

logger = structlog.get_logger(__name__)


class AnalysisService:
    """Service for managing artifact analysis."""

    def __init__(self):
        self.settings = get_settings()
        self.temp_dir = Path(self.settings.temp_dir)
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def analyze_artifact(self, artifact_path: Path) -> AnalysisResult:
        """Analyze an artifact and return the results."""
        logger.info("Starting artifact analysis", artifact_path=str(artifact_path))

        if not artifact_path.exists():
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")

        if artifact_path.stat().st_size > self.settings.max_file_size:
            raise ValueError(f"Artifact too large: {artifact_path.stat().st_size} bytes")

        # Determine the analyzer to use and run analysis
        cli_results = self._run_analysis(artifact_path)
        if not cli_results:
            raise ValueError(f"No analyzer found for artifact: {artifact_path}")

        # Convert CLI results to web API format
        result = convert_cli_results_to_api_format(cli_results, str(artifact_path))

        logger.info(
            "Artifact analysis completed",
            artifact_path=str(artifact_path),
            platform=result.platform,
            total_size=result.total_file_size,
            components=len(result.components),
        )

        return result

    def _run_analysis(self, artifact_path: Path) -> Optional[IOSAnalysisResults]:
        """Run the appropriate CLI analyzer for the given artifact."""

        # Try iOS analysis
        if artifact_path.suffix.lower() == ".zip" and "xcarchive" in artifact_path.name.lower():
            ios_analyzer = IOSAnalyzer()
            if ios_analyzer.can_analyze(artifact_path):
                logger.info("Using iOS analyzer", artifact_path=str(artifact_path))
                return ios_analyzer.analyze(artifact_path)

        # Android analysis is not yet implemented
        elif artifact_path.suffix.lower() in [".apk", ".aab"]:
            logger.warning("Android analysis not implemented", artifact_path=str(artifact_path))
            raise NotImplementedError("Android analysis is not yet implemented")

        logger.warning("No suitable analyzer found", artifact_path=str(artifact_path))
        return None

    def _extract_if_needed(self, artifact_path: Path) -> Path:
        """Extract the artifact if it's compressed."""
        if artifact_path.suffix == ".zip":
            with tempfile.TemporaryDirectory(dir=self.temp_dir) as temp_dir:
                extract_path = Path(temp_dir) / artifact_path.stem

                with zipfile.ZipFile(artifact_path, "r") as zip_ref:
                    zip_ref.extractall(extract_path)

                return extract_path

        return artifact_path
