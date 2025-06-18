from __future__ import annotations

from ..artifacts import AAB, APK, AndroidArtifact, ZippedAAB, ZippedAPK
from ..models.android import AndroidAnalysisResults, AndroidAppInfo
from ..models.common import FileAnalysis
from ..utils.logging import get_logger

logger = get_logger(__name__)


class AndroidAnalyzer:
    """Analyzer for Android apps (.apk, .aab files)."""

    def analyze(self, artifact: AndroidArtifact) -> AndroidAnalysisResults:
        manifest_dict = artifact.get_manifest().model_dump()

        app_info = AndroidAppInfo(
            name=manifest_dict["application"]["label"] or "Unknown",
            version=manifest_dict["version_name"] or "Unknown",
            build=manifest_dict["version_code"] or "Unknown",
            package_name=manifest_dict["package_name"],
        )

        apks: list[APK] = []
        # Split AAB into APKs, or use the APK directly
        if isinstance(artifact, AAB):
            apks = artifact.get_primary_apks()
        elif isinstance(artifact, ZippedAAB):
            apks = artifact.get_primary_apks()
        elif isinstance(artifact, ZippedAPK):
            apks.append(artifact.get_primary_apk())
        elif isinstance(artifact, APK):
            apks.append(artifact)
        else:
            raise ValueError(f"Unsupported artifact type: {type(artifact)}")

        logger.debug("Found %d APKs", len(apks))

        # TODO: Implement treemap generation from APKs

        return AndroidAnalysisResults(
            app_info=app_info,
            file_analysis=FileAnalysis(files=[]),
            analysis_duration=0,
        )
