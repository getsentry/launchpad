from __future__ import annotations

from launchpad.models.common import FileAnalysis

from ..artifacts import AndroidArtifact
from ..models.android import AndroidAnalysisResults, AndroidAppInfo


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

        return AndroidAnalysisResults(
            app_info=app_info,
            file_analysis=FileAnalysis(
                total_size=0,
                file_count=0,
                files_by_type={},
                duplicate_files=[],
                largest_files=[],
            ),
            analysis_duration=0,
        )
