from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from launchpad.artifacts.android.aab import AAB
from launchpad.artifacts.android.apk import APK
from launchpad.artifacts.android.zipped_aab import ZippedAAB
from launchpad.artifacts.android.zipped_apk import ZippedAPK
from launchpad.artifacts.artifact import AndroidArtifact
from launchpad.parsers.android.dex.types import ClassDefinition
from launchpad.size.hermes.reporter import HermesReport
from launchpad.size.hermes.utils import make_hermes_reports
from launchpad.size.insights.android.image_optimization import WebPOptimizationInsight
from launchpad.size.insights.common import (
    DuplicateFilesInsight,
    LargeAudioFileInsight,
    LargeImageFileInsight,
    LargeVideoFileInsight,
)
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.android import (
    AndroidAnalysisResults,
    AndroidAppInfo,
    AndroidInsightResults,
)
from launchpad.size.models.common import FileAnalysis, FileInfo
from launchpad.size.models.treemap import FILE_TYPE_TO_TREEMAP_TYPE, TreemapType
from launchpad.size.treemap.treemap_builder import TreemapBuilder
from launchpad.utils.file_utils import calculate_file_hash
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

FILE_NAME_TO_TREEMAP_TYPE: dict[str, TreemapType] = {
    "AndroidManifest.xml": TreemapType.MANIFESTS,
}


class AndroidAnalyzer:
    """Analyzer for Android apps (.apk, .aab files)."""

    def __init__(
        self,
        skip_insights: bool = False,
        **kwargs,
    ) -> None:
        """Args:
        skip_insights: Skip insights generation for faster analysis
        """
        self.skip_insights = skip_insights

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

        file_analysis = self._get_file_analysis(apks)
        class_definitions = self._get_class_definitions(apks)
        hermes_reports = self._get_hermes_reports(apks)
        treemap_builder = TreemapBuilder(
            app_name=app_info.name,
            platform="android",
            # TODO: (Ryan) This is a placeholder, we need to get the actual download compression ratio
            download_compression_ratio=1.0,
            class_definitions=class_definitions,
            hermes_reports=hermes_reports,
        )

        treemap = treemap_builder.build_file_treemap(file_analysis)

        insights: AndroidInsightResults | None = None
        if not self.skip_insights:
            logger.info("Generating insights from analysis results")
            insights_input = InsightsInput(
                app_info=app_info,
                file_analysis=file_analysis,
                treemap=treemap,
                binary_analysis=[],
                image_map=self._get_images(apks, file_analysis),
            )
            insights = AndroidInsightResults(
                duplicate_files=DuplicateFilesInsight().generate(insights_input),
                webp_optimization=WebPOptimizationInsight().generate(insights_input),
                large_images=LargeImageFileInsight().generate(insights_input),
                large_videos=LargeVideoFileInsight().generate(insights_input),
                large_audio=LargeAudioFileInsight().generate(insights_input),
            )

        return AndroidAnalysisResults(
            generated_at=datetime.now(timezone.utc),
            app_info=app_info,
            treemap=treemap,
            file_analysis=file_analysis,
            insights=insights,
            analysis_duration=None,
        )

    def _get_file_analysis(self, apks: list[APK]) -> FileAnalysis:
        file_infos: list[FileInfo] = []
        total_size = 0
        path_to_file_info: dict[str, FileInfo] = {}

        for apk in apks:
            extract_path = apk.get_extract_path()
            for file_path in extract_path.rglob("*"):
                if file_path.is_file():
                    logger.debug("Processing file: %s", file_path)
                    relative_path = str(file_path.relative_to(extract_path))

                    # Get file extension or use 'unknown' if none
                    file_type = file_path.suffix.lstrip(".").lower() or "unknown"

                    # Some files have special overrides for the treemap type
                    if file_path.name in FILE_NAME_TO_TREEMAP_TYPE:
                        treemap_type = FILE_NAME_TO_TREEMAP_TYPE[file_path.name]
                    else:
                        treemap_type = FILE_TYPE_TO_TREEMAP_TYPE.get(file_type, TreemapType.OTHER)
                    file_size = file_path.stat().st_size
                    total_size += file_size

                    # Special handling for DEX files - merge all dex files into one representation
                    # This is intentional as there could be multiple DEX files in an APK
                    # and we want to group them by package/classes vs by file
                    if file_type == "dex":
                        if "classes.dex" not in path_to_file_info:
                            # First DEX file - create the merged representation
                            file_hash = calculate_file_hash(file_path, algorithm="md5")
                            merged_dex_info = FileInfo(
                                path="classes.dex",
                                size=file_size,
                                file_type=file_type,
                                treemap_type=treemap_type,
                                hash_md5=file_hash,
                            )
                            path_to_file_info["classes.dex"] = merged_dex_info
                            logger.debug("Created merged DEX representation: %s", relative_path)
                        else:
                            # Additional DEX file - merge into existing representation
                            existing_info = path_to_file_info["classes.dex"]
                            merged_size = existing_info.size + file_size
                            logger.debug(
                                "Merging DEX file %s into classes.dex",
                                relative_path,
                            )

                            # Update the merged DEX file info
                            merged_dex_info = FileInfo(
                                path="classes.dex",
                                size=merged_size,
                                file_type=file_type,
                                treemap_type=treemap_type,
                                # Intentionally ignoring hash of merged file
                                hash_md5="",
                            )
                            path_to_file_info["classes.dex"] = merged_dex_info
                        continue

                    # If we've seen this path before, merge the sizes to simplify the treemap
                    # This is intentional as things like the AndroidManifest.xml are duplicated
                    # across APKs, but to users that's not relevant so we'll group.
                    if relative_path in path_to_file_info:
                        existing_info = path_to_file_info[relative_path]
                        merged_size = existing_info.size + file_size
                        logger.debug(
                            "Merging duplicate path %s: %d + %d = %d",
                            relative_path,
                            existing_info.size,
                            file_size,
                            merged_size,
                        )

                        # Create new FileInfo with merged size
                        merged_file_info = FileInfo(
                            path=relative_path,
                            size=merged_size,
                            file_type=file_type,
                            treemap_type=treemap_type,
                            # Intentionally ignoring hash of merged file
                            hash_md5="",
                        )
                        path_to_file_info[relative_path] = merged_file_info
                    else:
                        file_hash = calculate_file_hash(file_path, algorithm="md5")
                        # First time seeing this path
                        file_info = FileInfo(
                            path=relative_path,
                            size=file_size,
                            file_type=file_type,
                            treemap_type=treemap_type,
                            hash_md5=file_hash,
                        )
                        path_to_file_info[relative_path] = file_info

        # Convert dictionary values to list
        file_infos = list(path_to_file_info.values())

        # Group files by type
        files_by_type: dict[str, list[FileInfo]] = {}
        for file_info in file_infos:
            if file_info.file_type not in files_by_type:
                files_by_type[file_info.file_type] = []
            files_by_type[file_info.file_type].append(file_info)

        return FileAnalysis(
            files=file_infos,
        )

    def _get_class_definitions(self, apks: list[APK]) -> list[ClassDefinition]:
        class_definitions: list[ClassDefinition] = []
        for apk in apks:
            class_definitions.extend(apk.get_class_definitions())
        return class_definitions

    def _get_hermes_reports(self, apks: list[APK]) -> dict[str, HermesReport]:
        """Get Hermes reports from all APKs and combine them."""
        all_reports: dict[str, HermesReport] = {}
        for apk in apks:
            extract_path = apk.get_extract_path()
            apk_reports = make_hermes_reports(extract_path)
            for relative_path, report in apk_reports.items():
                if relative_path in all_reports:
                    logger.warning(f"Duplicate Hermes report key found: {relative_path}, overwriting")
                all_reports[relative_path] = report
        return all_reports

    def _get_images(self, apks: list[APK], file_analysis: FileAnalysis) -> dict[Path, FileInfo]:
        image_map = {}
        for apk in apks:
            for image_file in apk.get_images():
                image_map[image_file] = next(
                    (file_info for file_info in file_analysis.files if str(image_file).endswith(file_info.path)), None
                )
                if image_map[image_file] is None:
                    logger.warning(f"Image file {image_file} not found in file analysis")
        return image_map
