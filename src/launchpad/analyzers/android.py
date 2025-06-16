from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipInfo

from launchpad.utils.treemap_builder import TreemapBuilder

from ..artifacts import AAB, APK, AndroidArtifact, ZippedAAB, ZippedAPK
from ..models.android import AndroidAnalysisResults, AndroidAppInfo
from ..models.common import FileAnalysis, FileInfo
from ..models.treemap import TreemapType
from ..utils.logging import get_logger

logger = get_logger(__name__)

FILE_NAME_TO_TREEMAP_TYPE: dict[str, TreemapType] = {
    "AndroidManifest.xml": TreemapType.MANIFESTS,
}


class AndroidAnalyzer:
    """Analyzer for Android apps (.apk, .aab files)."""

    def analyze(self, artifact: AndroidArtifact) -> AndroidAnalysisResults:
        manifest_dict = artifact.get_manifest().model_dump()
        start_time = time.time()

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
        treemap_builder = TreemapBuilder(
            app_name=app_info.name,
            platform="android",
            download_compression_ratio=0.0,
            filesystem_block_size=4 * 1024,
        )

        treemap_results = treemap_builder.build_file_treemap(file_analysis)

        analysis_duration = time.time() - start_time
        return AndroidAnalysisResults(
            generated_at=datetime.now(timezone.utc),
            analysis_duration=analysis_duration,
            app_info=app_info,
            treemap_results=treemap_results,
            file_analysis=file_analysis,
        )

    def _get_file_analysis(self, apks: list[APK]) -> FileAnalysis:
        file_infos: list[ZipInfo] = []
        for apk in apks:
            file_infos.extend(apk.get_file_infos())

        # Group files by type
        files_by_type: dict[str, list[FileInfo]] = {}
        for zip_file_info in file_infos:
            logger.debug("Processing file: %s", zip_file_info.filename)
            # Get file extension or use 'unknown' if none
            file_type = Path(zip_file_info.filename).suffix.lstrip(".").lower() or "unknown"
            if file_type not in files_by_type:
                files_by_type[file_type] = []

            file_info = FileInfo(
                path=zip_file_info.filename,
                size=zip_file_info.file_size,
                file_type=file_type,
                hash_md5=None,  # TODO: Implement
            )
            files_by_type[file_type].append(file_info)

        return FileAnalysis(
            file_count=len(file_infos),
            files_by_type=files_by_type,
            # TODO: Implement
            total_size=0,
            duplicate_files=[],
            largest_files=[],
        )
