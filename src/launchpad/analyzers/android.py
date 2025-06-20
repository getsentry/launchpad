from __future__ import annotations

import time
from datetime import datetime, timezone

from ..artifacts.android.aab import AAB
from ..artifacts.android.apk import APK
from ..artifacts.android.zipped_aab import ZippedAAB
from ..artifacts.android.zipped_apk import ZippedAPK
from ..artifacts.artifact import AndroidArtifact
from ..models.android import AndroidAnalysisResults, AndroidAppInfo
from ..models.common import FileAnalysis, FileInfo
from ..models.treemap import FILE_TYPE_TO_TREEMAP_TYPE, TreemapType
from ..utils.file_utils import calculate_file_hash
from ..utils.logging import get_logger
from ..utils.treemap.treemap_builder import TreemapBuilder

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
            # TODO: (Ryan) This is a placeholder, we need to get the actual download compression ratio
            download_compression_ratio=1.0,
        )

        treemap = treemap_builder.build_file_treemap(file_analysis)

        analysis_duration = time.time() - start_time
        return AndroidAnalysisResults(
            generated_at=datetime.now(timezone.utc),
            analysis_duration=analysis_duration,
            app_info=app_info,
            treemap=treemap,
            file_analysis=file_analysis,
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
                    # Get file extension or use 'unknown' if none
                    file_type = file_path.suffix.lstrip(".").lower() or "unknown"

                    # Some files have special overrides for the treemap type
                    if file_path.name in FILE_NAME_TO_TREEMAP_TYPE:
                        treemap_type = FILE_NAME_TO_TREEMAP_TYPE[file_path.name]
                    else:
                        treemap_type = FILE_TYPE_TO_TREEMAP_TYPE.get(file_type, TreemapType.OTHER)

                    # Get relative path from extract directory
                    relative_path = str(file_path.relative_to(extract_path))
                    file_size = file_path.stat().st_size
                    total_size += file_size

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
                            # Intentionally igoring hash of merged file
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
