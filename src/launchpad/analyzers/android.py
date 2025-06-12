from __future__ import annotations

from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from ..artifacts import APK, AndroidArtifact, ZippedAPK
from ..models.android import AndroidAnalysisResults, AndroidAppInfo


class AndroidAnalyzer:
    """Analyzer for Android apps (.apk, .aab files)."""

    def __init__(self, path: Path) -> None:
        self.artifact = self._artifact_from_path(path)

    def analyze(self) -> AndroidAnalysisResults:
        manifest_dict = self.artifact.get_manifest().model_dump()

        app_info = AndroidAppInfo(
            name=manifest_dict["application"]["label"] or "Unknown",
            version=manifest_dict["version_name"] or "Unknown",
            build=manifest_dict["version_code"] or "Unknown",
            package_name=manifest_dict["package_name"],
        )

        return AndroidAnalysisResults(
            app_info=app_info,
        )

    def _artifact_from_path(self, path: Path) -> AndroidArtifact:
        """Create appropriate AndroidArtifact from file path.

        Args:
            path: Path to the Android artifact file

        Returns:
            Appropriate AndroidArtifact instance

        Raises:
            FileNotFoundError: If path does not exist
            ValueError: If file is not a valid Android artifact
        """
        if not path.is_file():
            raise FileNotFoundError(f"Path is not a file: {path}")

        content = path.read_bytes()

        # Check if it's a zip file by looking at magic bytes
        if content.startswith(b"PK\x03\x04"):
            # Check if zip contains a single APK (ZippedAPK)
            with ZipFile(BytesIO(content)) as zip_file:
                apk_files = [f for f in zip_file.namelist() if f.endswith(".apk")]
                if len(apk_files) == 1:
                    return ZippedAPK(content)

                # Check if zip contains AndroidManifest.xml (APK)
                manifest_files = [f for f in zip_file.namelist() if f.endswith("AndroidManifest.xml")]
                if manifest_files:
                    return APK(content)

        # Check if it's a direct APK by looking for AndroidManifest.xml (APK)
        try:
            with ZipFile(BytesIO(content)) as zip_file:
                if any(f.endswith("AndroidManifest.xml") for f in zip_file.namelist()):
                    return APK(content)
        except Exception:
            pass

        raise ValueError(f"File is not a supported Android artifact: {path}")
