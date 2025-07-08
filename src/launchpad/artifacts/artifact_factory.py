from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from .android.aab import AAB
from .android.apk import APK
from .android.zipped_aab import ZippedAAB
from .android.zipped_apk import ZippedAPK
from .apple.zipped_xcarchive import ZippedXCArchive
from .artifact import Artifact


class ArtifactFactory:
    """Factory for creating artifacts from paths."""

    @staticmethod
    def from_path(path: Path) -> Artifact:
        """Create appropriate Artifact from file path.

        Args:
            path: Path to the artifact file

        Returns:
            Appropriate Artifact instance

        Raises:
            FileNotFoundError: If path does not exist
            ValueError: If file is not a valid artifact
        """
        if not path.is_file():
            raise FileNotFoundError(f"Path is not a file: {path}")

        content = path.read_bytes()

        # Check if it's a zip file by looking at magic bytes
        if content.startswith(b"PK\x03\x04"):
            try:
                with ZipFile(BytesIO(content)) as zip_file:
                    filenames = zip_file.namelist()

                    # Check for XCArchive (iOS)
                    if ArtifactFactory._is_xcarchive(filenames):
                        return ZippedXCArchive(path)

                    # Check for single APK or AAB files (zipped artifacts)
                    apk_files = [f for f in filenames if f.endswith(".apk")]
                    if len(apk_files) == 1:
                        return ZippedAPK(path)

                    aab_files = [f for f in filenames if f.endswith(".aab")]
                    if len(aab_files) == 1:
                        return ZippedAAB(path)

                    # Check for AAB (base/manifest structure)
                    if any(
                        f.endswith("base/manifest/AndroidManifest.xml")
                        for f in filenames
                    ):
                        return AAB(path)

                    # Check for APK (AndroidManifest.xml)
                    if any(f.endswith("AndroidManifest.xml") for f in filenames):
                        return APK(path)

            except Exception:
                pass

        # Fallback: try direct APK/AAB detection regardless of magic bytes
        try:
            with ZipFile(BytesIO(content)) as zip_file:
                filenames = zip_file.namelist()

                if any(
                    f.endswith("base/manifest/AndroidManifest.xml") for f in filenames
                ):
                    return AAB(path)

                if any(f.endswith("AndroidManifest.xml") for f in filenames):
                    return APK(path)
        except Exception:
            pass

        raise ValueError("Input is not a supported artifact")

    @staticmethod
    def _is_xcarchive(filenames: list[str]) -> bool:
        """Check if filenames indicate an XCArchive structure."""
        # Method 1: .xcarchive/Info.plist pattern
        if any(f.endswith(".xcarchive/Info.plist") for f in filenames):
            return True

        # Method 2: Root Info.plist + Products/Applications structure
        has_root_info_plist = "Info.plist" in filenames
        has_products_apps = any(
            f.startswith("Products/Applications/") for f in filenames
        )

        return has_root_info_plist and has_products_apps
