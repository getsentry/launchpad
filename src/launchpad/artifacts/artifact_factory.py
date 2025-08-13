import logging

from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from .android.aab import AAB
from .android.apk import APK
from .android.zipped_aab import ZippedAAB
from .android.zipped_apk import ZippedAPK
from .apple.zipped_xcarchive import ZippedXCArchive
from .artifact import Artifact

logger = logging.getLogger(__name__)


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
                    # Check if zip contains a Info.plist in the root of the .xcarchive folder (ZippedXCArchive)
                    plist_files = [f for f in zip_file.namelist() if f.endswith(".xcarchive/Info.plist")]
                    if plist_files:
                        return ZippedXCArchive(path)

                    apk_files = [f for f in zip_file.namelist() if f.endswith(".apk")]
                    if len(apk_files) == 1:
                        return ZippedAPK(path)

                    aab_files = [f for f in zip_file.namelist() if f.endswith(".aab")]
                    if len(aab_files) == 1:
                        return ZippedAAB(path)

                    # Check if zip contains base/manifest/AndroidManifest.xml (AAB)
                    manifest_files = [f for f in zip_file.namelist() if f.endswith("base/manifest/AndroidManifest.xml")]
                    if manifest_files:
                        return AAB(path)

                    # Check if zip contains AndroidManifest.xml (APK)
                    manifest_files = [f for f in zip_file.namelist() if f.endswith("AndroidManifest.xml")]
                    if manifest_files:
                        return APK(path)

            except BadZipFile as e:
                logger.error(f"ZIP file is corrupted: {e}")
                raise ValueError(f"Corrupted ZIP file: {e}")
            except Exception as e:
                logger.error(f"Unexpected error reading ZIP: {e}")
                raise ValueError(f"Error reading ZIP file: {e}")

        # Check if it's a direct APK or AAB by looking for AndroidManifest.xml in specific locations
        try:
            with ZipFile(BytesIO(content)) as zip_file:
                if any(f.endswith("base/manifest/AndroidManifest.xml") for f in zip_file.namelist()):
                    return AAB(path)

                if any(f.endswith("AndroidManifest.xml") for f in zip_file.namelist()):
                    return APK(path)
        except Exception:
            pass

        raise ValueError("Input is not a supported artifact")
