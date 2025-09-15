"""Context manager for handling zip files with temporary extraction."""

from pathlib import Path
from types import TracebackType
from zipfile import BadZipFile, ZipFile

from launchpad.artifacts.android.aab import AAB
from launchpad.artifacts.android.apk import APK
from launchpad.artifacts.android.zipped_aab import ZippedAAB
from launchpad.artifacts.android.zipped_apk import ZippedAPK
from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact import Artifact
from launchpad.artifacts.providers.zip_provider import ZipProvider
from launchpad.utils.file_utils import cleanup_directory
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class ArtifactContext:
    """Context manager that extracts zip files and returns the appropriate Artifact instance.

    This context manager handles:
    - Opening and extracting zip files
    - Detecting the artifact type from zip contents
    - Creating the appropriate artifact instance
    - Automatic cleanup of temporary directories
    """

    def __init__(self, path: Path) -> None:
        """Initialize the context manager.

        Args:
            path: Path to the zip file
        """
        self.path = path
        self._zip_file: ZipFile | None = None
        self._zip_provider: ZipProvider | None = None
        self._extract_dir: Path | None = None

    def __enter__(self) -> Artifact:
        """Enter the context and return the appropriate artifact instance.

        Returns:
            Appropriate Artifact instance

        Raises:
            ValueError: If file is not a valid artifact
        """

        if not is_zip_file(self.path):
            raise ValueError("Artifact is not a zip file")

        try:
            self._zip_file = ZipFile(self.path)
            self._zip_provider = ZipProvider(self.path)
            self._extract_dir = self._zip_provider.extract_to_temp_directory()

            return self._create_artifact()
        except BadZipFile as e:
            logger.error(f"ZIP file is corrupted: {e}")
            raise ValueError(f"Corrupted ZIP file: {e}")
        except Exception as e:
            logger.error(f"Unexpected error reading ZIP: {e}")
            raise ValueError(f"Error reading ZIP file: {e}")

    def _create_artifact(self) -> Artifact:
        """Create the appropriate artifact based on zip contents.

        Returns:
            Appropriate Artifact instance

        Raises:
            ValueError: If file is not a valid artifact
        """
        if self._zip_file is None or self._extract_dir is None:
            raise ValueError("Context not properly initialized")

        # Check if zip contains a Info.plist in the root of the .xcarchive folder (ZippedXCArchive)
        plist_files = [f for f in self._zip_file.namelist() if f.endswith(".xcarchive/Info.plist")]
        if plist_files:
            return ZippedXCArchive(self.path, self._extract_dir)

        apk_files = [f for f in self._zip_file.namelist() if f.endswith(".apk")]
        if len(apk_files) == 1:
            return ZippedAPK(self.path, self._extract_dir)

        aab_files = [f for f in self._zip_file.namelist() if f.endswith(".aab")]
        if len(aab_files) == 1:
            return ZippedAAB(self.path, self._extract_dir)

        # Check if zip contains base/manifest/AndroidManifest.xml (AAB)
        manifest_files = [f for f in self._zip_file.namelist() if f.endswith("base/manifest/AndroidManifest.xml")]
        if manifest_files:
            return AAB(self.path, self._extract_dir)

        # Check if zip contains AndroidManifest.xml (APK)
        manifest_files = [f for f in self._zip_file.namelist() if f.endswith("AndroidManifest.xml")]
        if manifest_files:
            return APK(self.path, self._extract_dir)

        # Check if it's a direct APK or AAB by looking for AndroidManifest.xml in specific locations - only really used for testing
        try:
            with ZipFile(self.path) as zip_file:
                if any(f.endswith("base/manifest/AndroidManifest.xml") for f in zip_file.namelist()):
                    return AAB(self.path, self._extract_dir)

                if any(f.endswith("AndroidManifest.xml") for f in zip_file.namelist()):
                    return APK(self.path, self._extract_dir)
        except Exception:
            pass

        raise ValueError("Input is not a supported artifact")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the context and clean up resources.

        Args:
            exc_type: Exception type if an exception occurred
            exc_val: Exception value if an exception occurred
            exc_tb: Traceback if an exception occurred
        """
        # Close zip file
        if self._zip_file is not None:
            self._zip_file.close()

        if self._extract_dir is not None and self._extract_dir.exists():
            cleanup_directory(self._extract_dir)


def is_zip_file(path: Path) -> bool:
    if not path.is_file():
        return False

    with open(path, "rb") as f:
        magic_bytes = f.read(4)
    return magic_bytes.startswith(b"PK\x03\x04")
