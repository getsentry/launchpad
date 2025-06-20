from io import BytesIO
from pathlib import Path
from typing import BinaryIO
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
        return ArtifactFactory.from_bytes(content)

    @staticmethod
    def from_file(file: BinaryIO) -> Artifact:
        """Create appropriate Artifact from file.

        Args:
            file: The artifact file

        Returns:
            Appropriate Artifact instance

        Raises:
            ValueError: If file is not a valid artifact
        """
        content = file.read()
        return ArtifactFactory.from_bytes(content)

    @staticmethod
    def from_bytes(content: bytes) -> Artifact:
        """Create appropriate Artifact from file path.

        Args:
            content: bytes of the artifact

        Returns:
            Appropriate Artifact instance

        Raises:
            ValueError: If file is not a valid artifact
        """
        # Check if it's a zip file by looking at magic bytes
        if content.startswith(b"PK\x03\x04"):
            # Check if zip contains a single APK (ZippedAPK)
            with ZipFile(BytesIO(content)) as zip_file:
                # Check if zip contains a Info.plist in the root of the .xcarchive folder (ZippedXCArchive)
                plist_files = [f for f in zip_file.namelist() if f.endswith(".xcarchive/Info.plist")]
                if plist_files:
                    return ZippedXCArchive(content)

                apk_files = [f for f in zip_file.namelist() if f.endswith(".apk")]
                if len(apk_files) == 1:
                    return ZippedAPK(content)

                aab_files = [f for f in zip_file.namelist() if f.endswith(".aab")]
                if len(aab_files) == 1:
                    return ZippedAAB(content)

                # Check if zip contains base/manifest/AndroidManifest.xml (AAB)
                manifest_files = [f for f in zip_file.namelist() if f.endswith("base/manifest/AndroidManifest.xml")]
                if manifest_files:
                    return AAB(content)

                # Check if zip contains AndroidManifest.xml (APK)
                manifest_files = [f for f in zip_file.namelist() if f.endswith("AndroidManifest.xml")]
                if manifest_files:
                    return APK(content)

        # Check if it's a direct APK or AAB by looking for AndroidManifest.xml in specific locations
        try:
            with ZipFile(BytesIO(content)) as zip_file:
                if any(f.endswith("base/manifest/AndroidManifest.xml") for f in zip_file.namelist()):
                    return AAB(content)

                if any(f.endswith("AndroidManifest.xml") for f in zip_file.namelist()):
                    return APK(content)
        except Exception:
            pass

        raise ValueError("Input is not a supported artifact")
