import os
import plistlib
import shutil
import subprocess
import tempfile

from pathlib import Path
from typing import Any, List

from launchpad.utils.logging import get_logger

from ..artifact import AppleArtifact
from ..providers.zip_provider import ZipProvider

logger = get_logger(__name__)


class ZippedXCArchive(AppleArtifact):
    """A zipped XCArchive file."""

    def __init__(self, path: Path, content: bytes) -> None:
        super().__init__(content)
        self._zip_provider = ZipProvider(path)
        self._extract_dir = self._zip_provider.extract_to_temp_directory()
        self._app_bundle_path: Path | None = None
        self._plist: dict[str, Any] | None = None
        self._provisioning_profile: dict[str, Any] | None = None

    def get_plist(self) -> dict[str, Any]:
        """Get the Info.plist contents."""
        if self._plist is not None:
            return self._plist

        app_bundle_path = self.get_app_bundle_path()
        plist_path = app_bundle_path / "Info.plist"

        try:
            with open(plist_path, "rb") as f:
                plist_data = plistlib.load(f)

            self._plist = plist_data
            return self._plist
        except Exception as e:
            raise RuntimeError(f"Failed to parse Info.plist: {e}")

    def generate_ipa(self, output_path: Path):
        """Generate an IPA file

        An IPA file is a zip file containing a Payload directory, with the .app bundle inside.

        Args:
            output_path: Path where the IPA file should be saved

        Returns:
            Path to the generated IPA file

        Raises:
            RuntimeError: If IPA generation fails
        """

        logger.info("Generating IPA file from XCArchive")

        # Get the app bundle path
        app_bundle_path = self.get_app_bundle_path()

        # Create a temporary directory for Payload
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)
            payload_dir = temp_dir_path / "Payload"
            payload_dir.mkdir()
            dest_app_path = payload_dir / app_bundle_path.name

            # Copy the .app bundle into Payload (preserve symlinks, permissions, etc.)
            shutil.copytree(app_bundle_path, dest_app_path, symlinks=True)

            # Create the IPA file using zip to preserve symlinks and metadata
            try:
                subprocess.run(
                    ["zip", "-r", "-y", str(output_path), "Payload"],  # Recursive  # Store symlinks as symlinks
                    cwd=temp_dir_path,
                    check=True,
                )

                logger.info(f"IPA file generated successfully: {output_path}")
                return output_path
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Failed to generate IPA file with zip: {e}")
            except FileNotFoundError:
                raise RuntimeError("zip command not found. This tool is required for IPA generation.")

    def get_provisioning_profile(self) -> dict[str, Any] | None:
        if self._provisioning_profile is not None:
            return self._provisioning_profile

        app_bundle_path = self.get_app_bundle_path()
        mobileprovision_path = app_bundle_path / "embedded.mobileprovision"
        try:
            with open(mobileprovision_path, "rb") as f:
                content = f.read()

            content_str = content.decode("utf-8", errors="ignore")
            plist_start = content_str.find("<?xml")
            plist_end = content_str.find("</plist>")
            if plist_start == -1 or plist_end == -1:
                return None

            plist_str = content_str[plist_start : plist_end + 8]
            self._provisioning_profile = plistlib.loads(plist_str.encode("utf-8"))
            return self._provisioning_profile
        except FileNotFoundError:
            logger.debug(f"No embedded.mobileprovision found at {mobileprovision_path}")
            return None

    def get_binary_path(self) -> Path | None:
        app_bundle_path = self.get_app_bundle_path()
        plist = self.get_plist()
        executable_name: str = plist.get("CFBundleExecutable", "")
        if not executable_name:
            return None

        return app_bundle_path / executable_name

    def get_app_bundle_path(self) -> Path:
        """Get the path to the .app bundle."""
        if self._app_bundle_path is not None:
            return self._app_bundle_path

        for path in self._extract_dir.rglob("*.app"):
            if path.is_dir() and "__MACOSX" not in str(path):
                logger.debug(f"Found Apple app bundle: {path}")
                return path

        raise FileNotFoundError(f"No .app bundle found in {self._extract_dir}")

    def get_all_binary_paths(self) -> List[tuple[Path, str]]:
        """Find all binaries in the app bundle."""

        binaries: List[tuple[Path, str]] = []

        app_bundle_path = self.get_app_bundle_path()

        # Find main executable
        main_executable = self.get_plist().get("CFBundleExecutable")
        if main_executable is None:
            raise RuntimeError("CFBundleExecutable not found in Info.plist")
        main_binary_path = Path(os.path.join(str(app_bundle_path), main_executable))
        binaries.append((main_binary_path, main_executable))  # Don't skip Swift metadata for main binary

        # Find framework binaries
        for framework_path in app_bundle_path.rglob("*.framework"):
            if framework_path.is_dir():
                framework_name = framework_path.stem
                framework_binary_path = framework_path / framework_name
                binaries.append((framework_binary_path, framework_name))  # Skip Swift metadata for frameworks

        # Find app extension binaries
        for extension_path in app_bundle_path.rglob("*.appex"):
            if extension_path.is_dir():
                extension_plist_path = extension_path / "Info.plist"
                if extension_plist_path.exists():
                    try:
                        import plistlib

                        with open(extension_plist_path, "rb") as f:
                            extension_plist = plistlib.load(f)
                        extension_executable = extension_plist.get("CFBundleExecutable")
                        if extension_executable:
                            extension_binary_path = extension_path / extension_executable
                            # Use the full extension name as the key to avoid conflicts
                            extension_name = f"{extension_path.stem}/{extension_executable}"
                            binaries.append(
                                (extension_binary_path, extension_name)
                            )  # Skip Swift metadata for extensions
                    except Exception as e:
                        logger.warning(f"Failed to read extension Info.plist at {extension_path}: {e}")

        return binaries
