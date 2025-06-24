import plistlib

from pathlib import Path
from typing import Any

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
