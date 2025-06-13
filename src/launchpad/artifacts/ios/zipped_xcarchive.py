import logging
import plistlib
from pathlib import Path
from typing import Any, Optional

from ..artifact import IOSArtifact
from ..providers.zip_provider import ZipProvider

logger = logging.getLogger(__name__)


class ZippedXCArchive(IOSArtifact):
    """A zipped XCArchive file."""

    def __init__(self, content: bytes) -> None:
        super().__init__(content)
        self._zip_provider = ZipProvider(content)
        self._extract_dir = self._zip_provider.extract_to_temp_directory()
        self._app_bundle_path: Optional[Path] = None
        self._plist: Optional[dict[str, Any]] = None

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

    def get_app_bundle_path(self) -> Path:
        """Get the path to the .app bundle."""
        if self._app_bundle_path is not None:
            return self._app_bundle_path

        for path in self._extract_dir.rglob("*.app"):
            if path.is_dir():
                logger.debug(f"Found iOS app bundle: {path}")
                return path

        raise FileNotFoundError(f"No .app bundle found in {self._extract_dir}")
