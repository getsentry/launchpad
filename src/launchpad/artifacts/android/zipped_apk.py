from pathlib import Path

from ..artifact import AndroidArtifact
from ..providers.zip_provider import ZipProvider
from .apk import APK
from .manifest.manifest import AndroidManifest


class ZippedAPK(AndroidArtifact):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.path = path
        self._zip_provider = ZipProvider(path)
        self._extract_dir: Path | None = None  # Lazy extraction
        self._primary_apk: APK | None = None

    def _ensure_extracted(self) -> Path:
        """Ensure the archive is extracted and return the extraction directory."""
        if self._extract_dir is None:
            self._extract_dir = self._zip_provider.extract_to_temp_directory()
        return self._extract_dir

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with automatic cleanup."""
        self._zip_provider.cleanup()
        self._extract_dir = None
        return False  # Don't suppress exceptions

    def get_manifest(self) -> AndroidManifest:
        return self.get_primary_apk().get_manifest()

    def get_primary_apk(self) -> APK:
        if self._primary_apk is not None:
            return self._primary_apk

        extract_dir = self._ensure_extracted()
        for path in extract_dir.rglob("*.apk"):
            if path.is_file():
                self._primary_apk = APK(path)
                return self._primary_apk

        raise FileNotFoundError(f"No primary APK found in {extract_dir}")
