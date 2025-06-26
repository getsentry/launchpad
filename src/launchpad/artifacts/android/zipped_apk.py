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
        self._extract_dir = self._zip_provider.extract_to_temp_directory()
        self._primary_apk: APK | None = None

    def get_manifest(self) -> AndroidManifest:
        return self.get_primary_apk().get_manifest()

    def get_primary_apk(self) -> APK:
        if self._primary_apk is not None:
            return self._primary_apk

        for path in self._extract_dir.rglob("*.apk"):
            if path.is_file():
                self._primary_apk = APK(path, path.read_bytes())
                return self._primary_apk

        raise FileNotFoundError(f"No primary APK found in {self._extract_dir}")
