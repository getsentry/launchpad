from pathlib import Path

from ..artifact import AndroidArtifact
from .apk import APK
from .manifest.manifest import AndroidManifest


class ZippedAPK(AndroidArtifact):
    def __init__(self, path: Path, extract_dir: Path) -> None:
        super().__init__(path)
        self.path = path
        self._extract_dir = extract_dir
        self._primary_apk: APK | None = None

    def get_manifest(self) -> AndroidManifest:
        return self.get_primary_apk().get_manifest()

    def get_primary_apk(self) -> APK:
        if self._primary_apk is not None:
            return self._primary_apk

        for path in self._extract_dir.rglob("*.apk"):
            if path.is_file():
                # Create a temporary extraction for the nested APK
                from ..providers.zip_provider import ZipProvider

                zip_provider = ZipProvider(path)
                apk_extract_dir = zip_provider.extract_to_temp_directory()
                self._primary_apk = APK(path, apk_extract_dir)
                return self._primary_apk

        raise FileNotFoundError(f"No primary APK found in {self._extract_dir}")
