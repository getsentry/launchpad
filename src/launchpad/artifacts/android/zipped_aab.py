from pathlib import Path

from ..artifact import AndroidArtifact
from ..providers.zip_provider import ZipProvider
from .aab import AAB
from .apk import APK
from .manifest.manifest import AndroidManifest


class ZippedAAB(AndroidArtifact):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._zip_provider = ZipProvider(path)
        self._extract_dir = self._zip_provider.extract_to_temp_directory()
        self._aab: AAB | None = None

    def get_manifest(self) -> AndroidManifest:
        return self.get_aab().get_manifest()

    def get_aab(self) -> AAB:
        if self._aab is not None:
            return self._aab

        for path in self._extract_dir.rglob("*.aab"):
            if path.is_file():
                self._aab = AAB(path, path.read_bytes())
                return self._aab

        raise FileNotFoundError(f"No AAB found in {self._extract_dir}")

    def get_primary_apks(self) -> list[APK]:
        return self.get_aab().get_primary_apks()
