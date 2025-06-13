from typing import Optional

from ..artifact import AndroidArtifact
from ..providers.zip_provider import ZipProvider
from .aab import AAB
from .manifest.manifest import AndroidManifest


class ZippedAAB(AndroidArtifact):
    def __init__(self, content: bytes) -> None:
        super().__init__(content)
        self._zip_provider = ZipProvider(content)
        self._extract_dir = self._zip_provider.extract_to_temp_directory()
        self._aab: Optional[AAB] = None

    def get_manifest(self) -> AndroidManifest:
        return self.get_aab().get_manifest()

    def get_aab(self) -> AAB:
        if self._aab is not None:
            return self._aab

        for path in self._extract_dir.rglob("*.aab"):
            if path.is_file():
                self._aab = AAB(path.read_bytes())
                return self._aab

        raise FileNotFoundError(f"No AAB found in {self._extract_dir}")
