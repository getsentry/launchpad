from pathlib import Path

from .artifact import Artifact


class ELFArtifact(Artifact):
    def __init__(self, path: Path) -> None:
        super().__init__(path)

    def get_app_icon(self) -> bytes | None:
        return None
