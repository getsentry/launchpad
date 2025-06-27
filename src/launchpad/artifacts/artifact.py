from pathlib import Path
from typing import Any

from .android.manifest.manifest import AndroidManifest
from .android.resources.resource_table import ResourceTable


class Artifact:
    """Base class for all artifacts that can be analyzed."""

    def __init__(self, path: Path) -> None:
        self.path = path


class AndroidArtifact(Artifact):
    """Protocol defining the interface for Android artifacts."""

    def get_manifest(self) -> AndroidManifest:
        """Get the Android manifest information."""
        raise NotImplementedError("Not implemented")

    def get_resource_tables(self) -> list[ResourceTable]:
        """Get the resource tables from the artifact."""
        raise NotImplementedError("Not implemented")


class AppleArtifact(Artifact):
    """Protocol defining the interface for Apple artifacts."""

    def get_plist(self) -> dict[str, Any]:
        """Get the plist from the artifact."""
        raise NotImplementedError("Not implemented")

    def generate_ipa(self, output_path: Path):
        raise NotImplementedError("Not implemented")
