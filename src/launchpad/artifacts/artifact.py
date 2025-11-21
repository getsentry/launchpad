from pathlib import Path
from typing import Any, Callable

import lief

from launchpad.parsers.android.dex.dex_mapping import DexMapping

from .android.manifest.manifest import AndroidManifest
from .android.resources.resource_table import ResourceTable


class Artifact:
    """Base class for all artifacts that can be analyzed."""

    def __init__(self, path: Path, cleanup: None | Callable[[], None] = None) -> None:
        self.path = path
        self.cleanup = cleanup

    def __del__(self):
        # __del__ can be called prior to __init__ finishing
        # if e.g. __init__ throws an exception so we have to be very
        # careful what we rely on:
        cleanup = getattr(self, "cleanup", None)
        if cleanup:
            cleanup()

    def get_app_icon(self) -> bytes | None:
        """Get the app icon from the artifact."""
        raise NotImplementedError("Not implemented")


class AndroidArtifact(Artifact):
    """Protocol defining the interface for Android artifacts."""

    def get_manifest(self) -> AndroidManifest:
        """Get the Android manifest information."""
        raise NotImplementedError("Not implemented")

    def get_resource_tables(self) -> list[ResourceTable]:
        """Get the resource tables from the artifact."""
        raise NotImplementedError("Not implemented")

    def get_dex_mapping(self) -> DexMapping | None:
        """Get the Dex mapping from the artifact."""
        raise NotImplementedError("Not implemented")


class AppleArtifact(Artifact):
    """Protocol defining the interface for Apple artifacts."""

    def get_plist(self) -> dict[str, Any]:
        """Get the plist from the artifact."""
        raise NotImplementedError("Not implemented")

    def get_lief_cache(self) -> dict[Path, lief.MachO.FatBinary]:
        """Get the LIEF cache of pre-parsed binaries"""
        return {}

    def generate_ipa(self, output_path: Path):
        raise NotImplementedError("Not implemented")
