"""Artifact models for app size analysis.

These models represent various artifact types found in mobile app bundles
and provide structured data for analysis results.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class ArtifactType(str, Enum):
    """Types of artifacts found in app bundles."""

    BINARY = "binary"
    LIBRARY = "library"
    FRAMEWORK = "framework"
    RESOURCE = "resource"
    ASSET = "asset"
    LOCALIZATION = "localization"
    METADATA = "metadata"
    SCRIPT = "script"
    CONFIG = "config"
    OTHER = "other"


class CompressionType(str, Enum):
    """Compression types for artifacts."""

    NONE = "none"
    GZIP = "gzip"
    ZLIB = "zlib"
    LZMA = "lzma"
    BROTLI = "brotli"
    ZSTD = "zstd"


class ResourceType(str, Enum):
    """Types of resources in app bundles."""

    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    FONT = "font"
    DATA = "data"
    NIFI = "nifi"
    STORYBOARD = "storyboard"
    XIB = "xib"
    PLIST = "plist"
    JSON = "json"
    XML = "xml"
    HTML = "html"
    CSS = "css"
    JAVASCRIPT = "javascript"
    OTHER = "other"


class BaseArtifact(BaseModel):
    """Base artifact information."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(..., description="Path relative to app bundle root")
    size: int = Field(..., ge=0, description="Size in bytes")
    compressed_size: Optional[int] = Field(None, ge=0, description="Compressed size in bytes")
    artifact_type: ArtifactType = Field(..., description="Type of artifact")
    hash_sha256: Optional[str] = Field(None, description="SHA256 hash of the artifact")
    compression: CompressionType = Field(CompressionType.NONE, description="Compression type")

    @property
    def compression_ratio(self) -> Optional[float]:
        """Calculate compression ratio if compressed size is available."""
        if self.compressed_size is not None and self.size > 0:
            return 1.0 - (self.compressed_size / self.size)
        return None


class BinaryArtifact(BaseArtifact):
    """Binary artifact (executable, library, etc.)."""

    model_config = ConfigDict(frozen=True)

    artifact_type: ArtifactType = Field(default=ArtifactType.BINARY)
    architectures: List[str] = Field(..., description="CPU architectures")
    is_encrypted: bool = Field(False, description="Whether the binary is encrypted")
    is_stripped: bool = Field(True, description="Whether debug symbols are stripped")
    linked_libraries: List[str] = Field(default_factory=list, description="Linked dynamic libraries")
    exported_symbols: int = Field(0, ge=0, description="Number of exported symbols")
    imported_symbols: int = Field(0, ge=0, description="Number of imported symbols")
    sections: Dict[str, int] = Field(default_factory=dict, description="Binary sections and sizes")


class FrameworkArtifact(BaseArtifact):
    """Framework artifact (iOS frameworks or Android libraries)."""

    model_config = ConfigDict(frozen=True)

    artifact_type: ArtifactType = Field(default=ArtifactType.FRAMEWORK)
    name: str = Field(..., description="Framework name")
    version: Optional[str] = Field(None, description="Framework version")
    is_dynamic: bool = Field(True, description="Whether it's a dynamic framework")
    is_system: bool = Field(False, description="Whether it's a system framework")
    bundle_id: Optional[str] = Field(None, description="Bundle identifier (iOS)")
    main_binary: Optional[BinaryArtifact] = Field(None, description="Main binary of the framework")
    resources: List[ResourceArtifact] = Field(default_factory=list, description="Framework resources")


class ResourceArtifact(BaseArtifact):
    """Resource artifact (images, data files, etc.)."""

    model_config = ConfigDict(frozen=True)

    artifact_type: ArtifactType = Field(default=ArtifactType.RESOURCE)
    resource_type: ResourceType = Field(..., description="Specific type of resource")
    dimensions: Optional[Dict[str, int]] = Field(None, description="Dimensions (for images/videos)")
    duration: Optional[float] = Field(None, description="Duration in seconds (for audio/video)")
    encoding: Optional[str] = Field(None, description="Encoding format")
    language: Optional[str] = Field(None, description="Language code (for localized resources)")


class LocalizationArtifact(BaseArtifact):
    """Localization artifact (.strings, .stringsdict files)."""

    model_config = ConfigDict(frozen=True)

    artifact_type: ArtifactType = Field(default=ArtifactType.LOCALIZATION)
    language: str = Field(..., description="Language code")
    region: Optional[str] = Field(None, description="Region code")
    string_count: int = Field(0, ge=0, description="Number of localized strings")
    resource_type: str = Field("strings", description="Type of localization resource")


class AssetCatalog(BaseModel):
    """Asset catalog information (iOS)."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Asset catalog name")
    path: str = Field(..., description="Path to asset catalog")
    total_size: int = Field(..., ge=0, description="Total size of all assets")
    asset_count: int = Field(..., ge=0, description="Number of assets")
    assets: List[ResourceArtifact] = Field(default_factory=list, description="Individual assets")
    
    @property
    def average_asset_size(self) -> float:
        """Calculate average asset size."""
        return self.total_size / self.asset_count if self.asset_count > 0 else 0.0


class MetadataArtifact(BaseArtifact):
    """Metadata artifact (plists, manifests, etc.)."""

    model_config = ConfigDict(frozen=True)

    artifact_type: ArtifactType = Field(default=ArtifactType.METADATA)
    format: str = Field(..., description="Metadata format (plist, json, xml, etc.)")
    purpose: str = Field(..., description="Purpose of the metadata file")
    parsed_content: Optional[Dict] = Field(None, description="Parsed content if available")


class ArtifactCollection(BaseModel):
    """Collection of artifacts grouped by type."""

    model_config = ConfigDict(frozen=True)

    binaries: List[BinaryArtifact] = Field(default_factory=list)
    frameworks: List[FrameworkArtifact] = Field(default_factory=list)
    resources: List[ResourceArtifact] = Field(default_factory=list)
    localizations: List[LocalizationArtifact] = Field(default_factory=list)
    metadata: List[MetadataArtifact] = Field(default_factory=list)
    other: List[BaseArtifact] = Field(default_factory=list)

    @property
    def total_count(self) -> int:
        """Total number of artifacts."""
        return (
            len(self.binaries)
            + len(self.frameworks)
            + len(self.resources)
            + len(self.localizations)
            + len(self.metadata)
            + len(self.other)
        )

    @property
    def total_size(self) -> int:
        """Total size of all artifacts."""
        total = 0
        for collection in [
            self.binaries,
            self.frameworks,
            self.resources,
            self.localizations,
            self.metadata,
            self.other,
        ]:
            total += sum(artifact.size for artifact in collection)
        return total

    def get_by_type(self, artifact_type: ArtifactType) -> List[BaseArtifact]:
        """Get all artifacts of a specific type."""
        type_map = {
            ArtifactType.BINARY: self.binaries,
            ArtifactType.FRAMEWORK: self.frameworks,
            ArtifactType.RESOURCE: self.resources,
            ArtifactType.LOCALIZATION: self.localizations,
            ArtifactType.METADATA: self.metadata,
        }
        return type_map.get(artifact_type, self.other)


class SizeBreakdown(BaseModel):
    """Size breakdown by category."""

    model_config = ConfigDict(frozen=True)

    category: str = Field(..., description="Category name")
    size: int = Field(..., ge=0, description="Size in bytes")
    percentage: float = Field(..., ge=0, le=100, description="Percentage of total")
    items: List[Union[BaseArtifact, "SizeBreakdown"]] = Field(
        default_factory=list, description="Items in this category"
    )
    
    @property
    def item_count(self) -> int:
        """Number of items in this category."""
        return len(self.items)


# Allow recursive reference in SizeBreakdown
SizeBreakdown.model_rebuild()


class PlatformSpecificArtifacts(BaseModel):
    """Platform-specific artifact collections."""

    model_config = ConfigDict(frozen=True)


class IOSSpecificArtifacts(PlatformSpecificArtifacts):
    """iOS-specific artifacts."""

    asset_catalogs: List[AssetCatalog] = Field(default_factory=list)
    storyboards: List[ResourceArtifact] = Field(default_factory=list)
    nibs: List[ResourceArtifact] = Field(default_factory=list)
    core_data_models: List[ResourceArtifact] = Field(default_factory=list)
    metal_libraries: List[BinaryArtifact] = Field(default_factory=list)
    swift_modules: List[BinaryArtifact] = Field(default_factory=list)


class AndroidSpecificArtifacts(PlatformSpecificArtifacts):
    """Android-specific artifacts."""

    dex_files: List[BinaryArtifact] = Field(default_factory=list)
    native_libraries: Dict[str, List[BinaryArtifact]] = Field(
        default_factory=dict, description="Native libraries by ABI"
    )
    resources_arsc: Optional[ResourceArtifact] = Field(None)
    manifest: Optional[MetadataArtifact] = Field(None)
    proguard_mappings: Optional[MetadataArtifact] = Field(None)
    kotlin_metadata: List[MetadataArtifact] = Field(default_factory=list)