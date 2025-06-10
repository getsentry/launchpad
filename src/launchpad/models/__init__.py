"""Data models for app size analysis results."""

# Import common models that are shared across platforms
# Import Android models (placeholders for now)
from .android import AndroidAnalysisResults, AndroidAppInfo, AndroidBinaryAnalysis, AndroidMetadata

# Import artifact models
from .artifacts import (
    AndroidSpecificArtifacts,
    ArtifactCollection,
    ArtifactType,
    AssetCatalog,
    BaseArtifact,
    BinaryArtifact,
    CompressionType,
    FrameworkArtifact,
    IOSSpecificArtifacts,
    LocalizationArtifact,
    MetadataArtifact,
    PlatformSpecificArtifacts,
    ResourceArtifact,
    ResourceType,
    SizeBreakdown,
)
from .common import (
    BaseAnalysisResults,
    BaseAppInfo,
    BaseBinaryAnalysis,
    DuplicateFileGroup,
    FileAnalysis,
    FileInfo,
    SymbolInfo,
)

# Import iOS-specific models
from .ios import (  # Backwards compatibility aliases
    AnalysisResults,
    AppInfo,
    BinaryAnalysis,
    IOSAnalysisResults,
    IOSAppInfo,
    IOSBinaryAnalysis,
    SwiftMetadata,
)

__all__ = [
    # Common models
    "FileInfo",
    "DuplicateFileGroup",
    "SymbolInfo",
    "FileAnalysis",
    "BaseAppInfo",
    "BaseBinaryAnalysis",
    "BaseAnalysisResults",
    # Artifact models
    "ArtifactType",
    "CompressionType",
    "ResourceType",
    "BaseArtifact",
    "BinaryArtifact",
    "FrameworkArtifact",
    "ResourceArtifact",
    "LocalizationArtifact",
    "MetadataArtifact",
    "AssetCatalog",
    "ArtifactCollection",
    "SizeBreakdown",
    "PlatformSpecificArtifacts",
    "IOSSpecificArtifacts",
    "AndroidSpecificArtifacts",
    # iOS-specific models
    "SwiftMetadata",
    "IOSAppInfo",
    "IOSBinaryAnalysis",
    "IOSAnalysisResults",
    # Backwards compatibility aliases (to be deprecated)
    "AppInfo",
    "BinaryAnalysis",
    "AnalysisResults",
    # Android models (placeholder)
    "AndroidMetadata",
    "AndroidAppInfo",
    "AndroidBinaryAnalysis",
    "AndroidAnalysisResults",
]
