"""Data models for app size analysis results."""

# Import common models that are shared across platforms
from .common import (
    FileInfo,
    DuplicateFileGroup,
    SymbolInfo,
    FileAnalysis,
    BaseAppInfo,
    BaseBinaryAnalysis,
    BaseAnalysisResults,
)

# Import iOS-specific models
from .ios import (
    SwiftMetadata,
    IOSAppInfo,
    IOSBinaryAnalysis,
    IOSAnalysisResults,
    # Backwards compatibility aliases
    AppInfo,
    BinaryAnalysis,
    AnalysisResults,
)

# Import Android models (placeholders for now)
from .android import (
    AndroidMetadata,
    AndroidAppInfo,
    AndroidBinaryAnalysis,
    AndroidAnalysisResults,
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
