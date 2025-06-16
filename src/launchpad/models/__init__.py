"""Data models for app size analysis results."""

# Import common models that are shared across platforms
# Import Android models (placeholders for now)
from .android import AndroidAnalysisResults, AndroidAppInfo
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
    IOSAnalysisResults,
    IOSAppInfo,
    IOSBinaryAnalysis,
    SwiftMetadata,
)
from .range_mapping import BinaryTag, Range, RangeConflict, RangeMap
from .treemap import TreemapElement, TreemapResults, TreemapType

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
    # Android models
    "AndroidAppInfo",
    "AndroidAnalysisResults",
    # Range mapping models
    "BinaryTag",
    "Range",
    "RangeConflict",
    "RangeMap",
    # Treemap models
    "TreemapType",
    "TreemapElement",
    "TreemapResults",
]
