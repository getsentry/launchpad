"""Data models for app size analysis results."""

# Import common models that are shared across platforms
# Import Android models (placeholders for now)
from .android import AndroidAnalysisResults, AndroidAppInfo

# Import Apple-specific models
from .apple import (  # Backwards compatibility aliases
    AppleAnalysisResults,
    AppleAppInfo,
    MachOBinaryAnalysis,
    SwiftMetadata,
)
from .common import BaseAnalysisResults, BaseAppInfo, BaseBinaryAnalysis, FileAnalysis, FileInfo, SymbolInfo
from .range_mapping import BinaryTag, Range, RangeConflict, RangeMap
from .treemap import TreemapElement, TreemapResults, TreemapType

__all__ = [
    # Common models
    "FileInfo",
    "SymbolInfo",
    "FileAnalysis",
    "BaseAppInfo",
    "BaseBinaryAnalysis",
    "BaseAnalysisResults",
    # Apple-specific models
    "SwiftMetadata",
    "AppleAppInfo",
    "MachOBinaryAnalysis",
    "AppleAnalysisResults",
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
