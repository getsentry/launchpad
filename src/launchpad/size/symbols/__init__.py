"""Symbol categorization and aggregation for size analysis."""

from launchpad.size.symbols.cpp_aggregator import CppSymbolTypeAggregator
from launchpad.size.symbols.objc_aggregator import ObjCSymbolTypeAggregator
from launchpad.size.symbols.partitioner import SymbolInfo
from launchpad.size.symbols.swift_aggregator import SwiftSymbolTypeAggregator
from launchpad.size.symbols.types import CppSymbolTypeGroup, ObjCSymbolTypeGroup, SwiftSymbolTypeGroup

__all__ = [
    "SymbolInfo",
    "SwiftSymbolTypeAggregator",
    "SwiftSymbolTypeGroup",
    "ObjCSymbolTypeAggregator",
    "ObjCSymbolTypeGroup",
    "CppSymbolTypeAggregator",
    "CppSymbolTypeGroup",
]
