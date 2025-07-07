"""Range mapping system for tracking binary content categorization."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List

from pydantic import BaseModel, ConfigDict, Field
from sortedcontainers import SortedList  # type: ignore[import-untyped, unused-ignore]


class BinaryTag(Enum):
    """Enum for categorizing binary content types."""

    # String categories
    CFSTRINGS = "cfstrings"
    SWIFT_FILE_PATHS = "swift_file_paths"
    METHOD_SIGNATURES = "method_signatures"
    OBJC_TYPE_STRINGS = "objc_type_strings"
    C_STRINGS = "c_strings"

    # Header and metadata
    HEADERS = "headers"
    LOAD_COMMANDS = "load_commands"

    # Executable code
    TEXT_SEGMENT = "text_segment"
    FUNCTION_STARTS = "function_starts"
    EXTERNAL_METHODS = "external_methods"

    # Code signature
    CODE_SIGNATURE = "code_signature"

    # DYLD info categories
    DYLD = "dyld"  # Parent category for all DYLD-related ranges
    DYLD_REBASE = "dyld_rebase"
    DYLD_BIND = "dyld_bind"
    DYLD_LAZY_BIND = "dyld_lazy_bind"
    DYLD_EXPORTS = "dyld_exports"
    DYLD_FIXUPS = "dyld_fixups"
    DYLD_STRING_TABLE = "dyld_string_table"

    # Binary modules/classes
    OBJC_CLASSES = "objc_classes"
    SWIFT_METADATA = "swift_metadata"
    BINARY_MODULES = "binary_modules"

    # Data sections
    DATA_SEGMENT = "data_segment"
    CONST_DATA = "const_data"

    # Unwind and debug info
    UNWIND_INFO = "unwind_info"
    DEBUG_INFO = "debug_info"

    # Unmapped regions
    UNMAPPED = "unmapped"


@dataclass(frozen=True, order=True)
class Range:
    """Represents a range in the binary with its categorization.

    This class is ordered by start position for use in sorted containers.
    """

    start: int
    end: int  # exclusive
    tag: BinaryTag
    description: str | None = None

    def __post_init__(self) -> None:
        """Validate range invariants."""
        if self.start < 0:
            raise ValueError(f"Range start must be non-negative, got {self.start}")
        if self.end <= self.start:
            raise ValueError(f"Range end ({self.end}) must be greater than start ({self.start})")

    @property
    def size(self) -> int:
        """Size of the range in bytes."""
        return self.end - self.start

    def overlaps(self, other: Range) -> bool:
        """Check if this range overlaps with another range."""
        return self.start < other.end and other.start < self.end

    def contains(self, offset: int) -> bool:
        """Check if the range contains the given offset."""
        return self.start <= offset < self.end


class RangeConflict(BaseModel):
    """Represents a conflict between overlapping ranges."""

    model_config = ConfigDict(frozen=True)

    range1: Range
    range2: Range
    overlap_start: int = Field(..., ge=0)
    overlap_end: int = Field(..., ge=0)
    overlap_size: int = Field(..., ge=0)

    @classmethod
    def from_ranges(cls, range1: Range, range2: Range) -> RangeConflict | None:
        """Create a conflict from two overlapping ranges."""
        if not range1.overlaps(range2):
            return None

        overlap_start = max(range1.start, range2.start)
        overlap_end = min(range1.end, range2.end)
        overlap_size = overlap_end - overlap_start

        return cls(
            range1=range1,
            range2=range2,
            overlap_start=overlap_start,
            overlap_end=overlap_end,
            overlap_size=overlap_size,
        )


class RangeMap:
    """Efficient range mapping system for tracking binary content categorization.

    This class uses a sorted list for efficient operations and provides basic conflict detection.
    """

    def __init__(self, total_file_size: int = 0) -> None:
        """Initialize the range map with total file size."""
        self._ranges: SortedList[Range] = SortedList(key=lambda r: r.start)  # Sorted by start position
        self._conflicts: List[RangeConflict] = []
        self._total_file_size = total_file_size

    @property
    def ranges(self) -> List[Range]:
        """List of ranges in the map."""
        return list(self._ranges)

    @property
    def conflicts(self) -> List[RangeConflict]:
        """List of detected conflicts."""
        return self._conflicts.copy()

    @property
    def total_file_size(self) -> int:
        """Total size of the file being mapped."""
        return self._total_file_size

    @property
    def total_mapped(self) -> int:
        """Total bytes mapped to any category."""
        return sum(r.size for r in self._ranges)

    @property
    def unmapped_size(self) -> int:
        """Total bytes not mapped to any category."""
        return max(0, self._total_file_size - self.total_mapped)

    @property
    def total_conflict_size(self) -> int:
        """Total size of overlapping regions."""
        return sum(c.overlap_size for c in self._conflicts)

    def size_by_tag(self) -> Dict[BinaryTag, int]:
        """Get total size for each binary tag."""
        sizes: Dict[BinaryTag, int] = {}
        for range_item in self._ranges:
            sizes[range_item.tag] = sizes.get(range_item.tag, 0) + range_item.size
        return sizes

    def add_range(
        self,
        start: int,
        end: int,
        tag: BinaryTag,
        description: str | None = None,
    ) -> None:
        """Add a range to the map with basic conflict detection.

        Args:
            start: Start offset of the range
            end: End offset of the range (exclusive)
            tag: Binary tag for categorization
            description: Optional description of the range
        """
        if start < 0 or end <= start:
            raise ValueError(f"Invalid range: start={start}, end={end}")

        if end > self._total_file_size:
            raise ValueError(f"Range end ({end}) exceeds file size ({self._total_file_size})")

        new_range = Range(start, end, tag, description)

        # Fast path: if no ranges exist, just add it
        if not self._ranges:
            self._ranges.add(new_range)
            return

        # Find ranges that might overlap
        overlapping_ranges = self._find_overlapping_ranges(new_range)

        if not overlapping_ranges:
            # No conflicts, add directly
            self._ranges.add(new_range)
            return

        # Record conflicts but still add the range
        for existing_range in overlapping_ranges:
            conflict = RangeConflict.from_ranges(new_range, existing_range)
            if conflict:
                self._conflicts.append(conflict)

        # Add the range (simple behavior - no splitting)
        self._ranges.add(new_range)

    def get_unmapped_regions(self) -> List[Range]:
        """Get all unmapped regions in the file."""
        if not self._ranges:
            if self._total_file_size > 0:
                return [Range(0, self._total_file_size, BinaryTag.UNMAPPED, "entire_file")]
            return []

        unmapped_regions: List[Range] = []
        sorted_ranges = sorted(self._ranges, key=lambda r: r.start)

        # Check for gap before first range
        if sorted_ranges[0].start > 0:
            unmapped_regions.append(Range(0, sorted_ranges[0].start, BinaryTag.UNMAPPED, "before_first_range"))

        # Check for gaps between ranges
        for i in range(len(sorted_ranges) - 1):
            current_end = sorted_ranges[i].end
            next_start = sorted_ranges[i + 1].start

            if current_end < next_start:
                unmapped_regions.append(Range(current_end, next_start, BinaryTag.UNMAPPED, f"gap_{i}"))

        # Check for gap after last range
        last_end = sorted_ranges[-1].end
        if last_end < self._total_file_size:
            unmapped_regions.append(Range(last_end, self._total_file_size, BinaryTag.UNMAPPED, "after_last_range"))

        return unmapped_regions

    def get_coverage_report(self) -> Dict[str, int]:
        """Get a detailed coverage report."""
        unmapped_regions = self.get_unmapped_regions()
        return {
            "total_file_size": self._total_file_size,
            "total_mapped": self.total_mapped,
            "unmapped_size": self.unmapped_size,
            "coverage_percentage": int((self.total_mapped / max(1, self._total_file_size)) * 100),
            "conflict_count": len(self._conflicts),
            "total_conflict_size": self.total_conflict_size,
            "unmapped_region_count": len(unmapped_regions),
            "largest_unmapped_region": max((r.size for r in unmapped_regions), default=0),
        }

    def _find_overlapping_ranges(self, new_range: Range) -> List[Range]:
        """Find all existing ranges that overlap with the new range."""
        overlapping: List[Range] = []

        # Use bisect to find the insertion point for efficient searching
        start_idx = self._ranges.bisect_left(Range(new_range.start, new_range.start + 1, new_range.tag))

        # Search backwards from insertion point to find overlapping ranges
        for i in range(start_idx - 1, -1, -1):
            if self._ranges[i].end <= new_range.start:
                break
            if self._ranges[i].overlaps(new_range):
                overlapping.append(self._ranges[i])

        # Search forwards from insertion point
        for i in range(start_idx, len(self._ranges)):
            if self._ranges[i].start >= new_range.end:
                break
            if self._ranges[i].overlaps(new_range):
                overlapping.append(self._ranges[i])

        return overlapping
