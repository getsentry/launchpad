"""Range mapping system for tracking binary content categorization."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List

from pydantic import BaseModel, ConfigDict, Field
from sortedcontainers import SortedList  # type: ignore[import-untyped]


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
    DYLD_REBASE = "dyld_rebase"
    DYLD_BIND = "dyld_bind"
    DYLD_LAZY_BIND = "dyld_lazy_bind"
    DYLD_EXPORTS = "dyld_exports"
    DYLD_FIXUPS = "dyld_fixups"

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

    def intersect(self, other: Range) -> Range | None:
        """Return the intersection of this range with another, or None if no overlap."""
        if not self.overlaps(other):
            return None

        start = max(self.start, other.start)
        end = min(self.end, other.end)

        # For intersections, we need to decide which tag to use
        # Priority: unmapped is lowest, then use the first range's tag
        if self.tag == BinaryTag.UNMAPPED:
            tag = other.tag
        elif other.tag == BinaryTag.UNMAPPED:
            tag = self.tag
        else:
            tag = self.tag  # Use first range's tag for conflicts

        return Range(start, end, tag, f"intersection({self.description}, {other.description})")


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

    This class uses a sorted list (similar to red-black tree) for efficient O(log n)
    operations and provides sophisticated conflict resolution including partial range splitting.
    """

    def __init__(self, total_file_size: int = 0) -> None:
        """Initialize the range map with total file size."""
        self._ranges: SortedList[Range] = SortedList(key=lambda r: r.start)  # Sorted by start position
        self._conflicts: List[RangeConflict] = []
        self._total_file_size = total_file_size
        self._conflict_size = 0

    @property
    def ranges(self) -> List[Range]:
        """List of ranges in the map (for compatibility)."""
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
    def conflict_size(self) -> int:
        """Total size of conflicting regions."""
        return self._conflict_size

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
        allow_partial: bool = False,
        conflict_notifier: Callable[[Range], None] | None = None,
    ) -> None:
        """Add a range to the map, with sophisticated conflict handling.

        Args:
            start: Start offset of the range
            end: End offset of the range (exclusive)
            tag: Binary tag for categorization
            description: Optional description of the range
            allow_partial: If True, split ranges to handle partial overlaps
            conflict_notifier: Optional callback for conflict notification
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

        # Handle conflicts
        if allow_partial:
            self._add_with_partial_splitting(new_range, overlapping_ranges, conflict_notifier)
        else:
            self._add_with_conflict_detection(new_range, overlapping_ranges, conflict_notifier)

    def _find_overlapping_ranges(self, new_range: Range) -> List[Range]:
        """Find all existing ranges that overlap with the new range."""
        overlapping: List[Range] = []

        # Use bisect to find the insertion point for efficient searching
        # Find ranges that might overlap
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

    def _add_with_partial_splitting(
        self,
        new_range: Range,
        overlapping_ranges: List[Range],
        conflict_notifier: Callable[[Range], None] | None,
    ) -> None:
        """Add range with partial splitting to handle overlaps (like legacy Swift code)."""

        # Sort overlapping ranges by start position
        overlapping_ranges.sort(key=lambda r: r.start)

        current_start = new_range.start
        current_end = new_range.end

        for existing_range in overlapping_ranges:
            if conflict_notifier:
                conflict_notifier(existing_range)

            # Record the conflict
            conflict = RangeConflict.from_ranges(new_range, existing_range)
            if conflict:
                self._conflicts.append(conflict)
                self._conflict_size += conflict.overlap_size

            # If there's a gap before the existing range, add that part
            if current_start < existing_range.start:
                gap_end = min(existing_range.start, current_end)
                if gap_end > current_start:
                    partial_range = Range(current_start, gap_end, new_range.tag, new_range.description)
                    self._ranges.add(partial_range)

            # Skip over the overlapping part
            current_start = max(current_start, existing_range.end)

            # If we've covered the entire range, we're done
            if current_start >= current_end:
                return

        # Add any remaining part after all overlaps
        if current_start < current_end:
            remaining_range = Range(current_start, current_end, new_range.tag, new_range.description)
            self._ranges.add(remaining_range)

    def _add_with_conflict_detection(
        self,
        new_range: Range,
        overlapping_ranges: List[Range],
        conflict_notifier: Callable[[Range], None] | None,
    ) -> None:
        """Add range with conflict detection but no splitting."""
        # Record conflicts but don't split
        for existing_range in overlapping_ranges:
            if conflict_notifier:
                conflict_notifier(existing_range)

            conflict = RangeConflict.from_ranges(new_range, existing_range)
            if conflict:
                self._conflicts.append(conflict)
                self._conflict_size += conflict.overlap_size

        # Still add the range (legacy behavior)
        self._ranges.add(new_range)

    def find_ranges_at_offset(self, offset: int) -> List[Range]:
        """Find all ranges that contain the given offset."""
        return [r for r in self._ranges if r.contains(offset)]

    def find_ranges_in_interval(self, start: int, end: int) -> List[Range]:
        """Find all ranges that overlap with the given interval."""
        query_range = Range(start, end, BinaryTag.UNMAPPED)  # Tag doesn't matter for overlap check
        return self._find_overlapping_ranges(query_range)

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

    def get_largest_unmapped_regions(self, limit: int = 10) -> List[Range]:
        """Get the largest unmapped regions, useful for identifying issues."""
        unmapped = self.get_unmapped_regions()
        return sorted(unmapped, key=lambda r: r.size, reverse=True)[:limit]

    def validate_coverage(self, allow_unmapped_threshold: int = 1024) -> bool:
        """Validate that the file is adequately covered by ranges.

        Args:
            allow_unmapped_threshold: Maximum size of unmapped regions to allow

        Returns:
            True if coverage is adequate
        """
        largest_unmapped = self.get_largest_unmapped_regions(1)
        if largest_unmapped and largest_unmapped[0].size > allow_unmapped_threshold:
            return False

        # Check that total mapped + unmapped equals file size
        expected_size = self.total_mapped + self.unmapped_size
        return expected_size == self._total_file_size

    def get_coverage_report(self) -> Dict[str, int]:
        """Get a detailed coverage report."""
        return {
            "total_file_size": self._total_file_size,
            "total_mapped": self.total_mapped,
            "unmapped_size": self.unmapped_size,
            "coverage_percentage": int((self.total_mapped / max(1, self._total_file_size)) * 100),
            "conflict_count": len(self._conflicts),
            "total_conflict_size": self.total_conflict_size,
            "unmapped_region_count": len(self.get_unmapped_regions()),
            "largest_unmapped_region": max((r.size for r in self.get_unmapped_regions()), default=0),
        }

    def contains_address(self, address: int) -> bool:
        """Check if an address is covered by any range (like legacy Swift method)."""
        # Create a test range
        overlapping = self._find_overlapping_ranges(Range(address, address + 1, BinaryTag.UNMAPPED))
        return len(overlapping) > 0
