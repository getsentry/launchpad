"""Range mapping system for tracking binary content categorization."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


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


@dataclass(frozen=True)
class Range:
    """Represents a range in the binary with its categorization."""

    start: int
    end: int  # exclusive
    tag: BinaryTag
    description: Optional[str] = None

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

    def intersect(self, other: Range) -> Optional[Range]:
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
    def from_ranges(cls, range1: Range, range2: Range) -> Optional[RangeConflict]:
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


class RangeMap(BaseModel):
    """Efficient range mapping system for tracking binary content categorization.

    This class maintains a sorted list of non-overlapping ranges and provides
    efficient querying and conflict detection.
    """

    model_config = ConfigDict(frozen=True)

    ranges: List[Range] = Field(default_factory=list, description="List of ranges in the map")
    conflicts: List[RangeConflict] = Field(
        default_factory=list, description="List of detected conflicts"
    )
    total_file_size: int = Field(default=0, ge=0, description="Total size of the file being mapped")

    def __init__(self, total_file_size: int = 0, **data: Any) -> None:
        """Initialize the range map with total file size."""
        super().__init__(total_file_size=total_file_size, **data)

    @property
    def total_mapped(self) -> int:
        """Total bytes mapped to any category."""
        return sum(r.size for r in self.ranges)

    @property
    def unmapped_size(self) -> int:
        """Total bytes not mapped to any category."""
        return max(0, self.total_file_size - self.total_mapped)

    @property
    def total_conflict_size(self) -> int:
        """Total size of overlapping regions."""
        return sum(c.overlap_size for c in self.conflicts)

    def size_by_tag(self) -> Dict[BinaryTag, int]:
        """Get total size for each binary tag."""
        sizes: Dict[BinaryTag, int] = {}
        for range_item in self.ranges:
            sizes[range_item.tag] = sizes.get(range_item.tag, 0) + range_item.size
        return sizes

    def get_unmapped_regions(self) -> List[Range]:
        """Get all unmapped regions in the file."""
        if not self.ranges:
            if self.total_file_size > 0:
                return [Range(0, self.total_file_size, BinaryTag.UNMAPPED, "entire_file")]
            return []

        unmapped_regions = []
        sorted_ranges = sorted(self.ranges, key=lambda r: r.start)

        # Check for gap before first range
        if sorted_ranges[0].start > 0:
            unmapped_regions.append(
                Range(0, sorted_ranges[0].start, BinaryTag.UNMAPPED, "before_first_range")
            )

        # Check for gaps between ranges
        for i in range(len(sorted_ranges) - 1):
            current_end = sorted_ranges[i].end
            next_start = sorted_ranges[i + 1].start

            if current_end < next_start:
                unmapped_regions.append(
                    Range(current_end, next_start, BinaryTag.UNMAPPED, f"gap_{i}")
                )

        # Check for gap after last range
        last_end = sorted_ranges[-1].end
        if last_end < self.total_file_size:
            unmapped_regions.append(
                Range(last_end, self.total_file_size, BinaryTag.UNMAPPED, "after_last_range")
            )

        return unmapped_regions

    def add_range(
        self, start: int, end: int, tag: BinaryTag, description: Optional[str] = None
    ) -> None:
        """Add a range to the map, detecting conflicts."""
        if start < 0 or end <= start:
            raise ValueError(f"Invalid range: start={start}, end={end}")

        if end > self.total_file_size:
            raise ValueError(f"Range end ({end}) exceeds file size ({self.total_file_size})")

        new_range = Range(start, end, tag, description)

        # Check for conflicts with existing ranges
        for existing_range in self.ranges:
            conflict = RangeConflict.from_ranges(new_range, existing_range)
            if conflict:
                # Since the model is frozen, we need to work around it
                self.__dict__["conflicts"] = self.conflicts + [conflict]

        # Add the range to our list
        self.__dict__["ranges"] = self.ranges + [new_range]

    def find_ranges_at_offset(self, offset: int) -> List[Range]:
        """Find all ranges that contain the given offset."""
        return [r for r in self.ranges if r.contains(offset)]

    def find_ranges_in_interval(self, start: int, end: int) -> List[Range]:
        """Find all ranges that overlap with the given interval."""
        query_range = Range(start, end, BinaryTag.UNMAPPED)  # Tag doesn't matter for overlap check
        return [r for r in self.ranges if r.overlaps(query_range)]

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
        return expected_size == self.total_file_size

    def get_coverage_report(self) -> Dict[str, int]:
        """Get a detailed coverage report."""
        return {
            "total_file_size": self.total_file_size,
            "total_mapped": self.total_mapped,
            "unmapped_size": self.unmapped_size,
            "coverage_percentage": int((self.total_mapped / max(1, self.total_file_size)) * 100),
            "conflict_count": len(self.conflicts),
            "total_conflict_size": self.total_conflict_size,
            "unmapped_region_count": len(self.get_unmapped_regions()),
            "largest_unmapped_region": max(
                (r.size for r in self.get_unmapped_regions()), default=0
            ),
        }
