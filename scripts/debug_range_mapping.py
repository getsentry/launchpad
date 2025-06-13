#!/usr/bin/env python3
"""Debug script to analyze iOS binary range mapping.

This script analyzes the range mapping coverage of an iOS binary and provides
detailed information about mapped/unmapped regions, conflicts, and size breakdown.

Usage:
    python scripts/debug_range_mapping.py [path_to_xcarchive.zip]

If no path is provided, it defaults to the HackerNews test artifact.
"""

import sys
from pathlib import Path
from typing import Optional

# Add src to path so we can import launchpad modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from launchpad.analyzers.ios import IOSAnalyzer


def analyze_range_mapping(app_path: Path) -> None:
    """Analyze and display range mapping information for an iOS app."""
    print(f"Analyzing: {app_path}")
    print("=" * 50)

    analyzer = IOSAnalyzer(enable_range_mapping=True)
    results = analyzer.analyze(app_path)

    if not results.binary_analysis.range_map:
        print("ERROR: No range mapping was created!")
        return

    range_map = results.binary_analysis.range_map

    # Basic statistics
    print(f"File size: {range_map.total_file_size:,} bytes")
    print(f"Total mapped: {range_map.total_mapped:,} bytes")
    print(f"Unmapped: {range_map.unmapped_size:,} bytes")
    print(f"Coverage: {(range_map.total_mapped / range_map.total_file_size * 100):.1f}%")
    print()

    # Unmapped regions analysis
    unmapped_regions = range_map.get_unmapped_regions()
    if unmapped_regions:
        print(f"Unmapped regions ({len(unmapped_regions)}):")
        for i, region in enumerate(unmapped_regions):
            print(f"  {i+1:2d}. {region.start:8,} - {region.end:8,} ({region.size:6,} bytes)")
    else:
        print("✅ Perfect coverage! No unmapped regions.")
    print()

    # Size breakdown by category
    print("Size breakdown by category:")
    size_by_tag = range_map.size_by_tag()
    total_categorized = sum(size_by_tag.values())

    for tag, size in sorted(size_by_tag.items(), key=lambda x: x[1], reverse=True):
        percentage = (size / total_categorized * 100) if total_categorized > 0 else 0
        print(f"  {tag.value:20s}: {size:8,} bytes ({percentage:5.1f}%)")
    print()

    # Conflicts analysis
    conflicts = range_map.conflicts
    if conflicts:
        print(f"⚠️  Conflicts detected ({len(conflicts)}):")
        total_conflict_size = sum(c.overlap_size for c in conflicts)
        print(f"  Total conflict size: {total_conflict_size:,} bytes")

        for i, conflict in enumerate(conflicts):
            print(f"  {i+1:2d}. {conflict.range1.description} vs {conflict.range2.description}")
            print(
                f"      Overlap: {conflict.overlap_start:,} - {conflict.overlap_end:,} ({conflict.overlap_size:,} bytes)"
            )
    else:
        print("✅ No conflicts detected.")
    print()

    # Validation
    is_valid = range_map.validate_coverage(allow_unmapped_threshold=1024)
    if is_valid:
        print("✅ Range mapping validation: PASSED")
    else:
        print("❌ Range mapping validation: FAILED")
        largest_unmapped = max((r.size for r in unmapped_regions), default=0)
        print(f"   Largest unmapped region: {largest_unmapped:,} bytes (limit: 1,024)")


def main() -> None:
    """Main entry point."""
    # Default to test artifact if no path provided
    if len(sys.argv) > 1:
        app_path = Path(sys.argv[1])
    else:
        # Default to the HackerNews test artifact
        app_path = Path(__file__).parent.parent / "tests" / "artifacts" / "HackerNews.xcarchive.zip"

    if not app_path.exists():
        print(f"ERROR: File not found: {app_path}")
        print("\nUsage: python scripts/debug_range_mapping.py [path_to_xcarchive.zip]")
        sys.exit(1)

    try:
        analyze_range_mapping(app_path)
    except Exception as e:
        print(f"ERROR: Failed to analyze {app_path}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
