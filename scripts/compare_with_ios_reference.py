#!/usr/bin/env python3
"""Compare our implementation results with the reference implementation."""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def load_json_file(file_path: Path) -> Dict[str, Any]:
    """Load JSON data from file."""
    with open(file_path, "r") as f:
        return json.load(f)


def extract_reference_values(reference_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract key values from reference implementation."""
    values = {}

    # App store file sizes
    app_store = reference_data.get("app_store_file_sizes", {}).get("mainApp", {})
    values["ref_download_size"] = app_store.get("downloadSize", 0)
    values["ref_install_size"] = app_store.get("installSize", 0)

    # App total value (seems to be different from install size)
    values["ref_app_value"] = reference_data.get("app", {}).get("value", 0)

    # Total savings
    values["ref_total_savings"] = reference_data.get("total_savings", 0)

    # Count files in app children (for comparison)
    app_children = reference_data.get("app", {}).get("children", [])
    values["ref_app_children_count"] = len(app_children)

    return values


def extract_our_values(our_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract key values from our implementation."""
    values = {}

    # File analysis totals
    file_analysis = our_data.get("file_analysis", {})
    values["our_total_size"] = file_analysis.get("total_size", 0)
    values["our_file_count"] = file_analysis.get("file_count", 0)

    # Treemap totals
    treemap = our_data.get("treemap", {})
    values["our_install_size"] = treemap.get("total_install_size", 0)
    values["our_download_size"] = treemap.get("total_download_size", 0)
    values["our_treemap_file_count"] = treemap.get("file_count", 0)

    # Duplicate savings
    duplicate_files = file_analysis.get("duplicate_files", [])
    values["our_total_savings"] = sum(group.get("potential_savings", 0) for group in duplicate_files)

    # App info
    app_info = our_data.get("app_info", {})
    values["our_app_name"] = app_info.get("name", "")
    values["our_app_version"] = app_info.get("version", "")

    # Binary analysis
    binary_analysis = our_data.get("binary_analysis", {})
    values["our_executable_size"] = binary_analysis.get("executable_size", 0)

    return values


def collect_reference_file_sizes(reference_data: Dict[str, Any]) -> Dict[str, int]:
    """Collect individual file sizes from reference implementation."""
    file_sizes: Dict[str, int] = {}

    def traverse_children(children: List[Dict[str, Any]], path_prefix: str = ""):
        """Recursively traverse children to collect file sizes."""
        for child in children:
            child_name = child.get("name", "unknown")
            current_path = f"{path_prefix}/{child_name}" if path_prefix else child_name

            if "file" in child:
                file_data = child["file"]
                file_path = file_data.get("path", current_path)
                file_value = file_data.get("value", 0)
                if isinstance(file_path, str) and isinstance(file_value, int):
                    # Normalize path by removing leading slash and absolute paths
                    normalized_path = file_path.lstrip("/")
                    # If it's still an absolute path, try to extract just the relative part
                    if "HackerNews.app/" in normalized_path:
                        normalized_path = normalized_path.split("HackerNews.app/")[-1]
                    file_sizes[normalized_path] = file_value

                # Also traverse any children of the file
                if "children" in file_data and isinstance(file_data["children"], list):
                    traverse_children(file_data["children"], current_path)
            elif "children" in child and isinstance(child["children"], list):
                traverse_children(child["children"], current_path)

    app_children = reference_data.get("app", {}).get("children", [])
    if isinstance(app_children, list):
        traverse_children(app_children)

    return file_sizes


def collect_our_file_sizes(our_data: Dict[str, Any]) -> Dict[str, int]:
    """Collect individual file sizes from our implementation."""
    file_sizes: Dict[str, int] = {}

    def traverse_treemap(element: Dict[str, Any]) -> None:
        """Recursively traverse treemap elements to collect file sizes."""
        element_path = element.get("path")
        if element_path:  # This is a file (has a path)
            install_size = element.get("install_size", 0)
            if isinstance(element_path, str) and isinstance(install_size, int):
                file_sizes[element_path] = install_size

        # Recursively traverse children
        children = element.get("children", [])
        if isinstance(children, list):
            for child in children:
                if isinstance(child, dict):
                    traverse_treemap(child)  # type: ignore

    # Get from treemap instead of file_analysis to use aligned sizes
    treemap = our_data.get("treemap", {})
    root = treemap.get("root", {})
    if isinstance(root, dict):
        traverse_treemap(root)  # type: ignore

    return file_sizes


def compare_implementations() -> None:
    """Compare our implementation with the reference."""
    # File paths
    reference_file = Path(__file__).parent.parent / "tests" / "artifacts" / "hackernews-results.json"
    our_file = Path(__file__).parent.parent / "apple-app-analysis-report.json"

    # Check if files exist
    if not reference_file.exists():
        print(f"❌ Reference file not found: {reference_file}")
        return

    if not our_file.exists():
        print(f"❌ Our results file not found: {our_file}")
        print("Run: python -m launchpad.cli apple-app --verbose tests/artifacts/HackerNews.xcarchive.zip")
        return

    print("📊 Comparing Apple App Size Analysis Results")
    print("=" * 50)

    # Load data
    reference_data = load_json_file(reference_file)
    our_data = load_json_file(our_file)

    # Extract key values
    ref_values = extract_reference_values(reference_data)
    our_values = extract_our_values(our_data)

    print("\n📱 App Information:")
    print(f"  Our app: {our_values['our_app_name']} v{our_values['our_app_version']}")

    print("\n📏 Size Comparisons:")
    ref_install_mb = ref_values["ref_install_size"] / 1024 / 1024
    our_install_mb = our_values["our_install_size"] / 1024 / 1024
    print(f"  Reference install size: {ref_values['ref_install_size']:,} bytes ({ref_install_mb:.1f} MB)")
    print(f"  Our install size:       {our_values['our_install_size']:,} bytes ({our_install_mb:.1f} MB)")
    install_diff = our_values["our_install_size"] - ref_values["ref_install_size"]
    print(f"  Difference:             {install_diff:+,} bytes ({install_diff/1024/1024:+.1f} MB)")

    ref_download_mb = ref_values["ref_download_size"] / 1024 / 1024
    our_download_mb = our_values["our_download_size"] / 1024 / 1024
    print(f"\n  Reference download size: {ref_values['ref_download_size']:,} bytes ({ref_download_mb:.1f} MB)")
    print(f"  Our download size:       {our_values['our_download_size']:,} bytes ({our_download_mb:.1f} MB)")
    download_diff = our_values["our_download_size"] - ref_values["ref_download_size"]
    print(f"  Difference:              {download_diff:+,} bytes ({download_diff/1024/1024:+.1f} MB)")

    ref_app_mb = ref_values["ref_app_value"] / 1024 / 1024
    our_total_mb = our_values["our_total_size"] / 1024 / 1024
    print(f"\n  Reference app value:     {ref_values['ref_app_value']:,} bytes ({ref_app_mb:.1f} MB)")
    print(f"  Our total size:          {our_values['our_total_size']:,} bytes ({our_total_mb:.1f} MB)")
    app_diff = our_values["our_total_size"] - ref_values["ref_app_value"]
    print(f"  Difference:              {app_diff:+,} bytes ({app_diff/1024/1024:+.1f} MB)")

    print(f"\n📊 File Counts:")
    print(f"  Our file count:          {our_values['our_file_count']}")
    print(f"  Reference app children:  {ref_values['ref_app_children_count']}")

    print(f"\n💾 Executable Size:")
    print(
        f"  Our executable size:     {our_values['our_executable_size']:,} bytes ({our_values['our_executable_size']/1024/1024:.1f} MB)"
    )

    print(f"\n💰 Potential Savings:")
    print(
        f"  Reference savings:       {ref_values['ref_total_savings']:,} bytes ({ref_values['ref_total_savings']/1024:.1f} KB)"
    )
    print(
        f"  Our savings:             {our_values['our_total_savings']:,} bytes ({our_values['our_total_savings']/1024:.1f} KB)"
    )
    savings_diff = our_values["our_total_savings"] - ref_values["ref_total_savings"]
    print(f"  Difference:              {savings_diff:+,} bytes ({savings_diff/1024:+.1f} KB)")

    # Compare individual file sizes
    print(f"\n📁 Individual File Size Comparison:")
    ref_files = collect_reference_file_sizes(reference_data)
    our_files = collect_our_file_sizes(our_data)

    print(f"  Reference files found:   {len(ref_files)}")
    print(f"  Our files found:         {len(our_files)}")

    # Find common files and compare sizes
    common_files = set(ref_files.keys()) & set(our_files.keys())
    only_in_ref = set(ref_files.keys()) - set(our_files.keys())
    only_in_ours = set(our_files.keys()) - set(ref_files.keys())

    print(f"  Common files:            {len(common_files)}")
    print(f"  Only in reference:       {len(only_in_ref)}")
    print(f"  Only in ours:            {len(only_in_ours)}")

    if common_files:
        print(f"\n🔍 Sample File Size Matches:")
        # Show first 10 common files
        for file_path in sorted(list(common_files))[:10]:
            ref_size = ref_files[file_path]
            our_size = our_files[file_path]
            match = "✅" if ref_size == our_size else "❌"
            print(f"  {match} {file_path}: {ref_size:,} vs {our_size:,}")

    # Summary
    print(f"\n🎯 Summary:")
    if abs(install_diff) < 1000:  # Within 1KB
        print("  ✅ Install sizes match closely")
    else:
        print("  ❌ Install sizes differ significantly")

    if abs(download_diff) < 1000:  # Within 1KB
        print("  ✅ Download sizes match closely")
    else:
        print("  ❌ Download sizes differ significantly")

    if abs(savings_diff) < 100:  # Within 100 bytes
        print("  ✅ Savings calculations match closely")
    else:
        print("  ❌ Savings calculations differ")


if __name__ == "__main__":
    compare_implementations()
