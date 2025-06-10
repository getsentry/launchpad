#!/usr/bin/env python3
"""Demo script for treemap generation functionality."""

import json
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from launchpad.analyzers.ios import IOSAnalyzer  # noqa: E402


def generate_treemap_demo(input_path: Path, output_path: Path) -> None:
    """Generate a treemap demo for the given iOS app.

    Args:
        input_path: Path to the iOS app archive (.xcarchive.zip)
        output_path: Path where to save the treemap JSON
    """
    print(f"Analyzing iOS app: {input_path}")

    # Create analyzer with treemap enabled
    analyzer = IOSAnalyzer(enable_treemap=True)

    # Analyze the app
    print("Running analysis...")
    results = analyzer.analyze(input_path)

    # Display basic info
    print(f"\nApp: {results.app_info.name} v{results.app_info.version}")
    print(f"Bundle ID: {results.app_info.bundle_id}")
    print(f"Total files: {results.file_analysis.file_count}")
    total_mb = results.total_size / 1024 / 1024
    print(f"Total size: {results.total_size:,} bytes ({total_mb:.1f} MB)")

    if results.treemap:
        print("\nTreemap Statistics:")
        print(f"Total install size: {results.treemap.total_install_size:,} bytes")
        print(f"Total download size: {results.treemap.total_download_size:,} bytes")
        ratio = results.treemap.total_download_size / results.treemap.total_install_size
        print(f"Compression ratio: {ratio:.1%}")

        # Show category breakdown
        print("\nCategory breakdown:")
        for category, sizes in results.treemap.category_breakdown.items():
            install_mb = sizes["install"] / 1024 / 1024
            download_mb = sizes["download"] / 1024 / 1024
            print(f"  {category}: {install_mb:.1f} MB install, {download_mb:.1f} MB download")

        # Generate JSON for visualization
        treemap_json = results.treemap.to_json_dict()

        # Save to file
        with open(output_path, "w") as f:
            json.dump(treemap_json, f, indent=2)

        print(f"\nTreemap JSON saved to: {output_path}")
        print("You can use this JSON with D3.js treemap visualization libraries.")

        # Show a sample of the JSON structure
        print("\nSample JSON structure:")
        print(f"- Root app name: {treemap_json['app']['name']}")
        print(f"- Root children count: {len(treemap_json['app']['children'])}")
        print(f"- Metadata keys: {list(treemap_json['metadata'].keys())}")

    else:
        print("Treemap generation was disabled or failed.")


def main() -> None:
    """Main function."""
    # Default paths
    sample_app = Path(__file__).parent.parent / "tests" / "artifacts" / "HackerNews.xcarchive.zip"
    output_file = Path(__file__).parent.parent / "hackernews_treemap.json"

    # Check if sample app exists
    if not sample_app.exists():
        print(f"Sample app not found: {sample_app}")
        print("Please provide a path to an iOS app archive (.xcarchive.zip)")
        return

    try:
        generate_treemap_demo(sample_app, output_file)
    except Exception as e:
        print(f"Error: {e}")
        return


if __name__ == "__main__":
    main()
