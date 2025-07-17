#!/usr/bin/env python3
"""
Test script for image optimization using Pillow.
Processes images and saves optimized versions for visual comparison.
"""

import io
import logging
import sys
from pathlib import Path
from typing import List, NamedTuple

import pillow_heif  # type: ignore
from PIL import Image

# Register HEIF support
pillow_heif.register_heif_opener()  # type: ignore

# Silence noisy loggers
for noisy in ("PIL", "pillow_heif"):
    logging.getLogger(noisy).setLevel(logging.WARNING)


class OptimizationResult(NamedTuple):
    original_size: int
    optimized_size: int
    savings: int
    savings_percent: float
    method: str


def format_size(size_bytes: int) -> str:
    """Format file size in human readable format."""
    size = float(size_bytes)
    for unit in ['B', 'KB', 'MB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def test_minification(img: Image.Image, file_size: int, fmt: str) -> OptimizationResult | None:
    """Test basic minification optimization."""
    try:
        with io.BytesIO() as buf:
            save_params = {"optimize": True}
            if fmt == "png":
                img.save(buf, format="PNG", **save_params)
            else:
                work = img.convert("RGB") if img.mode in {"RGBA", "LA", "P"} else img
                work.save(buf, format="JPEG", quality=85, **save_params)

            new_size = buf.tell()
            if new_size < file_size:
                savings = file_size - new_size
                return OptimizationResult(
                    original_size=file_size,
                    optimized_size=new_size,
                    savings=savings,
                    savings_percent=(savings / file_size) * 100,
                    method=f"minified_{fmt.upper()}"
                )
    except Exception as e:
        print(f"  ❌ Minification failed: {e}")
    return None


def test_heic_conversion(img: Image.Image, file_size: int) -> OptimizationResult | None:
    """Test HEIC conversion optimization."""
    try:
        with io.BytesIO() as buf:
            img.save(buf, format="HEIF", quality=85)
            new_size = buf.tell()
            if new_size < file_size:
                savings = file_size - new_size
                return OptimizationResult(
                    original_size=file_size,
                    optimized_size=new_size,
                    savings=savings,
                    savings_percent=(savings / file_size) * 100,
                    method="HEIC"
                )
    except Exception as e:
        print(f"  ❌ HEIC conversion failed: {e}")
    return None


def save_optimized_image(img: Image.Image, output_path: Path, method: str) -> None:
    """Save the optimized image to disk."""
    try:
        if method.startswith("minified_PNG"):
            img.save(output_path, format="PNG", optimize=True)
        elif method.startswith("minified_JPEG"):
            work = img.convert("RGB") if img.mode in {"RGBA", "LA", "P"} else img
            work.save(output_path, format="JPEG", quality=85, optimize=True)
        elif method == "HEIC":
            img.save(output_path, format="HEIF", quality=85)
    except Exception as e:
        print(f"  ❌ Failed to save optimized image: {e}")


def process_image(image_path: Path, output_dir: Path) -> None:
    """Process a single image and save optimized versions."""
    print(f"\n📸 Processing: {image_path.name}")

    try:
        file_size = image_path.stat().st_size
        print(f"  📊 Original size: {format_size(file_size)}")

        with Image.open(image_path) as img:
            img.load()  # type: ignore
            fmt = (img.format or image_path.suffix[1:]).lower()
            print(f"  🏷️  Format: {fmt.upper()}, Mode: {img.mode}, Size: {img.size}")

            results: List[OptimizationResult] = []

            # Test minification for current format
            if fmt in {"png", "jpg", "jpeg"}:
                if result := test_minification(img, file_size, fmt):
                    results.append(result)

            # Test HEIC conversion for non-HEIC images
            if fmt not in {"heif", "heic"}:
                if result := test_heic_conversion(img, file_size):
                    results.append(result)

            # Test HEIC minification for HEIC images
            if fmt in {"heif", "heic"}:
                if result := test_heic_conversion(img, file_size):
                    result = result._replace(method="minified_HEIC")
                    results.append(result)

            if not results:
                print("  ℹ️  No optimization opportunities found")
                return

            # Show all results
            print("  💡 Optimization opportunities:")
            for i, result in enumerate(results, 1):
                print(f"    {i}. {result.method}: "
                     f"{format_size(result.savings)} saved "
                     f"({result.savings_percent:.1f}%) "
                     f"→ {format_size(result.optimized_size)}")

            # Save the best optimization
            best_result = max(results, key=lambda r: r.savings)
            if best_result.savings >= 4096:  # 4KB threshold
                stem = image_path.stem
                if best_result.method == "HEIC":
                    output_path = output_dir / f"{stem}_optimized.heic"
                elif best_result.method.startswith("minified_"):
                    output_path = output_dir / f"{stem}_optimized{image_path.suffix}"
                else:
                    output_path = output_dir / f"{stem}_optimized{image_path.suffix}"

                save_optimized_image(img, output_path, best_result.method)
                print(f"  ✅ Saved optimized version: {output_path.name}")
                print(f"  🎯 Best savings: {format_size(best_result.savings)} "
                     f"({best_result.savings_percent:.1f}%) with {best_result.method}")
            else:
                print(f"  ⚠️  Best savings ({format_size(best_result.savings)}) "
                      f"below 4KB threshold")

    except Exception as e:
        print(f"  ❌ Failed to process image: {e}")


def main():
    """Main function."""
    if len(sys.argv) != 2:
        print("Usage: python test_image_optimization.py <directory_or_image_path>")
        print("\nThis script will:")
        print("- Analyze images for optimization opportunities")
        print("- Save optimized versions with '_optimized' suffix")
        print("- Show before/after file sizes and savings")
        print("- Allow you to visually compare original vs optimized")
        sys.exit(1)

    input_path = Path(sys.argv[1])

    if not input_path.exists():
        print(f"❌ Path does not exist: {input_path}")
        sys.exit(1)

    # Collect image files
    image_extensions = {'.png', '.jpg', '.jpeg', '.heif', '.heic'}

    if input_path.is_file():
        if input_path.suffix.lower() not in image_extensions:
            print(f"❌ Not a supported image file: {input_path}")
            sys.exit(1)
        image_files = [input_path]
        output_dir = input_path.parent
    else:
        image_files: List[Path] = []
        for ext in image_extensions:
            image_files.extend(input_path.glob(f"*{ext}"))
            image_files.extend(input_path.glob(f"*{ext.upper()}"))

        if not image_files:
            print(f"❌ No supported image files found in: {input_path}")
            sys.exit(1)
        output_dir = input_path

    print(f"🔍 Found {len(image_files)} image(s) to process")
    print(f"📁 Output directory: {output_dir}")

    # Process each image
    for image_file in sorted(image_files):
        process_image(image_file, output_dir)

    print(f"\n✨ Processing complete!")
    print(f"📂 Check {output_dir} for optimized images with '_optimized' suffix")
    print("👀 Open original and optimized images side-by-side to compare quality")


if __name__ == "__main__":
    main()
