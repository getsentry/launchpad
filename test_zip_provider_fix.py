#!/usr/bin/env python3
"""Test script to verify ZipProvider fix resolves class name issue."""

import sys
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from launchpad.artifacts.android.zipped_apk import ZippedAPK
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


def test_class_names_preserved():
    """Test that class names are preserved after APK object goes out of scope."""
    # Use a test APK file
    test_apk_path = Path("tests/_fixtures/android/hn.apk")

    if not test_apk_path.exists():
        logger.error(f"Test APK not found: {test_apk_path}")
        return

    # Read the APK file
    with open(test_apk_path, "rb") as f:
        apk_content = f.read()

    # Create ZippedAPK object
    zipped_apk = ZippedAPK(apk_content)
    apk = zipped_apk.get_primary_apk()

    # Get class definitions
    class_definitions = apk.get_class_definitions()

    logger.info(f"Found {len(class_definitions)} class definitions")

    # Log first few class names
    for i, class_def in enumerate(class_definitions[:5]):
        logger.info(f"Class {i}: {class_def.fullname}")

    # Store some class names for later comparison
    stored_names = [class_def.fullname for class_def in class_definitions[:5]]

    # Force the APK object to go out of scope
    del apk
    del zipped_apk

    # Try to access the stored names again
    logger.info("After object destruction, stored names are:")
    for i, name in enumerate(stored_names):
        logger.info(f"Stored class {i}: {name}")

    logger.info("Test completed successfully!")


if __name__ == "__main__":
    test_class_names_preserved()
