import gzip
import typing
import zipfile

from pathlib import Path

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


# Follows the same approach as Google Android Studio's GzipSizeCalculator:
# https://android.googlesource.com/platform/tools/base/+/studio-master-dev/apkparser/analyzer/src/main/java/com/android/tools/apk/analyzer/internal/GzipSizeCalculator.java
def calculate_apk_download_size(apk_path: Path) -> int:
    if not apk_path.exists():
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    if not apk_path.is_file():
        raise ValueError(f"Path is not a file: {apk_path}")

    try:
        with open(apk_path, "rb") as apk_file:
            apk_data = apk_file.read()

        # Compress using gzip with maximum compression (level 9)
        # This matches Google Play Store's compression approach
        compressed_data = gzip.compress(apk_data, compresslevel=9)

        download_size = len(compressed_data)

        logger.debug(
            f"APK download size calculation - "
            f"Original size: {len(apk_data)} bytes, "
            f"Compressed size: {download_size} bytes, "
            f"Compression ratio: {download_size / len(apk_data) * 100:.1f}%"
        )

        return download_size

    except Exception as e:
        raise ValueError("Failed to calculate download size for APK") from e


def calculate_apk_install_size(apk_file: typing.BinaryIO) -> int:
    size = 0
    with zipfile.ZipFile(apk_file) as z:
        for info in z.infolist():
            size += info.file_size
    return size
