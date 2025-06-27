import subprocess

from pathlib import Path

from ..logging import get_logger

logger = get_logger(__name__)


class Cwebp:
    def __init__(self):
        self.binary_path = self._find_cwebp()
        if not self.binary_path:
            raise FileNotFoundError("cwebp binary not found in PATH")

    def _find_cwebp(self) -> str | None:
        try:
            result = subprocess.run(
                ["which", "cwebp"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def convert_to_webp(self, input_path: Path, output_path: Path) -> bool:
        """Convert an image to WebP format.
        Returns:
            True if conversion was successful, False otherwise
        """
        args = [self.binary_path]

        args.append("-lossless")

        args.extend([str(input_path), "-o", str(output_path)])

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode != 0:
                logger.debug(f"cwebp conversion failed: {result.stderr}")
                return False

            return output_path.exists()

        except Exception as e:
            logger.debug(f"Error running cwebp: {e}")
            return False
