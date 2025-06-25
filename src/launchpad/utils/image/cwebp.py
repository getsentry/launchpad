from __future__ import annotations

import subprocess

from typing import List, Optional

from ..logging import get_logger

logger = get_logger(__name__)


class CwebpError(Exception):
    """Exception raised when cwebp operations fail."""

    def __init__(self, message: str, return_code: int, stderr: str):
        super().__init__(message)
        self.return_code = return_code
        self.stderr = stderr


class Cwebp:
    """Wrapper for the cwebp command-line tool for WebP compression."""

    def __init__(self, cwebp_path: Optional[str] = None):
        self.cwebp_path = cwebp_path or "cwebp"
        self._verify_installation()

    def _verify_installation(self) -> None:
        try:
            result = subprocess.run(
                [self.cwebp_path, "-version"],
                capture_output=True,
                text=True,
                check=True,
            )
            logger.debug(f"cwebp version: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            raise CwebpError(
                f"cwebp version check failed: {e.stderr}",
                e.returncode,
                e.stderr,
            )
        except FileNotFoundError:
            raise FileNotFoundError(f"cwebp not found. Please install WebP tools. Expected path: {self.cwebp_path}")

    def run(self, args: List[str]) -> subprocess.CompletedProcess[str]:
        """Run cwebp with the given arguments.

        Args:
            args: List of arguments to pass to cwebp

        Returns:
            CompletedProcess result

        Raises:
            CwebpError: If cwebp execution fails
        """
        try:
            full_args = [self.cwebp_path] + args
            return subprocess.run(full_args, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            raise CwebpError(
                f"cwebp execution failed: {e.stderr}",
                e.returncode,
                e.stderr,
            )
