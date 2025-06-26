import os
import re
import subprocess
import tempfile
import uuid

from typing import Dict, List

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class SwiftDemangler:
    """A class to demangle Swift symbol names using the swift-demangle tool."""

    def __init__(self, remangle: bool = False):
        """
        Initialize the NameDemangler.

        Args:
            remangle: Whether to use the --remangle-new flag
        """
        self.remangle = remangle
        self.queue: List[str] = []

    def add_name(self, name: str) -> None:
        """
        Add a name to the demangling queue.

        Args:
            name: The mangled name to demangle
        """
        self.queue.append(name)

    def demangle_all(self) -> Dict[str, str]:
        """
        Demangle all names in the queue.

        Returns:
            A dictionary mapping original names to their demangled versions
        """
        if not self.queue:
            return {}

        names = self.queue.copy()
        self.queue.clear()
        results: Dict[str, str] = {}

        # Process in chunks to avoid ENOBUFS error
        chunk_size = 500

        for i in range(0, len(names), chunk_size):
            chunk = names[i : i + chunk_size]
            chunk_results = self._demangle_chunk(chunk)
            results.update(chunk_results)

        return results

    def _demangle_chunk(self, names: List[str]) -> Dict[str, str]:
        if not names:
            logger.warning("No names to demangle")
            return {}

        binary_path = self._get_binary_path()
        results: Dict[str, str] = {}

        # Create a temporary file for the names
        with tempfile.NamedTemporaryFile(
            mode="w", prefix=f"swift-demangle-{uuid.uuid4()}-", suffix=".txt"
        ) as temp_file:
            temp_file.write("\n".join(names))
            temp_file.flush()

            try:
                # Build the command
                if self.remangle:
                    command = f"{binary_path} --remangle-new < {temp_file.name}"
                else:
                    command = f"{binary_path} < {temp_file.name}"

                # Execute the command
                result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)

                output_lines = result.stdout.split("\n")

                # Map results back to original names
                for i, name in enumerate(names):
                    results[name] = output_lines[i].strip() if i < len(output_lines) else name

                return results

            except subprocess.CalledProcessError as error:
                # Handle partial output and errors
                partial_output = error.stdout or ""
                stdout_lines = partial_output.split("\n")
                error_message = error.stderr or ""

                # Try to extract the failed name from the error message
                match = re.search(r"Error: unable to de-mangle (.+)", error_message)
                if match and match.group(1):
                    failed_name = match.group(1).strip()
                    try:
                        failed_index = names.index(failed_name)
                    except ValueError:
                        logger.error(f"Could not find demangled name error: {error}")
                        return results

                    # Add successful results before the failure
                    for i in range(failed_index):
                        results[names[i]] = stdout_lines[i].strip() if i < len(stdout_lines) else names[i]

                    # Recursively process the remainder
                    remainder = names[failed_index + 1 :]
                    remainder_results = self._demangle_chunk(remainder)
                    results.update(remainder_results)

                else:
                    logger.error(f"Demangler error did not match regex: {error}")

                return results

    def _get_binary_path(self) -> str:
        platform = os.name

        if platform == "posix":  # macOS and Linux
            if os.uname().sysname == "Darwin":  # macOS
                return "xcrun swift-demangle"
            elif os.uname().sysname == "Linux":  # Linux
                # For now, raise an error as mentioned in the requirements
                raise RuntimeError("Linux swift-demangle binary not yet available")
            else:
                raise RuntimeError(f"Unsupported POSIX platform: {os.uname().sysname}")
        else:
            raise RuntimeError(f"Unsupported platform: {platform}")
