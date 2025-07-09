import json
import shutil
import subprocess
import tempfile
import uuid

from dataclasses import dataclass
from typing import Dict, List

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CwlDemangleResult:
    """Result from cwl-demangle tool parsing."""

    name: str
    type: str
    identifier: str
    module: str
    testName: List[str]
    typeName: str
    description: str
    mangled: str


class CwlDemangler:
    """A class to demangle Swift symbol names using the cwl-demangle tool."""

    def __init__(self, is_type: bool = False, continue_on_error: bool = True):
        """
        Initialize the CwlDemangler.

        Args:
            is_type: Whether to treat inputs as types rather than symbols
            continue_on_error: Whether to continue processing on errors
        """
        self.is_type = is_type
        self.queue: List[str] = []
        self.continue_on_error = continue_on_error
        self.uuid = uuid.uuid4()

    def add_name(self, name: str) -> None:
        """
        Add a name to the demangling queue.

        Args:
            name: The mangled name to demangle
        """
        self.queue.append(name)

    def demangle_all(self) -> Dict[str, CwlDemangleResult]:
        """
        Demangle all names in the queue.

        Returns:
            A dictionary mapping original names to their CwlDemangleResult instances
        """
        if not self.queue:
            return {}

        names = self.queue.copy()
        self.queue.clear()
        results: Dict[str, CwlDemangleResult] = {}

        # Process in chunks to avoid potential issues with large inputs
        chunk_size = 500

        for i in range(0, len(names), chunk_size):
            chunk = names[i : i + chunk_size]
            chunk_results = self._demangle_chunk(chunk, i)
            results.update(chunk_results)

        return results

    def _demangle_chunk(self, names: List[str], i: int) -> Dict[str, CwlDemangleResult]:
        if not names:
            logger.warning("No names to demangle")
            return {}

        binary_path = self._get_binary_path()
        results: Dict[str, CwlDemangleResult] = {}

        with tempfile.NamedTemporaryFile(
            mode="w", prefix=f"cwl-demangle-{self.uuid}-chunk-{i}-", suffix=".txt"
        ) as temp_file:
            temp_file.write("\n".join(names))
            temp_file.flush()

            command_parts = [
                binary_path,
                "batch",
                "--input",
                temp_file.name,
                "--json",
            ]

            if self.is_type:
                command_parts.append("--isType")

            if self.continue_on_error:
                command_parts.append("--continue-on-error")

            try:
                result = subprocess.run(command_parts, capture_output=True, text=True, check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"cwl-demangle failed: {e}")
                return {}

            batch_result = json.loads(result.stdout)

            for symbol_result in batch_result.get("results", []):
                mangled = symbol_result.get("mangled", "")
                if mangled in names:
                    demangle_result = CwlDemangleResult(
                        name=symbol_result["name"],
                        type=symbol_result["type"],
                        identifier=symbol_result["identifier"],
                        module=symbol_result["module"],
                        testName=symbol_result["testName"],
                        typeName=symbol_result["typeName"],
                        description=symbol_result["description"],
                        mangled=mangled,
                    )
                    results[mangled] = demangle_result

            return results

    def _get_binary_path(self) -> str:
        """Get the path to the cwl-demangle binary."""
        path = shutil.which("cwl-demangle")
        assert path is not None
        return path
