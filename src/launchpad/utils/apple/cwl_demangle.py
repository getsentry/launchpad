import json
import multiprocessing
import os
import shutil
import subprocess
import tempfile
import uuid

from dataclasses import dataclass
from typing import Dict, List, Tuple

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

    def __init__(
        self,
        is_type: bool = False,
        continue_on_error: bool = True,
    ):
        """
        Initialize the CwlDemangler.

        Args:
            is_type: Whether to treat inputs as types rather than symbols
            continue_on_error: Whether to continue processing on errors
        """
        self.is_type = is_type
        self.queue: List[str] = []
        self.continue_on_error = continue_on_error
        self.uuid = str(uuid.uuid4())

        # Disable parallel processing if LAUNCHPAD_NO_PARALLEL_DEMANGLE=true
        env_disable = os.environ.get("LAUNCHPAD_NO_PARALLEL_DEMANGLE", "").lower() == "true"
        self.use_parallel = not env_disable

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

        # Process in chunks to avoid potential issues with large inputs
        chunk_size = 5000
        total_chunks = (len(names) + chunk_size - 1) // chunk_size

        chunks: List[Tuple[List[str], int]] = []
        for i in range(0, len(names), chunk_size):
            chunk = names[i : i + chunk_size]
            chunk_idx = i // chunk_size
            chunks.append((chunk, chunk_idx))

        # Only use parallel processing if workload justifies multiprocessing overhead (≥4 chunks = ≥20K symbols)
        do_in_parallel = self.use_parallel and total_chunks >= 4

        logger.debug(
            f"Starting Swift demangling: {len(names)} symbols in {total_chunks} chunks "
            f"of {chunk_size} ({'parallel' if do_in_parallel else 'sequential'} mode)"
        )

        return self._demangle_parallel(chunks) if do_in_parallel else self._demangle_sequential(chunks)

    def _demangle_parallel(self, chunks: List[Tuple[List[str], int]]) -> Dict[str, CwlDemangleResult]:
        """Demangle chunks in parallel using multiprocessing"""
        results: Dict[str, CwlDemangleResult] = {}

        try:
            # Prepare arguments for starmap
            worker_args = [
                (chunk, chunk_idx, self.is_type, self.continue_on_error, self.uuid) for chunk, chunk_idx in chunks
            ]

            # Process chunks in parallel
            # NOTE: starmap pickles the function and arguments to send to worker processes.
            # Current arguments are all safe to pickle:
            # - chunk: List[str] (standard containers with primitives)
            # - chunk_idx: int (primitive)
            # - is_type: bool (primitive)
            # - continue_on_error: bool (primitive)
            # - uuid: str (primitive)
            with multiprocessing.Pool(processes=4) as pool:
                chunk_results = pool.starmap(_demangle_chunk_worker, worker_args)

            for chunk_result in chunk_results:
                results.update(chunk_result)

        except Exception:
            logger.exception("Parallel demangling failed, falling back to sequential")
            results = self._demangle_sequential(chunks)

        return results

    def _demangle_sequential(self, chunks: List[Tuple[List[str], int]]) -> Dict[str, CwlDemangleResult]:
        """Demangle chunks sequentially"""
        results: Dict[str, CwlDemangleResult] = {}

        for chunk, chunk_idx in chunks:
            chunk_results = self._demangle_chunk(chunk, chunk_idx)
            results.update(chunk_results)

        return results

    def _demangle_chunk(self, names: List[str], i: int) -> Dict[str, CwlDemangleResult]:
        return _demangle_chunk_worker(names, i, self.is_type, self.continue_on_error, self.uuid)


def _demangle_chunk_worker(
    chunk: List[str],
    chunk_idx: int,
    is_type: bool,
    continue_on_error: bool,
    demangle_uuid: str,
) -> Dict[str, CwlDemangleResult]:
    """Demangle a chunk of symbols. Arguments must be picklable for multiprocessing."""
    if not chunk:
        return {}

    binary_path = shutil.which("cwl-demangle")
    if binary_path is None:
        logger.error("cwl-demangle binary not found in PATH")
        return {}

    chunk_set = set(chunk)
    results: Dict[str, CwlDemangleResult] = {}

    with tempfile.NamedTemporaryFile(
        mode="w", prefix=f"cwl-demangle-{demangle_uuid}-chunk-{chunk_idx}-", suffix=".txt"
    ) as temp_file:
        temp_file.write("\n".join(chunk))
        temp_file.flush()

        command_parts = [
            binary_path,
            "batch",
            "--input",
            temp_file.name,
            "--json",
        ]

        if is_type:
            command_parts.append("--isType")

        if continue_on_error:
            command_parts.append("--continue-on-error")

        try:
            result = subprocess.run(command_parts, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError:
            logger.exception(f"cwl-demangle failed for chunk {chunk_idx}")
            return {}

        batch_result = json.loads(result.stdout)

        for symbol_result in batch_result.get("results", []):
            mangled = symbol_result.get("mangled", "")
            if mangled in chunk_set:
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
