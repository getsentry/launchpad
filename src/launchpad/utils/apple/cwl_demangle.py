import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from math import ceil
from typing import Dict, List, Literal, Tuple

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

# Default timeout for cwl-demangle subprocess (in seconds)
DEFAULT_DEMANGLE_TIMEOUT = int(os.environ.get("LAUNCHPAD_DEMANGLE_TIMEOUT", "10"))

# Default chunk size for batching symbols
DEFAULT_CHUNK_SIZE = int(os.environ.get("LAUNCHPAD_DEMANGLE_CHUNK_SIZE", "500"))
_MAX_PARALLEL_DEMANGLE_WORKERS = 4


@dataclass(slots=True)
class CwlDemangleResult:
    """Result from cwl-demangle tool parsing."""

    module: str
    testName: List[str]
    typeName: str
    mangled: str


@dataclass(frozen=True, slots=True)
class _DemangleChunkTelemetry:
    subprocess_duration_s: float | None
    status: Literal["success", "failed", "timeout"]


@dataclass(frozen=True, slots=True)
class _DemangleTelemetry:
    execution_mode: Literal["parallel", "sequential", "parallel-fallback"]
    chunks: tuple[_DemangleChunkTelemetry, ...]


def _percentile(ordered_values: list[float], percentile: float) -> float:
    if not ordered_values:
        return 0.0
    return ordered_values[max(0, ceil(percentile * len(ordered_values)) - 1)]


def _log_demangling_completed(
    telemetry: _DemangleTelemetry,
    *,
    chunk_size: int,
    symbol_count: int,
) -> None:
    successful_subprocess_durations: list[float] = []
    failed_chunk_count = 0
    timed_out_chunk_count = 0
    for chunk in telemetry.chunks:
        if chunk.status == "failed":
            failed_chunk_count += 1
        elif chunk.status == "timeout":
            timed_out_chunk_count += 1
        elif chunk.subprocess_duration_s is not None:
            successful_subprocess_durations.append(chunk.subprocess_duration_s)

    successful_subprocess_durations.sort()
    max_successful_subprocess_duration = successful_subprocess_durations[-1] if successful_subprocess_durations else 0.0
    logger.info(
        "size.apple.swift_demangling_completed",
        extra={
            "execution_mode": telemetry.execution_mode,
            "demangle_workers": _MAX_PARALLEL_DEMANGLE_WORKERS if telemetry.execution_mode != "sequential" else 1,
            "chunk_size": chunk_size,
            "chunk_count": len(telemetry.chunks),
            "symbol_count": symbol_count,
            "failed_chunk_count": failed_chunk_count,
            "timed_out_chunk_count": timed_out_chunk_count,
            "timeout_s": DEFAULT_DEMANGLE_TIMEOUT,
            "successful_chunk_subprocess_duration_p95_s": round(_percentile(successful_subprocess_durations, 0.95), 3),
            "successful_chunk_subprocess_duration_max_s": round(max_successful_subprocess_duration, 3),
        },
    )


class CwlDemangler:
    """A class to demangle Swift symbol names using the cwl-demangle tool."""

    def __init__(
        self,
        is_type: bool = False,
        continue_on_error: bool = True,
        use_json_summary: bool = False,
    ):
        """
        Initialize the CwlDemangler.

        Args:
            is_type: Whether to treat inputs as types rather than symbols
            continue_on_error: Whether to continue processing on errors
            use_json_summary: Whether to request compact JSON output
        """
        self.is_type = is_type
        self.queue: List[str] = []
        self.continue_on_error = continue_on_error
        self.uuid = str(uuid.uuid4())
        self.json_output_flag = "--json-summary" if use_json_summary else "--json"

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
        chunk_size = DEFAULT_CHUNK_SIZE
        total_chunks = (len(names) + chunk_size - 1) // chunk_size

        chunks: List[Tuple[List[str], int]] = []
        for i in range(0, len(names), chunk_size):
            chunk = names[i : i + chunk_size]
            chunk_idx = i // chunk_size
            chunks.append((chunk, chunk_idx))

        # Only use parallel processing if workload justifies multiprocessing overhead (≥4 chunks)
        do_in_parallel = self.use_parallel and total_chunks >= 4

        logger.debug(
            f"Starting Swift demangling: {len(names)} symbols in {total_chunks} chunks "
            f"of {chunk_size} ({'parallel' if do_in_parallel else 'sequential'} mode)"
        )

        if do_in_parallel:
            results, telemetry = self._demangle_parallel(chunks)
        else:
            results, telemetry = self._demangle_sequential(chunks)

        _log_demangling_completed(
            telemetry,
            chunk_size=chunk_size,
            symbol_count=len(names),
        )
        return results

    def _demangle_parallel(
        self, chunks: List[Tuple[List[str], int]]
    ) -> tuple[Dict[str, CwlDemangleResult], _DemangleTelemetry]:
        """Demangle chunks in parallel using threads"""
        results: Dict[str, CwlDemangleResult] = {}
        telemetry: list[_DemangleChunkTelemetry] = []

        try:
            with ThreadPoolExecutor(max_workers=_MAX_PARALLEL_DEMANGLE_WORKERS) as executor:
                futures = [executor.submit(self._demangle_chunk, chunk, chunk_idx) for chunk, chunk_idx in chunks]

            for future in futures:
                chunk_results, chunk_telemetry = future.result()
                results.update(chunk_results)
                telemetry.append(chunk_telemetry)

        except Exception:
            logger.exception("Parallel demangling failed, falling back to sequential")
            results, fallback_telemetry = self._demangle_sequential(chunks)
            return results, _DemangleTelemetry("parallel-fallback", fallback_telemetry.chunks)

        return results, _DemangleTelemetry("parallel", tuple(telemetry))

    def _demangle_sequential(
        self, chunks: List[Tuple[List[str], int]]
    ) -> tuple[Dict[str, CwlDemangleResult], _DemangleTelemetry]:
        """Demangle chunks sequentially"""
        results: Dict[str, CwlDemangleResult] = {}
        telemetry: list[_DemangleChunkTelemetry] = []

        for chunk, chunk_idx in chunks:
            chunk_results, chunk_telemetry = self._demangle_chunk(chunk, chunk_idx)
            results.update(chunk_results)
            telemetry.append(chunk_telemetry)

        return results, _DemangleTelemetry("sequential", tuple(telemetry))

    def _demangle_chunk(
        self, chunk: List[str], chunk_idx: int
    ) -> tuple[Dict[str, CwlDemangleResult], _DemangleChunkTelemetry]:
        if not chunk:
            return {}, _DemangleChunkTelemetry(None, "success")

        binary_path = shutil.which("cwl-demangle")
        if binary_path is None:
            logger.error("cwl-demangle binary not found in PATH")
            return {}, _DemangleChunkTelemetry(None, "failed")

        chunk_set = set(chunk)
        results: Dict[str, CwlDemangleResult] = {}

        with tempfile.NamedTemporaryFile(
            mode="w", prefix=f"cwl-demangle-{self.uuid}-chunk-{chunk_idx}-", suffix=".txt"
        ) as temp_file:
            temp_file.write("\n".join(chunk))
            temp_file.flush()

            command_parts = [
                binary_path,
                "batch",
                "--input",
                temp_file.name,
                self.json_output_flag,
            ]

            if self.is_type:
                command_parts.append("--isType")

            if self.continue_on_error:
                command_parts.append("--continue-on-error")

            subprocess_started = time.monotonic()
            try:
                result = subprocess.run(
                    command_parts, capture_output=True, text=True, check=True, timeout=DEFAULT_DEMANGLE_TIMEOUT
                )
            except subprocess.TimeoutExpired:
                elapsed = time.monotonic() - subprocess_started
                logger.exception(
                    "cwl-demangle subprocess timed out", extra={"chunk_idx": chunk_idx, "elapsed": elapsed}
                )
                return {}, _DemangleChunkTelemetry(elapsed, "timeout")
            except subprocess.CalledProcessError:
                elapsed = time.monotonic() - subprocess_started
                logger.exception("cwl-demangle subprocess failed", extra={"chunk_idx": chunk_idx, "elapsed": elapsed})
                return {}, _DemangleChunkTelemetry(elapsed, "failed")

            subprocess_duration_s = time.monotonic() - subprocess_started

            batch_result = json.loads(result.stdout)

            for symbol_result in batch_result.get("results", []):
                mangled = symbol_result.get("mangled", "")
                if mangled in chunk_set:
                    demangle_result = CwlDemangleResult(
                        module=symbol_result["module"],
                        testName=symbol_result["testName"],
                        typeName=symbol_result["typeName"],
                        mangled=mangled,
                    )
                    results[mangled] = demangle_result

            return results, _DemangleChunkTelemetry(subprocess_duration_s, "success")
