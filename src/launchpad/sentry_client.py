"""Client for making authenticated API calls to the Sentry monolith."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import re

from pathlib import Path
from typing import Any, Dict, NamedTuple, cast

import requests

from requests.adapters import HTTPAdapter
from requests.auth import AuthBase
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


def read_exactly(file: io.BytesIO, n: int) -> bytes:
    read = 0
    parts = []
    while read < n:
        part = file.read(n - read)
        if not part:
            break
        read += len(part)
        parts.append(part)
    return b"".join(parts)


class Rpc0Auth(AuthBase):
    utf8_encoded_shared_secret: bytes

    def __init__(self, shared_secret: str):
        self.utf8_encoded_shared_secret = shared_secret.encode("utf-8")

    def __call__(self, r):
        signature = hmac.new(self.utf8_encoded_shared_secret, r.body, hashlib.sha256).hexdigest()
        r.headers.update({"Authorization": f"rpcsignature rpc0:{signature}"})
        return r


class DownloadResult(NamedTuple):
    """Result of artifact download operation."""

    success: bool
    file_content: bytes
    file_size_bytes: int
    headers: dict[str, str]


class ErrorResult(NamedTuple):
    """Result when an operation fails."""

    error: str
    status_code: int


class UploadResult(NamedTuple):
    """Result of upload operation."""

    success: bool
    state: str | None = None
    message: str | None = None


def create_retry_session(max_retries: int = 3) -> requests.Session:
    """Create a requests session with retry configuration."""
    session = requests.Session()

    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=0.1,
        status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP status codes
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
        raise_on_status=False,  # Don't raise on HTTP errors, let our code handle them
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


class SentryClient:
    """Client for authenticated API calls to the Sentry monolith."""

    base_url: str
    auth: Rpc0Auth

    def __init__(self, base_url: str, shared_secret: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        if not shared_secret:
            shared_secret = os.getenv("LAUNCHPAD_RPC_SHARED_SECRET")
        if not shared_secret:
            raise RuntimeError("LAUNCHPAD_RPC_SHARED_SECRET must be provided or set as environment variable")
        self.session = create_retry_session()
        self.auth = Rpc0Auth(shared_secret)

    def download_artifact_to_file(self, org: str, project: str, artifact_id: str, out) -> int:
        """Download preprod artifact directly to a file-like object.

        Args:
            org: Organization slug
            project: Project slug
            artifact_id: Artifact ID
            out: File-like object to write to (must support write() method)

        Returns:
            Number of bytes written on success

        Raises:
            RuntimeError: With categorized error message on failure
        """
        endpoint = f"/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/"
        url = self._build_url(endpoint)

        logger.debug(f"GET {url}")

        response = self.session.get(url, auth=self.auth, timeout=120, stream=True)

        if response.status_code != 200:
            error_result = self._handle_error_response(response, "Download artifact")
            error_category, error_description = categorize_http_error(error_result)
            raise RuntimeError(f"Failed to download artifact ({error_category}): {error_description}")

        # Stream directly to the file-like object
        file_size = 0
        chunk_count = 0

        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                chunk_count += 1

                out.write(chunk)
                file_size += len(chunk)

                if file_size > 5 * 1024 * 1024 * 1024:  # 5GB limit
                    raise RuntimeError("Failed to download artifact (client_error): File size exceeds 5GB limit")

        return file_size

    def update_artifact(
        self, org: str, project: str, artifact_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any] | ErrorResult:
        """Update preprod artifact."""
        endpoint = f"/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/update/"
        return self._make_json_request("PUT", endpoint, data, operation="Update")

    def upload_size_analysis_file(
        self,
        org: str,
        project: str,
        artifact_id: str,
        file_path: str,
        max_retries: int = 3,
    ) -> Dict[str, Any] | ErrorResult:
        """Upload size analysis file with chunking following Rust sentry-cli pattern."""
        return self._upload_path_with_assembly(
            org=org,
            project=project,
            artifact_id=artifact_id,
            file_path=file_path,
            max_retries=max_retries,
            assemble_type="size_analysis",
        )

    def upload_installable_app(
        self,
        org: str,
        project: str,
        artifact_id: str,
        file: str | io.BytesIO,
        max_retries: int = 3,
    ) -> Dict[str, Any] | ErrorResult:
        """Upload installable app file with chunking following Rust sentry-cli pattern."""

        if isinstance(file, io.IOBase):
            return self._upload_file_with_assembly(
                org=org,
                project=project,
                artifact_id=artifact_id,
                file=file,
                max_retries=max_retries,
                assemble_type="installable_app",
            )
        else:
            # We should try remove this branch and only take file-like
            # objects for this API.
            return self._upload_path_with_assembly(
                org=org,
                project=project,
                artifact_id=artifact_id,
                file_path=file,
                max_retries=max_retries,
                assemble_type="installable_app",
            )

    def _upload_path_with_assembly(
        self,
        org: str,
        project: str,
        artifact_id: str,
        file_path: str | Path,
        max_retries: int,
        assemble_type: str,
    ) -> Dict[str, Any] | ErrorResult:
        logger.info(f"Uploading {file_path}")

        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        # TODO(EME-217): It looks like this is trying to prevent
        # directory escapes, but it's both too strong (files could be
        # called "foo..apk") and not sufficent (doesn't handle strange
        # unicode, absolute paths, etc).
        if ".." in str(file_path):
            raise ValueError(f"Invalid file path: {file_path}")

        with open(path, "rb") as f:
            return self._upload_file_with_assembly(org, project, artifact_id, f, max_retries, assemble_type)

    def _upload_file_with_assembly(
        self,
        org: str,
        project: str,
        artifact_id: str,
        file: io.BytesIO,
        max_retries: int,
        assemble_type: str,
    ) -> Dict[str, Any] | ErrorResult:
        """Upload file with chunking and assembly following Rust sentry-cli pattern."""

        # Step 1: Get chunk upload options from server
        logger.debug("Getting chunk upload options...")
        options_result = self._get_chunk_upload_options(org)
        if isinstance(options_result, ErrorResult):
            return ErrorResult(
                error=f"Failed to get chunk upload options: {options_result.error}",
                status_code=options_result.status_code,
            )

        chunk_options = options_result.get("chunking", {})
        chunk_size = chunk_options.get("chunk_size", 8 * 1024 * 1024)  # fallback to 8MB

        # TODO(EME-216): max_chunks is unused? Should we be using it?
        max_chunks = chunk_options.get("max_chunks", 64)

        logger.debug(f"Server chunk config: size={chunk_size}, max_chunks={max_chunks}")

        # Step 2: Calculate checksums
        total_checksum = hashlib.file_digest(file, "sha1").hexdigest()
        size = file.tell()
        file.seek(0)

        checksums = []
        while True:
            chunk = read_exactly(file, chunk_size)
            if not chunk:
                break
            checksums.append(hashlib.sha1(chunk).hexdigest())
        file.seek(0)
        logger.info(f"File prepared: SHA1={total_checksum} size={size} chunks={len(checksums)}")

        # Step 3: Upload chunks
        logger.info(f"Uploading all {len(checksums)} chunks...")
        while True:
            chunk = read_exactly(file, chunk_size)
            if not chunk:
                break
            self.upload_chunk(org, chunk)

        # Step 4: Assemble with retry loop
        for attempt in range(max_retries):
            logger.debug(f"Assembly attempt {attempt + 1}/{max_retries}")

            result = self._assemble_file(
                org=org,
                project=project,
                artifact_id=artifact_id,
                checksum=total_checksum,
                chunks=checksums,
                assemble_type=assemble_type,
            )

            # Handle ErrorResult from _assemble_file
            if isinstance(result, ErrorResult):
                logger.warning(f"Assembly attempt {attempt + 1} failed: {result}")
                if attempt == max_retries - 1:  # Last attempt
                    return result
                continue

            state = result.get("state")
            if state in ["ok", "created"]:
                logger.info("Upload and assembly successful")
                return result
            elif state == "not_found":
                missing = result.get("missingChunks", [])
                if missing:
                    logger.warning(f"{len(missing)} chunks failed to upload")
                else:
                    logger.warning("Assembly failed but no missing chunks reported")
                return result
            else:
                logger.warning(f"Assembly attempt {attempt + 1} failed: {result}")
                if attempt == max_retries - 1:  # Last attempt
                    return result

        return ErrorResult(error=f"Failed after {max_retries} attempts", status_code=500)

    def _build_url(self, endpoint: str) -> str:
        """Build full URL from endpoint."""
        return f"{self.base_url}{endpoint}"

    def _handle_error_response(self, response: requests.Response, operation: str) -> ErrorResult:
        """Handle non-200 response with consistent error format."""
        logger.warning(f"{operation} failed: {response.status_code}")
        # Cast to int to help type checker understand status_code is int
        status_code = cast(int, response.status_code)
        return ErrorResult(
            error=f"HTTP {status_code}",
            status_code=status_code,
        )

    def _make_json_request(
        self,
        method: str,
        endpoint: str,
        data: Dict[str, Any] | None = None,
        timeout: int = 30,
        operation: str | None = None,
    ) -> Dict[str, Any] | ErrorResult:
        """Make a JSON request with standard error handling."""
        url = self._build_url(endpoint)
        body = json.dumps(data).encode("utf-8") if data else b""
        operation = operation or f"{method} {endpoint}"

        logger.debug(f"{method} {url}")
        response = self.session.request(
            method=method,
            url=url,
            data=body or None,
            auth=self.auth,
            timeout=timeout,
        )

        if response.status_code != 200:
            return self._handle_error_response(response, operation)

        return response.json()

    def _get_chunk_upload_options(self, org: str) -> Dict[str, Any] | ErrorResult:
        """Get chunk upload configuration from server."""
        endpoint = f"/api/0/organizations/{org}/chunk-upload/"
        return self._make_json_request("GET", endpoint, operation="Get chunk options")

    def upload_chunk(self, org: str, chunk: bytes) -> bool:
        """Upload single chunk."""

        checksum = hashlib.sha1(chunk).hexdigest()

        r = requests.Request(
            "POST",
            f"{self.base_url}/api/0/organizations/{org}/chunk-upload/",
            files={
                "file": (checksum, chunk, "application/octet-stream"),
            },
            auth=self.auth,
        )

        response = self.session.send(r.prepare(), timeout=60)

        success = response.status_code in [200, 201, 409]  # 409 = already exists
        if not success:
            logger.warning(f"Chunk upload failed: {response.status_code}")
        return success

    def _assemble_file(
        self,
        org: str | int,
        project: str | int,
        artifact_id: str | int,
        checksum: str,
        chunks: list[str],
        assemble_type: str,
    ) -> Dict[str, Any] | ErrorResult:
        """Call the assemble generic endpoint with specified assemble_type."""
        # Validate hex strings
        if not re.match(r"^[a-fA-F0-9]+$", checksum):
            raise ValueError("Invalid checksum format")
        for chunk in chunks:
            if not re.match(r"^[a-fA-F0-9]+$", chunk):
                raise ValueError("Invalid chunk format")

        data = {
            "checksum": checksum,
            "chunks": chunks,
            "assemble_type": assemble_type,
        }

        endpoint = f"/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/assemble-generic/"
        return self._make_json_request("POST", endpoint, data, operation="Assemble request")


def categorize_http_error(error_result: ErrorResult | Dict[str, Any]) -> tuple[str, str]:
    """
    Categorize HTTP error results from SentryClient.

    Returns:
        Tuple of (error_category, error_description)
        Categories: "not_found", "server_error", "client_error", "unknown"
    """
    # Handle ErrorResult NamedTuple
    if isinstance(error_result, ErrorResult):
        status_code = error_result.status_code
        if status_code == 404:
            return "not_found", f"Resource not found (HTTP {status_code})"
        elif 500 <= status_code < 600:
            return "server_error", f"Server error (HTTP {status_code})"
        elif 400 <= status_code < 500:
            return "client_error", f"Client error (HTTP {status_code})"
        else:
            return "unknown", f"Unexpected HTTP status {status_code}"

    # Handle legacy dict format (for backward compatibility)
    if isinstance(error_result, dict):
        # First try to get the structured status code
        status_code = error_result.get("status_code")
        if isinstance(status_code, int):
            if status_code == 404:
                return "not_found", f"Resource not found (HTTP {status_code})"
            elif 500 <= status_code < 600:
                return "server_error", f"Server error (HTTP {status_code})"
            elif 400 <= status_code < 500:
                return "client_error", f"Client error (HTTP {status_code})"
            else:
                return "unknown", f"Unexpected HTTP status {status_code}"

        # Fallback to parsing the error message string
        error_msg = error_result.get("error", "")
        if isinstance(error_msg, str):
            # Extract HTTP status code from error message like "HTTP 404"
            match = re.search(r"HTTP (\d+)", error_msg)
            if match:
                try:
                    status_code = int(match.group(1))
                    if status_code == 404:
                        return "not_found", f"Resource not found (HTTP {status_code})"
                    elif 500 <= status_code < 600:
                        return "server_error", f"Server error (HTTP {status_code})"
                    elif 400 <= status_code < 500:
                        return "client_error", f"Client error (HTTP {status_code})"
                    else:
                        return "unknown", f"Unexpected HTTP status {status_code}"
                except ValueError:
                    pass

    return "unknown", f"Unknown error: {error_result}"
