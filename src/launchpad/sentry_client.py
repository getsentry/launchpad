"""Client for making authenticated API calls to the Sentry monolith."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets

from pathlib import Path
from typing import Any, Dict, NamedTuple

import requests

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


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

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.shared_secret = os.getenv("LAUNCHPAD_RPC_SHARED_SECRET")
        if not self.shared_secret:
            raise RuntimeError("LAUNCHPAD_RPC_SHARED_SECRET must be provided or set as environment variable")

        self.session = create_retry_session()

    def download_artifact_to_file(self, org: str, project: str, artifact_id: str, out) -> int | ErrorResult:
        """Download preprod artifact directly to a file-like object.

        Args:
            org: Organization slug
            project: Project slug
            artifact_id: Artifact ID
            out: File-like object to write to (must support write() method)

        Returns:
            Number of bytes written on success, or ErrorResult on failure
        """
        endpoint = f"/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/"
        url = self._build_url(endpoint)

        logger.debug(f"GET {url}")
        response = self.session.get(url, headers=self._get_auth_headers(), timeout=120, stream=True)

        if response.status_code != 200:
            return self._handle_error_response(response, "Download")

        # Stream directly to the file-like object
        file_size = 0
        try:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    out.write(chunk)
                    file_size += len(chunk)
                    if file_size > 5 * 1024 * 1024 * 1024:  # 5GB limit
                        logger.error("Download exceeds 5GB limit")
                        return ErrorResult(
                            error="File size exceeds 5GB limit",
                            status_code=413,  # Payload Too Large
                        )

            return file_size

        except Exception as e:
            logger.error(f"Failed to write to file-like object: {e}")
            return ErrorResult(
                error=f"Failed to write to file-like object: {e}",
                status_code=500,
            )

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
        # Basic path validation
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if ".." in file_path:
            raise ValueError(f"Invalid file path: {file_path}")

        with open(path, "rb") as f:
            content = f.read()

        logger.info(f"Uploading {file_path} ({len(content)} bytes, {len(content) / 1024 / 1024:.2f} MB)")

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
        max_chunks = chunk_options.get("max_chunks", 64)

        logger.debug(f"Server chunk config: size={chunk_size}, max_chunks={max_chunks}")

        # Step 2: Create chunks and calculate checksums
        total_checksum = hashlib.sha1(content).hexdigest()
        chunks = self._create_chunks(content, chunk_size)
        chunk_checksums = [c["checksum"] for c in chunks]

        logger.info(f"File prepared: SHA1={total_checksum}, chunks={len(chunks)}")

        # Step 3: Upload ALL chunks first (following Rust pattern)
        logger.info(f"Uploading all {len(chunks)} chunks...")
        self._upload_chunks(org, chunks, chunk_checksums)

        # Step 4: Assemble with retry loop
        for attempt in range(max_retries):
            logger.debug(f"Assembly attempt {attempt + 1}/{max_retries}")

            result = self._assemble_size_analysis(
                org=org,
                project=project,
                artifact_id=artifact_id,
                checksum=total_checksum,
                chunks=chunk_checksums,
            )

            # Handle ErrorResult from _assemble_size_analysis
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
                if not missing:
                    logger.warning("Assembly failed but no missing chunks reported")
                    return result

                logger.info(f"Re-uploading {len(missing)} missing chunks")
                if not self._upload_chunks(org, chunks, missing):
                    logger.warning(f"Some chunks failed to re-upload on attempt {attempt + 1}")
            else:
                logger.warning(f"Assembly attempt {attempt + 1} failed: {result}")
                if attempt == max_retries - 1:  # Last attempt
                    return result

        return ErrorResult(error=f"Failed after {max_retries} attempts", status_code=500)

    def _get_auth_headers(self, body: bytes | None = None) -> Dict[str, str]:
        """Get authentication headers for a request."""
        body = body or b""
        signature = hmac.new(self.shared_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        return {
            "Authorization": f"rpcsignature rpc0:{signature}",
            "Content-Type": "application/json",
        }

    def _build_url(self, endpoint: str) -> str:
        """Build full URL from endpoint."""
        return f"{self.base_url}{endpoint}"

    def _handle_error_response(self, response: requests.Response, operation: str) -> ErrorResult:
        """Handle non-200 response with consistent error format."""
        logger.warning(f"{operation} failed: {response.status_code}")
        return ErrorResult(
            error=f"HTTP {response.status_code}",
            status_code=response.status_code,
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
            headers=self._get_auth_headers(body),
            timeout=timeout,
        )

        if response.status_code != 200:
            return self._handle_error_response(response, operation)

        return response.json()

    def _get_chunk_upload_options(self, org: str) -> Dict[str, Any] | ErrorResult:
        """Get chunk upload configuration from server."""
        endpoint = f"/api/0/organizations/{org}/chunk-upload/"
        return self._make_json_request("GET", endpoint, operation="Get chunk options")

    def _create_chunks(self, content: bytes, chunk_size: int) -> list[Dict[str, Any]]:
        """Split content into chunks with checksums."""
        chunks = []
        for i in range(0, len(content), chunk_size):
            data = content[i : i + chunk_size]
            chunks.append(
                {
                    "checksum": hashlib.sha1(data).hexdigest(),
                    "data": data,
                    "size": len(data),
                }
            )

        logger.debug(f"Created {len(chunks)} chunks")

        # Show individual chunk details (limit for large files, similar to Rust version)
        max_chunks_to_show = 5
        for i, chunk in enumerate(chunks[:max_chunks_to_show]):
            logger.debug(f"  Chunk {i + 1}: {chunk['size']} bytes (SHA1: {chunk['checksum']})")
        if len(chunks) > max_chunks_to_show:
            logger.debug(f"  ... and {len(chunks) - max_chunks_to_show} more chunks")

        return chunks

    def _upload_chunks(self, org: str, chunks: list[Dict[str, Any]], target_checksums: list[str]) -> bool:
        """Upload chunks by checksum list."""
        chunk_map = {c["checksum"]: c for c in chunks}
        success = 0

        for checksum in target_checksums:
            if checksum not in chunk_map:
                logger.error(f"Chunk not found in map: {checksum}")
                continue

            if self._upload_chunk(org, chunk_map[checksum]):
                success += 1
                logger.debug(f"Uploaded chunk {success}/{len(target_checksums)}: {checksum}")

        logger.debug(f"Uploaded {success}/{len(target_checksums)} chunks successfully")
        return success == len(target_checksums)

    def _upload_chunk(self, org: str, chunk: Dict[str, Any]) -> bool:
        """Upload single chunk."""
        url = f"{self.base_url}/api/0/organizations/{org}/chunk-upload/"
        boundary = f"----FormBoundary{secrets.token_hex(16)}"

        # Create multipart body
        body = self._create_multipart_body(boundary, chunk["checksum"], chunk["data"])

        # For multipart, we need custom headers
        signature = hmac.new(self.shared_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers = {
            "Authorization": f"rpcsignature rpc0:{signature}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }

        try:
            response = self.session.post(url, data=body, headers=headers, timeout=60)

            success = response.status_code in [200, 201, 409]  # 409 = already exists
            if not success:
                logger.warning(f"Chunk upload failed: {response.status_code}")
            return success

        except Exception as e:
            logger.error(f"Chunk upload error: {e}")
            return False

    def _assemble_size_analysis(
        self,
        org: str | int,
        project: str | int,
        artifact_id: str | int,
        checksum: str,
        chunks: list[str],
    ) -> Dict[str, Any] | ErrorResult:
        """Call the assemble size analysis endpoint."""
        # Validate hex strings
        if not re.match(r"^[a-fA-F0-9]+$", checksum):
            raise ValueError("Invalid checksum format")
        for chunk in chunks:
            if not re.match(r"^[a-fA-F0-9]+$", chunk):
                raise ValueError("Invalid chunk format")

        data = {
            "checksum": checksum,
            "chunks": chunks,
            "assemble_type": "size_analysis",
        }

        endpoint = f"/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/assemble-generic/"
        return self._make_json_request("POST", endpoint, data, operation="Assemble request")

    def _create_multipart_body(self, boundary: str, filename: str, data: bytes) -> bytes:
        """Create multipart/form-data body."""
        lines = [
            f"--{boundary}",
            f'Content-Disposition: form-data; name="file"; filename="{filename}"',
            "Content-Type: application/octet-stream",
            "",
        ]

        parts = [
            "\r\n".join(lines).encode("utf-8"),
            b"\r\n",
            data,
            f"\r\n--{boundary}--\r\n".encode("utf-8"),
        ]

        return b"".join(parts)


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
