"""Client for making authenticated API calls to the Sentry monolith."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os

from typing import Any, Dict, Optional, TypeVar

import requests

from pydantic import BaseModel, ConfigDict, ValidationError
from pydantic.alias_generators import to_camel
from requests.adapters import HTTPAdapter
from requests.auth import AuthBase
from requests.exceptions import ChunkedEncodingError, ConnectionError, ContentDecodingError, JSONDecodeError, Timeout
from urllib3.util.retry import Retry

from launchpad.api.update_api_models import PutSize

logger = logging.getLogger(__name__)

ResponseModel = TypeVar("ResponseModel", bound=BaseModel)


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


class SentryClientError(Exception):
    def __init__(self, response=None, exception=None, detail=None):
        super().__init__(response, exception, detail)
        self.response = response
        self.exception = exception
        self.detail = detail

    def __str__(self):
        message = "SentryClientError:"
        if self.detail:
            message += f" {self.detail}"
        if self.exception is not None:
            message += f"\n  caused by: {self.exception}"
        if self.response is not None:
            message += f"\n  sentry response: {self.response}"
            try:
                error = self.response.json().get("error", None)
                if error:
                    message += f"\n  error message: {error}"
            except JSONDecodeError:
                pass
        return message

    def user_facing_message(self) -> str:
        return "Internal error"


class UpdateResponse(BaseModel):
    model_config = ConfigDict(strict=True, alias_generator=to_camel)
    success: bool
    artifact_id: str
    updated_fields: list[str]


class PutSizeResponse(BaseModel):
    model_config = ConfigDict(strict=True, alias_generator=to_camel)
    artifact_id: str


class ChunkOptionsResponse(BaseModel):
    model_config = ConfigDict(strict=True, alias_generator=to_camel)
    url: str
    chunk_size: int
    chunks_per_request: int
    max_file_size: int
    max_request_size: int
    concurrency: int
    hash_algorithm: str
    compression: list[str]
    accept: list[str]


class AssembleResponse(BaseModel):
    model_config = ConfigDict(strict=True, alias_generator=to_camel)
    state: str
    missing_chunks: list[str]
    detail: Optional[str] = None


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
    session: requests.Session

    def __init__(self, base_url: str, shared_secret: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        if not shared_secret:
            shared_secret = os.getenv("LAUNCHPAD_RPC_SHARED_SECRET")
        if not shared_secret:
            raise RuntimeError("LAUNCHPAD_RPC_SHARED_SECRET must be provided or set as environment variable")
        self.auth = Rpc0Auth(shared_secret)
        self.session = create_retry_session()

    def download_artifact_to_file(self, org: str, project: str, artifact_id: str, out: io.BytesIO) -> int:
        """Download preprod artifact directly to a file-like object.

        Args:
            org: Organization slug
            project: Project slug
            artifact_id: Artifact ID
            out: File-like object to write to (must support write() method)

        Returns:
            Number of bytes written on success
        """
        endpoint = f"/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/"
        url = self._build_url(endpoint)
        file_size = 0

        attempts = 3
        for attempt in range(attempts):
            try:
                response = self.session.get(url, auth=self.auth, timeout=120, stream=True)
                if response.status_code != 200:
                    raise SentryClientError(response=response)
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        out.write(chunk)
                        file_size += len(chunk)
                        if file_size > 5 * 1024 * 1024 * 1024:
                            raise SentryClientError(
                                detail="Failed to download artifact: File size exceeds 5GB limit",
                                response=response,
                            )
                break
            except (ConnectionError, Timeout, ChunkedEncodingError, ContentDecodingError) as e:
                if attempt == 0:
                    logger.warning(f"Download failed due to network error ({attempt + 1}/{attempts})", exc_info=True)
                else:
                    logger.exception(f"Download failed after {attempts} attempts due to network error")
                    raise SentryClientError(
                        detail="Failed to download artifact (network error)", response=response, exception=e
                    )

            # Restart download from the beginning (endpoint does not
            # currently support Range header).
            out.seek(0)
            out.truncate()  # Clear any partial data from failed download
            file_size = 0

        out.flush()
        return file_size

    def update_artifact(self, org: str, project: str, artifact_id: str, data: Dict[str, Any]) -> UpdateResponse:
        """Update preprod artifact."""
        endpoint = f"/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/update/"
        return self._make_json_request("PUT", endpoint, UpdateResponse, data=data)

    def upload_size_analysis_file(
        self,
        org: str,
        project: str,
        artifact_id: str,
        file: io.BytesIO,
        max_retries: int = 3,
    ) -> None:
        """Upload size analysis file with chunking following Rust sentry-cli pattern."""
        return self._upload_file_with_assembly(
            org=org,
            project=project,
            artifact_id=artifact_id,
            file=file,
            max_retries=max_retries,
            assemble_type="size_analysis",
        )

    def update_size_analysis(
        self, org: str, project: str, artifact_id: str, data: PutSize, identifier: str | None = None
    ) -> PutSizeResponse:
        if identifier:
            endpoint = f"/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/size/{identifier}/"
        else:
            endpoint = f"/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/size/"
        return self._make_json_request("PUT", endpoint, PutSizeResponse, data=data.model_dump())

    def upload_installable_app(
        self,
        org: str,
        project: str,
        artifact_id: str,
        file: str | io.BytesIO,
        max_retries: int = 3,
    ) -> None:
        """Upload installable app file with chunking following Rust sentry-cli pattern."""

        return self._upload_file_with_assembly(
            org=org,
            project=project,
            artifact_id=artifact_id,
            file=file,
            max_retries=max_retries,
            assemble_type="installable_app",
        )

    def _upload_file_with_assembly(
        self,
        org: str,
        project: str,
        artifact_id: str,
        file: io.BytesIO,
        max_retries: int,
        assemble_type: str,
    ):
        """Upload file with chunking and assembly."""

        options = self.get_chunk_upload_options(org)
        logger.debug(f"Server chunk config: {options}")

        chunk_size = options.chunk_size

        checksum = hashlib.file_digest(file, "sha1").hexdigest()
        size = file.tell()
        file.seek(0)

        chunks = []
        while True:
            chunk_bytes = read_exactly(file, chunk_size)
            if not chunk_bytes:
                break
            chunks.append(hashlib.sha1(chunk_bytes).hexdigest())
        file.seek(0)
        logger.info(f"File prepared: SHA1={checksum} size={size} chunks={len(chunks)}")

        for attempt in range(max_retries + 1):
            logger.debug(f"Assembly attempt {attempt}/{max_retries + 1}")
            data = {
                "checksum": checksum,
                "chunks": chunks,
                "assemble_type": assemble_type,
            }
            endpoint = f"/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/assemble-generic/"

            try:
                result = self._make_json_request("POST", endpoint, AssembleResponse, data=data)
            except SentryClientError:
                logger.warning(f"Assembly attempt {attempt + 1}", exc_info=True)
                continue

            if result.state in ["ok", "created"]:
                return

            for index, checksum in enumerate(chunks):
                if checksum in result.missing_chunks:
                    file.seek(chunk_size * index)
                    chunk_data = read_exactly(file, chunk_size)
                    self.upload_chunk(org, chunk_data)

        raise SentryClientError(detail=f"failed after {max_retries} attempts")

    def _build_url(self, endpoint: str) -> str:
        """Build full URL from endpoint."""
        return f"{self.base_url}{endpoint}"

    def _make_json_request(
        self,
        method: str,
        endpoint: str,
        model: ResponseModel,
        data: Dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> ResponseModel:
        """Make a JSON request with standard error handling."""
        url = self._build_url(endpoint)
        body = json.dumps(data).encode("utf-8") if data else b""

        logger.debug(f"{method} {url}")
        response = self.session.request(
            method=method,
            url=url,
            data=body or None,
            auth=self.auth,
            timeout=timeout,
        )

        if response.status_code == 200:
            try:
                j = response.json()
                return model.model_validate(j)
            except JSONDecodeError as exception:
                raise SentryClientError(response=response, exception=exception)
            except ValidationError as exception:
                raise SentryClientError(response=response, exception=exception)
        else:
            raise SentryClientError(response=response)

    def get_chunk_upload_options(self, org: str) -> ChunkOptionsResponse:
        """Get chunk upload configuration from server."""
        endpoint = f"/api/0/organizations/{org}/chunk-upload/"
        return self._make_json_request("GET", endpoint, ChunkOptionsResponse)

    def upload_chunk(self, org: str, chunk: bytes) -> bool:
        """Upload a single chunk."""

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
