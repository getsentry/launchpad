"""Tests for retry logic in SentryClient."""

import hashlib
import io

from unittest.mock import patch

import pytest
import responses

from requests.exceptions import ConnectionError
from responses.matchers import json_params_matcher, multipart_matcher

from launchpad.constants import PreprodFeature
from launchpad.sentry_client import (
    RETRY_ATTEMPTS,
    ChunkOptionsResponse,
    SentryClient,
    SentryClientError,
    UpdateResponse,
)


def mock_chunk_options(org):
    responses.add(
        responses.GET,
        f"https://example.com/api/0/organizations/{org}/chunk-upload/",
        json={
            "url": "https://example.com/chunk",
            "chunkSize": 8 * 1024 * 1024,
            "chunksPerRequest": 64,
            "maxFileSize": 2**32,
            "maxRequestSize": 32 * 1024 * 1024,
            "concurrency": 8,
            "hashAlgorithm": "sha1",
            "compression": ["gzip"],
            "accept": ["preprod_artifacts"],
        },
    )


class TestSentryClientRetry:
    @responses.activate
    def test_get_chunk_upload_options(self):
        responses.add(
            responses.GET,
            "https://example.com/api/0/organizations/test-org/chunk-upload/",
            json={
                "url": "https://example.com/chunk",
                "chunkSize": 8 * 1024 * 1024,
                "chunksPerRequest": 64,
                "maxFileSize": 2**32,
                "maxRequestSize": 32 * 1024 * 1024,
                "concurrency": 8,
                "hashAlgorithm": "sha1",
                "compression": ["gzip"],
                "accept": ["preprod_artifacts"],
            },
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        response = client.get_chunk_upload_options("test-org")
        assert response == ChunkOptionsResponse(
            url="https://example.com/chunk",
            chunkSize=8 * 1024 * 1024,
            chunksPerRequest=64,
            maxFileSize=2**32,
            maxRequestSize=32 * 1024 * 1024,
            concurrency=8,
            hashAlgorithm="sha1",
            compression=["gzip"],
            accept=["preprod_artifacts"],
        )

    @responses.activate
    def test_get_chunk_upload_options_invalid_response(self):
        responses.add(
            responses.GET,
            "https://example.com/api/0/organizations/test-org/chunk-upload/",
            json={
                "badResult": True,
            },
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        with pytest.raises(SentryClientError):
            client.get_chunk_upload_options("test-org")

    @responses.activate
    def test_get_chunk_upload_options_error_response(self):
        responses.add(
            responses.GET,
            "https://example.com/api/0/organizations/test-org/chunk-upload/",
            status=500,
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        with pytest.raises(SentryClientError) as excinfo:
            client.get_chunk_upload_options("test-org")
        assert "500" in str(excinfo.value)

    @responses.activate
    def test_get_chunk_upload_options_invalid_response_with_error(self):
        responses.add(
            responses.GET,
            "https://example.com/api/0/organizations/test-org/chunk-upload/",
            status=400,
            json={
                "error": "specific error message",
            },
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        with pytest.raises(SentryClientError) as excinfo:
            client.get_chunk_upload_options("test-org")
        assert "specific error message" in str(excinfo.value)

    @responses.activate
    def test_update_artifact(self):
        responses.add(
            responses.PUT,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/update/",
            json={
                "success": True,
                "artifactId": "test-artifact",
                "updatedFields": ["version"],
            },
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        response = client.update_artifact("test-org", "test-project", "test-artifact", {"version": "1.0"})
        assert response == UpdateResponse(success=True, artifactId="test-artifact", updatedFields=["version"])

    @responses.activate
    def test_update_artifact_with_requested_features(self):
        """Test that requested features are parsed into PreprodFeature enums."""
        responses.add(
            responses.PUT,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/update/",
            json={
                "success": True,
                "artifactId": "test-artifact",
                "updatedFields": ["version"],
                "requestedFeatures": ["size_analysis", "build_distribution"],
            },
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        response = client.update_artifact("test-org", "test-project", "test-artifact", {"version": "1.0"})

        assert response.requested_features == [PreprodFeature.SIZE_ANALYSIS, PreprodFeature.BUILD_DISTRIBUTION]

    @responses.activate
    @patch("launchpad.sentry_client.sentry_sdk.capture_message")
    def test_update_artifact_with_unknown_feature(self, mock_capture_message):
        """Test that unknown features are captured to Sentry and skipped."""
        responses.add(
            responses.PUT,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/update/",
            json={
                "success": True,
                "artifactId": "test-artifact",
                "updatedFields": ["version"],
                "requestedFeatures": ["size_analysis", "unknown_feature", "build_distribution"],
            },
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        response = client.update_artifact("test-org", "test-project", "test-artifact", {"version": "1.0"})

        assert response.requested_features == [PreprodFeature.SIZE_ANALYSIS, PreprodFeature.BUILD_DISTRIBUTION]
        mock_capture_message.assert_called_once_with(
            "Unknown feature returned by server: unknown_feature", level="error"
        )

    @responses.activate
    def test_upload_installable_app_previously_uploaded(self):
        mock_chunk_options("some_org")
        responses.add(
            responses.POST,
            "https://example.com/api/0/internal/some_org/some_project/files/preprodartifacts/some_artifact_id/assemble-generic/",
            json={
                "missingChunks": [],
                "state": "ok",
            },
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")

        f = io.BytesIO(b"Hello, world!")
        client.upload_installable_app(
            "some_org",
            "some_project",
            "some_artifact_id",
            f,
        )

    @responses.activate
    def test_upload_installable_app_single_chunk(self):
        mock_chunk_options("some_org")
        sha1_of_hello_world = "943a702d06f34599aee1f8da8ef9f7296031d699"

        responses.add(
            responses.POST,
            "https://example.com/api/0/internal/some_org/some_project/files/preprodartifacts/some_artifact_id/assemble-generic/",
            json={
                "missingChunks": [sha1_of_hello_world],
                "state": "not_found",
            },
        )

        responses.add(
            responses.POST,
            "https://example.com/api/0/internal/some_org/some_project/files/preprodartifacts/some_artifact_id/assemble-generic/",
            json={
                "missingChunks": [],
                "state": "created",
            },
        )

        responses.add(
            responses.POST,
            "https://example.com/api/0/organizations/some_org/chunk-upload/",
            match=[
                multipart_matcher({"file": (sha1_of_hello_world, b"Hello, world!", "application/octet-stream")}),
            ],
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")

        f = io.BytesIO(b"Hello, world!")
        client.upload_installable_app(
            "some_org",
            "some_project",
            "some_artifact_id",
            f,
        )

    @responses.activate
    def test_upload_installable_app_multiple_chunks(self):
        first_chunk = b"A" * 8 * 1024 * 1024
        second_chunk = b"B"
        data = first_chunk + second_chunk

        first_chunk_sha1 = hashlib.sha1(first_chunk).hexdigest()
        second_chunk_sha1 = hashlib.sha1(second_chunk).hexdigest()
        total_sha1 = hashlib.sha1(data).hexdigest()

        mock_chunk_options("some_org")
        responses.add(
            responses.POST,
            "https://example.com/api/0/internal/some_org/some_project/files/preprodartifacts/some_artifact_id/assemble-generic/",
            match=[
                json_params_matcher(
                    {
                        "checksum": total_sha1,
                        "chunks": [first_chunk_sha1, second_chunk_sha1],
                        "assemble_type": "installable_app",
                    }
                ),
            ],
            json={
                "missingChunks": [first_chunk_sha1, second_chunk_sha1],
                "state": "not_found",
            },
        )
        responses.add(
            responses.POST,
            "https://example.com/api/0/internal/some_org/some_project/files/preprodartifacts/some_artifact_id/assemble-generic/",
            match=[
                json_params_matcher(
                    {
                        "checksum": total_sha1,
                        "chunks": [first_chunk_sha1, second_chunk_sha1],
                        "assemble_type": "installable_app",
                    }
                ),
            ],
            json={
                "missingChunks": [],
                "state": "created",
            },
        )

        part1 = responses.add(
            responses.POST,
            "https://example.com/api/0/organizations/some_org/chunk-upload/",
            match=[
                multipart_matcher({"file": (first_chunk_sha1, first_chunk, "application/octet-stream")}),
            ],
        )

        part2 = responses.add(
            responses.POST,
            "https://example.com/api/0/organizations/some_org/chunk-upload/",
            match=[
                multipart_matcher({"file": (second_chunk_sha1, second_chunk, "application/octet-stream")}),
            ],
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")

        f = io.BytesIO(data)
        client.upload_installable_app(
            "some_org",
            "some_project",
            "some_artifact_id",
            f,
        )

        assert part1.call_count == 1
        assert part2.call_count == 1

    @responses.activate
    def test_upload_installable_app_single_chunk_failure(self):
        mock_chunk_options("some_org")
        sha1_of_hello_world = "943a702d06f34599aee1f8da8ef9f7296031d699"

        responses.add(
            responses.POST,
            "https://example.com/api/0/internal/some_org/some_project/files/preprodartifacts/some_artifact_id/assemble-generic/",
            json={
                "missingChunks": [sha1_of_hello_world],
                "state": "not_found",
            },
        )

        upload = responses.add(
            responses.POST,
            "https://example.com/api/0/organizations/some_org/chunk-upload/",
            match=[
                multipart_matcher({"file": (sha1_of_hello_world, b"Hello, world!", "application/octet-stream")}),
            ],
            status=500,
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")

        f = io.BytesIO(b"Hello, world!")
        with pytest.raises(SentryClientError) as excinfo:
            client.upload_installable_app(
                "some_org",
                "some_project",
                "some_artifact_id",
                f,
            )
        assert "failed after 3 attempts" in str(excinfo.value)
        assert upload.call_count == 16

    @responses.activate
    def test_download_artifact_success(self):
        """Test successful download of artifact."""
        responses.add(
            responses.HEAD,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            headers={"Content-Length": "40"},
        )

        responses.add(
            responses.GET,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            body=b"A" * 20 + b"B" * 20,
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        out = io.BytesIO()

        result = client.download_artifact("test-org", "test-project", "test-artifact", out)

        assert result == 40
        out.seek(0)
        assert out.read() == b"A" * 20 + b"B" * 20

    @responses.activate
    def test_download_artifact_with_retry(self):
        """Test download with retry after connection error."""
        responses.add(
            responses.HEAD,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            headers={"Content-Length": "13"},
        )

        responses.add(
            responses.GET,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            body=ConnectionError("Connection failed"),
        )

        responses.add(
            responses.GET,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            body=b"Hello, world!",
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        out = io.BytesIO()

        result = client.download_artifact("test-org", "test-project", "test-artifact", out)

        assert result == 13
        out.seek(0)
        assert out.read() == b"Hello, world!"

    @responses.activate
    def test_download_artifact_resumable(self):
        """Test download retry behavior (full restart, not true resumable)."""
        responses.add(
            responses.HEAD,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            headers={"Content-Length": "26"},
        )

        responses.add(
            responses.GET,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            body=ConnectionError("Connection lost"),
        )

        responses.add(
            responses.GET,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            body=b"Hello, world! How are you?",
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        out = io.BytesIO()

        result = client.download_artifact("test-org", "test-project", "test-artifact", out)

        assert result == 26
        out.seek(0)
        assert out.read() == b"Hello, world! How are you?"

    @responses.activate
    def test_download_artifact_http_error(self):
        """Test download with HTTP error response."""
        responses.add(
            responses.HEAD,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            headers={"Content-Length": "13"},
        )

        responses.add(
            responses.GET,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            status=404,
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        out = io.BytesIO()

        with pytest.raises(SentryClientError):
            client.download_artifact("test-org", "test-project", "test-artifact", out)

    @responses.activate
    def test_download_artifact_max_retries_exceeded(self):
        """Test download fails after maximum retries."""
        responses.add(
            responses.HEAD,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            headers={"Content-Length": "13"},
        )

        for _ in range(RETRY_ATTEMPTS):
            responses.add(
                responses.GET,
                "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
                body=ConnectionError("Connection failed"),
            )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        out = io.BytesIO()

        with pytest.raises(SentryClientError) as excinfo:
            client.download_artifact("test-org", "test-project", "test-artifact", out)

        assert "Download failed after retries" in str(excinfo.value)

    @responses.activate
    def test_download_artifact_handles_416_range_not_satisfiable(self):
        """Test download handles 416 Range Not Satisfiable by restarting from beginning."""
        responses.add(
            responses.HEAD,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            headers={"Content-Length": "13"},
        )

        # First request returns 416, second succeeds
        responses.add(
            responses.GET,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            status=416,
        )
        responses.add(
            responses.GET,
            "https://example.com/api/0/internal/test-org/test-project/files/preprodartifacts/test-artifact/",
            body="Hello, world!",
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        out = io.BytesIO()
        out.write(b"partial")  # Simulate partial download
        out.seek(0, io.SEEK_END)

        result = client.download_artifact("test-org", "test-project", "test-artifact", out)

        assert result == 13
        out.seek(0)
        assert out.read() == b"Hello, world!"
