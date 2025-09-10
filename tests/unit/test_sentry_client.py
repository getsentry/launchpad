"""Tests for retry logic in SentryClient."""

import hashlib
import io

import pytest
import responses

from responses.matchers import multipart_matcher

from launchpad.sentry_client import (
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
                "artifact_id": "test-artifact",
                "updated_fields": ["version"],
            },
        )

        client = SentryClient(base_url="https://example.com", shared_secret="password")
        response = client.update_artifact("test-org", "test-project", "test-artifact", {"version": "1.0"})
        assert response == UpdateResponse(success=True, artifact_id="test-artifact", updated_fields=["version"])

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
        first_chunk_sha1 = hashlib.sha1(first_chunk).hexdigest()
        second_chunk_sha1 = hashlib.sha1(second_chunk).hexdigest()
        data = first_chunk + second_chunk

        mock_chunk_options("some_org")
        responses.add(
            responses.POST,
            "https://example.com/api/0/internal/some_org/some_project/files/preprodartifacts/some_artifact_id/assemble-generic/",
            json={
                "missingChunks": [first_chunk_sha1, second_chunk_sha1],
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
        # We assemble once to find out the missing chunks
        # We then retry the assemble 3 times uploading any missing chunks
        # Each request can itself be retried 3 times
        # So (1*3)*4 = 16
        assert upload.call_count == 16
