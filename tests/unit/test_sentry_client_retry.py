"""Tests for retry logic in SentryClient."""

import hashlib
import io

from unittest.mock import Mock, patch

import requests
import responses

from requests.adapters import HTTPAdapter
from responses.matchers import multipart_matcher
from urllib3.util.retry import Retry

from launchpad.sentry_client import SentryClient, create_retry_session


class TestSentryClientRetry:
    """Test retry logic in SentryClient."""

    def setup_method(self):
        """Set up test fixtures."""
        with patch.dict("os.environ", {"LAUNCHPAD_RPC_SHARED_SECRET": "test_secret"}):
            self.client = SentryClient(base_url="https://example.com")

    def test_create_retry_session_configuration(self):
        """Test that create_retry_session creates a session with correct retry configuration."""
        session = create_retry_session(max_retries=5)

        # Check that session has the right type
        assert isinstance(session, requests.Session)

        # Check that the session has adapters mounted
        assert "http://" in session.adapters
        assert "https://" in session.adapters

        # Check that adapters are HTTPAdapter instances
        http_adapter = session.adapters["http://"]
        https_adapter = session.adapters["https://"]
        assert isinstance(http_adapter, HTTPAdapter)
        assert isinstance(https_adapter, HTTPAdapter)

        # Check that the retry strategy is configured
        assert http_adapter.max_retries.total == 5
        assert https_adapter.max_retries.total == 5

    def test_create_retry_session_default_retries(self):
        """Test that create_retry_session uses default retry count."""
        session = create_retry_session()

        http_adapter = session.adapters["http://"]
        assert http_adapter.max_retries.total == 3

    def test_sentry_client_uses_retry_session(self):
        """Test that SentryClient uses a retry session."""
        with patch.dict("os.environ", {"LAUNCHPAD_RPC_SHARED_SECRET": "test_secret"}):
            client = SentryClient(base_url="https://example.com")

            # Check that the client has a session
            assert hasattr(client, "session")
            assert isinstance(client.session, requests.Session)

            # Check that the session has retry adapters
            assert "http://" in client.session.adapters
            assert "https://" in client.session.adapters
            assert isinstance(client.session.adapters["http://"], HTTPAdapter)

    @patch("launchpad.sentry_client.requests.Session")
    def test_download_artifact_to_file_with_retry_session(self, mock_session_class):
        """Test that download_artifact_to_file uses the retry session."""
        # Mock the session and its methods
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.iter_content.return_value = [b"test content"]
        mock_response.headers = {"Content-Length": "12", "Content-Type": "application/octet-stream"}
        mock_session.get.return_value = mock_response

        # Create client with mocked session
        with patch.dict("os.environ", {"LAUNCHPAD_RPC_SHARED_SECRET": "test_secret"}):
            client = SentryClient(base_url="https://example.com")
            client.session = mock_session

        # Mock file object
        mock_file = Mock()
        result = client.download_artifact_to_file("test-org", "test-project", "test-artifact", mock_file)

        assert result == 12  # Length of "test content"
        assert mock_session.get.called
        mock_file.write.assert_called_with(b"test content")

    @patch("launchpad.sentry_client.requests.Session")
    def test_update_artifact_with_retry_session(self, mock_session_class):
        """Test that update_artifact uses the retry session."""
        # Mock the session and its methods
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        mock_session.request.return_value = mock_response

        # Create client with mocked session
        with patch.dict("os.environ", {"LAUNCHPAD_RPC_SHARED_SECRET": "test_secret"}):
            client = SentryClient(base_url="https://example.com")
            client.session = mock_session

        result = client.update_artifact("test-org", "test-project", "test-artifact", {"version": "1.0"})

        assert result == {"success": True}
        assert mock_session.request.called

    def test_retry_strategy_configuration(self):
        """Test that the retry strategy is configured correctly."""
        session = create_retry_session()
        adapter = session.adapters["https://"]
        retry_strategy = adapter.max_retries

        # Check retry configuration
        assert isinstance(retry_strategy, Retry)
        assert retry_strategy.total == 3
        assert retry_strategy.backoff_factor == 0.1
        assert retry_strategy.status_forcelist == [429, 500, 502, 503, 504]
        assert retry_strategy.raise_on_status is False

        # Check allowed methods
        expected_methods = ["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        assert retry_strategy.allowed_methods == expected_methods

    def test_retry_strategy_custom_max_retries(self):
        """Test that custom max retries is applied correctly."""
        session = create_retry_session(max_retries=5)
        adapter = session.adapters["https://"]
        retry_strategy = adapter.max_retries

        assert retry_strategy.total == 5

    @patch("launchpad.sentry_client.requests.Session")
    def test_json_request_uses_session(self, mock_session_class):
        """Test that _make_json_request uses the retry session."""
        # Mock the session and its methods
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "success"}
        mock_session.request.return_value = mock_response

        # Create client with mocked session
        with patch.dict("os.environ", {"LAUNCHPAD_RPC_SHARED_SECRET": "test_secret"}):
            client = SentryClient(base_url="https://example.com")
            client.session = mock_session

        result = client._make_json_request("POST", "/test", {"key": "value"})

        assert result == {"result": "success"}
        assert mock_session.request.called

        # Verify the call was made with correct parameters
        call_args = mock_session.request.call_args
        assert call_args[1]["method"] == "POST"
        assert "example.com/test" in call_args[1]["url"]


@responses.activate
def test_upload_installable_app_single_chunk():
    responses.add(
        responses.GET,
        "https://example.com/api/0/organizations/some_org/chunk-upload/",
        json={},
    )
    responses.add(
        responses.POST,
        "https://example.com/api/0/internal/some_org/some_project/files/preprodartifacts/some_artifact_id/assemble-generic/",
        json={},
    )

    sha1_of_hello_world = "943a702d06f34599aee1f8da8ef9f7296031d699"

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
def test_upload_installable_app_multiple_chunks():
    responses.add(
        responses.GET,
        "https://example.com/api/0/organizations/some_org/chunk-upload/",
        json={},
    )
    responses.add(
        responses.POST,
        "https://example.com/api/0/internal/some_org/some_project/files/preprodartifacts/some_artifact_id/assemble-generic/",
        json={},
    )

    first_chunk = b"A" * 8 * 1024 * 1024
    second_chunk = b"B"
    first_chunk_sha1 = hashlib.sha1(first_chunk).hexdigest()
    second_chunk_sha1 = hashlib.sha1(second_chunk).hexdigest()
    data = first_chunk + second_chunk

    responses.add(
        responses.POST,
        "https://example.com/api/0/organizations/some_org/chunk-upload/",
        match=[
            multipart_matcher({"file": (first_chunk_sha1, first_chunk, "application/octet-stream")}),
        ],
    )

    responses.add(
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
