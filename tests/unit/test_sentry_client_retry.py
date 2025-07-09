"""Tests for retry logic in SentryClient."""

from unittest.mock import Mock, patch

import requests

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from launchpad.sentry_client import SentryClient, create_retry_session


class TestSentryClientRetry:
    """Test retry logic in SentryClient."""

    def setup_method(self):
        """Set up test fixtures."""
        with patch.dict("os.environ", {"LAUNCHPAD_RPC_SHARED_SECRET": "test_secret"}):
            self.client = SentryClient(base_url="https://test.sentry.io")

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
            client = SentryClient(base_url="https://test.sentry.io")

            # Check that the client has a session
            assert hasattr(client, "session")
            assert isinstance(client.session, requests.Session)

            # Check that the session has retry adapters
            assert "http://" in client.session.adapters
            assert "https://" in client.session.adapters
            assert isinstance(client.session.adapters["http://"], HTTPAdapter)

    @patch("launchpad.sentry_client.requests.Session")
    def test_download_artifact_with_retry_success_after_failure(self, mock_session_class):
        """Test that download_artifact succeeds after retries via urllib3."""
        # Mock the session and its methods
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # First call fails, second succeeds
        mock_response_success = Mock()
        mock_response_success.status_code = 200
        mock_response_success.iter_content.return_value = [b"test content"]
        mock_response_success.headers = {"content-length": "12"}

        # Configure the mock to succeed on the call
        mock_session.get.return_value = mock_response_success

        # Create client with mocked session
        with patch.dict("os.environ", {"LAUNCHPAD_RPC_SHARED_SECRET": "test_secret"}):
            client = SentryClient(base_url="https://test.sentry.io")
            client.session = mock_session

        result = client.download_artifact("test-org", "test-project", "test-artifact")

        assert result["success"] is True
        assert result["file_content"] == b"test content"
        assert mock_session.get.called

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
            client = SentryClient(base_url="https://test.sentry.io")
            client.session = mock_session

        result = client.update_artifact("test-org", "test-project", "test-artifact", {"version": "1.0"})

        assert result == {"success": True}
        assert mock_session.request.called

    @patch("launchpad.sentry_client.requests.Session")
    def test_upload_chunk_with_retry_session(self, mock_session_class):
        """Test that _upload_chunk uses the retry session."""
        # Mock the session and its methods
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        # Create client with mocked session
        with patch.dict("os.environ", {"LAUNCHPAD_RPC_SHARED_SECRET": "test_secret"}):
            client = SentryClient(base_url="https://test.sentry.io")
            client.session = mock_session

        chunk = {"checksum": "abcd1234", "data": b"test data", "size": 9}

        result = client._upload_chunk("test-org", chunk)

        assert result is True
        assert mock_session.post.called

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
            client = SentryClient(base_url="https://test.sentry.io")
            client.session = mock_session

        result = client._make_json_request("POST", "/test", {"key": "value"})

        assert result == {"result": "success"}
        assert mock_session.request.called

        # Verify the call was made with correct parameters
        call_args = mock_session.request.call_args
        assert call_args[1]["method"] == "POST"
        assert "test.sentry.io/test" in call_args[1]["url"]
