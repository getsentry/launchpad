"""Tests for service error handling."""

import pytest

from launchpad.service import _categorize_http_error


class TestErrorCategorization:
    """Test the HTTP error categorization function."""

    def test_categorize_with_structured_status_code(self):
        """Test error categorization using structured status code."""
        # Test 404 not found
        error_result = {"error": "HTTP 404", "status_code": 404}
        category, description = _categorize_http_error(error_result)
        assert category == "not_found"
        assert "Resource not found (HTTP 404)" in description

        # Test 500 server error
        error_result = {"error": "HTTP 500", "status_code": 500}
        category, description = _categorize_http_error(error_result)
        assert category == "server_error"
        assert "Server error (HTTP 500)" in description

        # Test 502 server error
        error_result = {"error": "HTTP 502", "status_code": 502}
        category, description = _categorize_http_error(error_result)
        assert category == "server_error"
        assert "Server error (HTTP 502)" in description

        # Test 401 client error
        error_result = {"error": "HTTP 401", "status_code": 401}
        category, description = _categorize_http_error(error_result)
        assert category == "client_error"
        assert "Client error (HTTP 401)" in description

        # Test 403 client error
        error_result = {"error": "HTTP 403", "status_code": 403}
        category, description = _categorize_http_error(error_result)
        assert category == "client_error"
        assert "Client error (HTTP 403)" in description

        # Test unusual status code
        error_result = {"error": "HTTP 299", "status_code": 299}
        category, description = _categorize_http_error(error_result)
        assert category == "unknown"
        assert "Unexpected HTTP status 299" in description

    def test_categorize_with_string_parsing_fallback(self):
        """Test error categorization using string parsing fallback."""
        # Test 404 not found (no status_code field)
        error_result = {"error": "HTTP 404"}
        category, description = _categorize_http_error(error_result)
        assert category == "not_found"
        assert "Resource not found (HTTP 404)" in description

        # Test 500 server error
        error_result = {"error": "HTTP 500"}
        category, description = _categorize_http_error(error_result)
        assert category == "server_error"
        assert "Server error (HTTP 500)" in description

        # Test 503 server error
        error_result = {"error": "HTTP 503"}
        category, description = _categorize_http_error(error_result)
        assert category == "server_error"
        assert "Server error (HTTP 503)" in description

        # Test 400 client error
        error_result = {"error": "HTTP 400"}
        category, description = _categorize_http_error(error_result)
        assert category == "client_error"
        assert "Client error (HTTP 400)" in description

    def test_categorize_with_malformed_input(self):
        """Test error categorization with malformed input."""
        # Test missing fields
        error_result = {}
        category, description = _categorize_http_error(error_result)
        assert category == "unknown"
        assert "Unknown error" in description

        # Test non-integer status code
        error_result = {"error": "HTTP 404", "status_code": "404"}
        category, description = _categorize_http_error(error_result)
        assert category == "not_found"  # Should fall back to string parsing
        assert "Resource not found (HTTP 404)" in description

        # Test non-HTTP error message
        error_result = {"error": "Connection timeout"}
        category, description = _categorize_http_error(error_result)
        assert category == "unknown"
        assert "Unknown error" in description

        # Test malformed HTTP error message
        error_result = {"error": "HTTP abc"}
        category, description = _categorize_http_error(error_result)
        assert category == "unknown"
        assert "Unknown error" in description
