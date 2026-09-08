import uuid

from contextlib import contextmanager
from contextvars import ContextVar

_request_id: ContextVar[str | None] = ContextVar("request_id")
_log_fields: ContextVar[dict[str, str]] = ContextVar("log_fields")


@contextmanager
def request_context(**fields: str):
    """Create a request context with a unique request_id and stamp the given fields onto every log record."""
    request_token = _request_id.set(str(uuid.uuid4()))
    fields_token = _log_fields.set(fields)
    try:
        yield
    finally:
        _log_fields.reset(fields_token)
        _request_id.reset(request_token)


def current_request_id() -> str | None:
    return _request_id.get(None)


def bind_request_id(request_id: str) -> None:
    _request_id.set(request_id)


def current_log_fields() -> dict[str, str]:
    return _log_fields.get({})


def bind_log_fields(fields: dict[str, str]) -> None:
    _log_fields.set(fields)


class RequestLogFilter:
    """Logging filter that adds request_id and request_context fields to log records."""

    def filter(self, record) -> bool:
        for key, value in _log_fields.get({}).items():
            setattr(record, key, value)
        try:
            record.request_id = _request_id.get()
        except LookupError:
            pass
        return True
