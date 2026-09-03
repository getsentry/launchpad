import uuid

from contextlib import contextmanager
from contextvars import ContextVar

_request_id: ContextVar[str | None] = ContextVar("request_id")
_log_fields: ContextVar[dict[str, str]] = ContextVar("log_fields")


@contextmanager
def request_context():
    """Create a request context with a unique request_id."""
    request_id = str(uuid.uuid4())
    token = _request_id.set(request_id)
    try:
        yield
    finally:
        _request_id.reset(token)


def current_request_id() -> str | None:
    return _request_id.get(None)


def bind_request_id(request_id: str) -> None:
    _request_id.set(request_id)


@contextmanager
def log_context(**fields: str):
    """Attach structured fields (e.g. artifact_id) to every log record emitted within the block."""
    token = _log_fields.set({**_log_fields.get({}), **fields})
    try:
        yield
    finally:
        _log_fields.reset(token)


def current_log_fields() -> dict[str, str]:
    return _log_fields.get({})


def bind_log_fields(fields: dict[str, str]) -> None:
    _log_fields.set(fields)


class RequestLogFilter:
    """Logging filter that adds request_id and log_context fields to log records."""

    def filter(self, record) -> bool:
        for key, value in _log_fields.get({}).items():
            setattr(record, key, value)
        try:
            record.request_id = _request_id.get()
        except LookupError:
            pass
        return True
