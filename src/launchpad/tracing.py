import uuid

from contextlib import contextmanager
from contextvars import ContextVar

_request_id: ContextVar[str | None] = ContextVar("request_id")


@contextmanager
def request_context():
    """Create a request context with a unique request_id."""
    request_id = str(uuid.uuid4())
    token = _request_id.set(request_id)
    try:
        yield
    finally:
        _request_id.reset(token)


class RequestLogFilter:
    """Logging filter that adds request_id to log records.."""

    def filter(self, record) -> bool:
        try:
            request_id = _request_id.get()
            record.request_id = request_id
        except LookupError:
            pass
        return True
