import uuid

from contextlib import contextmanager
from contextvars import ContextVar

_request_id: ContextVar[str | None] = ContextVar("request_id")
_artifact_id: ContextVar[str | None] = ContextVar("artifact_id")


@contextmanager
def request_context(artifact_id: str | None = None):
    """Create a request context with a unique request_id and stamp the artifact_id onto every log record."""
    request_token = _request_id.set(str(uuid.uuid4()))
    artifact_token = _artifact_id.set(artifact_id)
    try:
        yield
    finally:
        _artifact_id.reset(artifact_token)
        _request_id.reset(request_token)


def current_request_id() -> str | None:
    return _request_id.get(None)


def bind_request_id(request_id: str) -> None:
    _request_id.set(request_id)


def current_artifact_id() -> str | None:
    return _artifact_id.get(None)


def bind_artifact_id(artifact_id: str) -> None:
    _artifact_id.set(artifact_id)


class RequestLogFilter:
    """Logging filter that adds request_id and artifact_id to log records."""

    def filter(self, record) -> bool:
        try:
            record.request_id = _request_id.get()
        except LookupError:
            pass
        artifact_id = _artifact_id.get(None)
        if artifact_id is not None:
            record.artifact_id = artifact_id
        return True
