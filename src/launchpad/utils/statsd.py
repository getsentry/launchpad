import os

from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any, Literal

from datadog.dogstatsd.base import DogStatsd

# There are a few weird issues with DataDog documented in other Sentry repos.
# See:
# - https://github.com/getsentry/sentry/blob/81e1b8694f2ab3a63ecab3accf9911cc97accbb0/src/sentry/metrics/dogstatsd.py#L30
# - https://github.com/getsentry/seer/blob/992299aa44ce744366fe1be0c20b11d99987fa1d/src/seer/fastapi_app.py#L33
# - https://github.com/DataDog/datadogpy/issues/764
# Minimize these by:
# - turning off the problem features
# - not using the global initialize() and statsd instances.


OK = DogStatsd.OK
WARNING = DogStatsd.WARNING
CRITICAL = DogStatsd.CRITICAL
UNKNOWN = DogStatsd.UNKNOWN


class StatsdInterface(ABC):
    @abstractmethod
    def increment(self, metric: str, value: int = 1, tags: list[str] | None = None) -> None:
        pass

    @abstractmethod
    def gauge(self, metric: str, value: float, tags: list[str] | None = None) -> None:
        pass

    @abstractmethod
    def timing(self, metric: str, value: float, tags: list[str] | None = None) -> None:
        pass

    @abstractmethod
    def service_check(
        self,
        name: str,
        status: int,
        tags: list[str] | None = None,
        hostname: str | None = None,
        message: str | None = None,
    ) -> None:
        pass

    @abstractmethod
    @contextmanager
    def timed(self, metric: str, tags: list[str] | None = None) -> Any:
        pass


class NullStatsd(StatsdInterface):
    def increment(self, metric: str, value: int = 1, tags: list[str] | None = None) -> None:
        pass

    def gauge(self, metric: str, value: float, tags: list[str] | None = None) -> None:
        pass

    def timing(self, metric: str, value: float, tags: list[str] | None = None) -> None:
        pass

    def service_check(
        self,
        name: str,
        status: int,
        tags: list[str] | None = None,
        hostname: str | None = None,
        message: str | None = None,
    ) -> None:
        pass

    @contextmanager
    def timed(self, metric: str, tags: list[str] | None = None) -> Any:
        yield


class FakeStatsd(StatsdInterface):
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def increment(self, metric: str, value: int = 1, tags: list[str] | None = None) -> None:
        self.calls.append(("increment", {"metric": metric, "value": value, "tags": tags}))

    def gauge(self, metric: str, value: float, tags: list[str] | None = None) -> None:
        self.calls.append(("gauge", {"metric": metric, "value": value, "tags": tags}))

    def timing(self, metric: str, value: float, tags: list[str] | None = None) -> None:
        self.calls.append(("timing", {"metric": metric, "value": value, "tags": tags}))

    def service_check(
        self,
        name: str,
        status: int,
        tags: list[str] | None = None,
        hostname: str | None = None,
        message: str | None = None,
    ) -> None:
        self.calls.append(
            ("service_check", {"name": name, "status": status, "tags": tags, "hostname": hostname, "message": message})
        )

    @contextmanager
    def timed(self, metric: str, tags: list[str] | None = None) -> Any:
        self.calls.append(("timed", {"metric": metric, "tags": tags}))
        yield


class DogStatsdWrapper(StatsdInterface):
    def __init__(self, dogstatsd: DogStatsd):
        self._dogstatsd = dogstatsd

    def increment(self, metric: str, value: int = 1, tags: list[str] | None = None) -> None:
        self._dogstatsd.increment(metric, value, tags)

    def gauge(self, metric: str, value: float, tags: list[str] | None = None) -> None:
        self._dogstatsd.gauge(metric, value, tags)

    def timing(self, metric: str, value: float, tags: list[str] | None = None) -> None:
        self._dogstatsd.timing(metric, value, tags)

    def service_check(
        self,
        name: str,
        status: int,
        tags: list[str] | None = None,
        hostname: str | None = None,
        message: str | None = None,
    ) -> None:
        self._dogstatsd.service_check(name, status, tags, hostname, message)

    @contextmanager
    def timed(self, metric: str, tags: list[str] | None = None) -> Any:
        with self._dogstatsd.timed(metric, tags):
            yield


def create_dogstatsd_client(namespace: str) -> DogStatsd:
    host = os.getenv("STATSD_HOST", "127.0.0.1")
    port_str = os.getenv("STATSD_PORT", "8125")
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"STATSD_PORT must be a valid integer, got: {port_str}")
    return DogStatsd(
        host=host,
        port=port,
        namespace=namespace,
        disable_telemetry=True,
        origin_detection_enabled=False,
    )


_namespace_to_statsd: dict[str, StatsdInterface] = {}


def get_statsd(namespace_suffix: Literal[None, "consumer"] = None) -> StatsdInterface:
    namespace = f"launchpad.{namespace_suffix}" if namespace_suffix else "launchpad"

    if namespace in _namespace_to_statsd:
        return _namespace_to_statsd[namespace]

    wrapper = DogStatsdWrapper(create_dogstatsd_client(namespace))
    _namespace_to_statsd[namespace] = wrapper
    return wrapper
