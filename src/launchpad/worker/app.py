import os
import resource
import time

from collections.abc import Generator
from contextlib import contextmanager

from arroyo.backends.kafka import KafkaProducer
from datadog.dogstatsd.base import DogStatsd
from taskbroker_client.app import TaskbrokerApp
from taskbroker_client.metrics import MetricsBackend, Tags
from taskbroker_client.router import TaskRouter


def _convert_tags(tags: Tags | None) -> list[str] | None:
    if tags is None:
        return None
    return [f"{k}:{v}" for k, v in tags.items()]


class DatadogMetricsBackend(MetricsBackend):
    def __init__(self) -> None:
        host = os.getenv("STATSD_HOST", "127.0.0.1")
        port_str = os.getenv("STATSD_PORT", "8125")
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"STATSD_PORT must be a valid integer, got: {port_str}")

        self._dogstatsd = DogStatsd(
            host=host,
            port=port,
            namespace="launchpad.taskworker",
            disable_telemetry=True,
            origin_detection_enabled=False,
        )

    def incr(
        self,
        name: str,
        value: int | float = 1,
        tags: Tags | None = None,
        sample_rate: float | None = None,
    ) -> None:
        kwargs: dict = {"tags": _convert_tags(tags)}
        if sample_rate is not None:
            kwargs["sample_rate"] = sample_rate
        self._dogstatsd.increment(name, int(value), **kwargs)

    def distribution(
        self,
        name: str,
        value: int | float,
        tags: Tags | None = None,
        unit: str | None = None,
        sample_rate: float | None = None,
    ) -> None:
        kwargs: dict = {"tags": _convert_tags(tags)}
        if sample_rate is not None:
            kwargs["sample_rate"] = sample_rate
        self._dogstatsd.distribution(name, value, **kwargs)

    @contextmanager
    def timer(
        self,
        key: str,
        tags: Tags | None = None,
        sample_rate: float | None = None,
        stacklevel: int = 0,
    ) -> Generator[None]:
        start = time.monotonic()
        try:
            yield
        finally:
            duration_ms = (time.monotonic() - start) * 1000
            self.distribution(key, duration_ms, tags=tags, unit="millisecond", sample_rate=sample_rate)

    @contextmanager
    def track_memory_usage(
        self,
        key: str,
        tags: Tags | None = None,
    ) -> Generator[None]:
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        try:
            yield
        finally:
            after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            self.distribution(key, after - before, tags=tags, unit="byte")


class CustomRouter(TaskRouter):
    def route_namespace(self, name: str) -> str:
        return "taskworker-launchpad"


def producer_factory(topic: str) -> KafkaProducer:
    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9092")
    config = {
        "bootstrap.servers": bootstrap_servers,
        "compression.type": "lz4",
        "message.max.bytes": 50000000,
    }
    return KafkaProducer(config)


app = TaskbrokerApp(
    name="launchpad",
    producer_factory=producer_factory,
    router_class=CustomRouter(),
    metrics_class=DatadogMetricsBackend(),
)

app.set_modules(["launchpad.worker.tasks"])
