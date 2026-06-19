import os

from arroyo.backends.kafka import KafkaProducer
from taskbroker_client.app import TaskbrokerApp
from taskbroker_client.metrics import MetricsBackend, DatadogMetrics
from taskbroker_client.router import TaskRouter



class CustomRouter(TaskRouter):
    def route_namespace(self, name: str) -> str:
        return os.getenv("TASKWORKER_TOPIC", "taskworker")


def producer_factory(topic: str) -> KafkaProducer:
    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9092")
    config = {
        "bootstrap.servers": bootstrap_servers,
        "compression.type": "lz4",
        "message.max.bytes": 50000000,
    }
    return KafkaProducer(config)


def create_metrics() -> MetricsBackend:
    host = os.getenv("STATSD_HOST", "127.0.0.1")
    port_str = os.getenv("STATSD_PORT", "8125")
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"STATSD_PORT must be a valid integer, got: {port_str}")

    return DatadogMetrics(
        application="launchpad",
        processing_pool="launchpad",
        statsd_host=host,
        statsd_port=port,
        enable_prefixed_metrics=True,
    )


app = TaskbrokerApp(
    name="launchpad",
    producer_factory=producer_factory,
    router_class=CustomRouter(),
    metrics_class=create_metrics(),
)

app.set_config(
    {
        "rpc_secret": os.getenv("TASKWORKER_SHARED_SECRET", None),
    }
)

app.set_modules(["launchpad.worker.tasks"])
