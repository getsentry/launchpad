from arroyo.backends.kafka import KafkaProducer
from taskbroker_client.app import TaskbrokerApp
from taskbroker_client.router import TaskRouter

from .store import StubAtMostOnce


class CustomRouter(TaskRouter):
    """Custom router that routes all namespaces to the 'taskworker' topic."""

    def route_namespace(self, name: str) -> str:
        return "taskworker"


def producer_factory(topic: str) -> KafkaProducer:
    # TODO use env vars for kafka host/port
    config = {
        "bootstrap.servers": "127.0.0.1:9092",
        "compression.type": "lz4",
        "message.max.bytes": 50000000,  # 50MB
    }
    return KafkaProducer(config)


app = TaskbrokerApp(
    name="launchpad",
    producer_factory=producer_factory,
    router_class=CustomRouter(),
    at_most_once_store=StubAtMostOnce(),
)

app.set_modules(["tasks"])
