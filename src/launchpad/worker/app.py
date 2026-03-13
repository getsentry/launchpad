from arroyo.backends.kafka import KafkaProducer
from taskbroker_client.app import TaskbrokerApp
from taskbroker_client.router import TaskRouter


class CustomRouter(TaskRouter):
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
)

app.set_modules(["launchpad.worker.tasks"])
