"""Kafka consumer implementation for Launchpad using Arroyo."""

from __future__ import annotations

import logging
import multiprocessing
import os
import time

from dataclasses import dataclass
from logging.handlers import QueueHandler, QueueListener
from multiprocessing.connection import Connection
from typing import Any, Callable, Generic, Mapping, TypeVar, Union

from arroyo import Topic, configure_metrics
from arroyo.backends.kafka import KafkaConsumer as ArroyoKafkaConsumer
from arroyo.backends.kafka import KafkaPayload
from arroyo.dlq import InvalidMessage
from arroyo.processing.processor import StreamProcessor
from arroyo.processing.strategies import ProcessingStrategy, ProcessingStrategyFactory
from arroyo.processing.strategies.abstract import MessageRejected
from arroyo.processing.strategies.commit import CommitOffsets
from arroyo.processing.strategies.healthcheck import Healthcheck
from arroyo.types import Commit, FilteredPayload, Message, Partition, TStrategyPayload
from sentry_kafka_schemas import get_codec

from launchpad.artifact_processor import ArtifactProcessor
from launchpad.constants import HEALTHCHECK_MAX_AGE_SECONDS, PREPROD_ARTIFACT_EVENTS_TOPIC
from launchpad.tracing import RequestLogFilter
from launchpad.utils.arroyo_metrics import DatadogMetricsBackend
from launchpad.utils.logging import get_logger

TResult = TypeVar("TResult")

logger = get_logger(__name__)

# Schema codec for preprod artifact events
PREPROD_ARTIFACT_SCHEMA = get_codec(PREPROD_ARTIFACT_EVENTS_TOPIC)


def trampoline(function: Callable, log_queue: multiprocessing.Queue, conn: Connection) -> None:
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    queue_handler = QueueHandler(log_queue)
    queue_handler.addFilter(RequestLogFilter())
    root_logger.addHandler(queue_handler)
    root_logger.setLevel(logging.DEBUG)

    input_message = conn.recv()
    try:
        result = function(input_message)
    except Exception as e:
        conn.send(e)
    else:
        conn.send(result)
    conn.close()


class Job(Generic[TStrategyPayload, TResult]):
    def __init__(
        self,
        function: Callable,
        log_queue: multiprocessing.Queue,
        message: Message[TStrategyPayload],
        deadline: float = 0,
    ) -> None:
        ctx = multiprocessing.get_context("forkserver")
        ours, theirs = ctx.Pipe(True)
        self.__process = ctx.Process(target=trampoline, args=(function, log_queue, theirs))
        self.__process.start()
        self.__ours = ours
        self.__message = message
        self.__deadline = deadline
        ours.send(message.payload)

    def poll(self) -> Union[Message[TResult], None]:
        if not self.__message:
            return None
        if self.__deadline and time.time() > self.__deadline:
            raise InvalidMessage.from_value(self.__message.value)
        if not self.__ours.poll(0):
            return None
        result = self.__ours.recv()
        self.__ours.close()
        self.__process.join()
        self.__process.close()
        self.__process = None

        message = self.__message
        self.__message = None
        if isinstance(result, Exception):
            raise result
        else:
            return message.replace(result)

    def terminate(self) -> None:
        if self.__process:
            self.__process.terminate()
            self.__process = None
            self.__message = None


class RunTaskWithSubprocess(
    ProcessingStrategy[Union[FilteredPayload, TStrategyPayload]], Generic[TStrategyPayload, TResult]
):
    def __init__(
        self,
        function: Callable[[TStrategyPayload], TResult],
        next_step: ProcessingStrategy[Union[FilteredPayload, TResult]],
        timeout_s: float = 30.0,
    ) -> None:
        self.__function = function
        self.__next_step = next_step
        self.__closed = False
        self.__timeout = timeout_s

        self.__pending_input = None
        self.__job = None
        self.__pending_output = None

        ctx = multiprocessing.get_context("forkserver")
        self.__log_queue = ctx.Queue()
        root_logger = logging.getLogger()
        handlers = list(root_logger.handlers) if root_logger.handlers else []
        self.__queue_listener = QueueListener(self.__log_queue, *handlers, respect_handler_level=True)
        self.__queue_listener.start()

    def submit(self, message: Message[Union[FilteredPayload, TStrategyPayload]]) -> None:
        if self.__closed:
            raise MessageRejected("Strategy is closed")

        if self.__pending_input:
            raise MessageRejected("Strategy full")

        self.__pending_input = message

    def poll(self) -> None:
        if self.__pending_output:
            try:
                self.__next_step.submit(self.__pending_output)
            except MessageRejected:
                pass
            else:
                self.__pending_output = None
        elif self.__job:
            assert self.__pending_output is None
            try:
                result = self.__job.poll()
            except:
                self.__job = None
                raise
            else:
                if result:
                    self.__job = None
                    self.__pending_output = result
        elif self.__pending_input:
            assert self.__job is None
            deadline = time.time() + self.__timeout
            self.__job = Job(self.__function, self.__log_queue, self.__pending_input, deadline)
            self.__pending_input = None
        else:
            pass

        self.__next_step.poll()

    def close(self) -> None:
        self.__closed = True

    def terminate(self) -> None:
        self.__closed = True
        self.__queue_listener.stop()

        if self.__job:
            self.__job.terminate()
            self.__job = None

        self.__pending_input = None
        self.__pending_ouput = None

        self.__next_step.terminate()

    def join(self, timeout: float | None = None) -> None:
        timeout = 24 * 60 * 60 if timeout is None else timeout
        start = time.time()
        deadline = start + timeout

        while time.time() < deadline:
            self.poll()
            if not self.__pending_output and not self.__pending_input and not self.__job:
                break
            time.sleep(0)

        remaining = deadline - time.time()

        self.__queue_listener.stop()

        self.__next_step.close()
        self.__next_step.join(remaining)


def process_kafka_message_with_service(payload: KafkaPayload) -> Any:
    """Process a Kafka message using the actual service logic in a worker process."""
    try:
        decoded = PREPROD_ARTIFACT_SCHEMA.decode(payload.value)
        ArtifactProcessor.process_message(decoded)
        return decoded  # type: ignore[no-any-return]
    except Exception as e:
        logger.error(f"Failed to process message in worker: {e}", exc_info=True)
        raise


def create_kafka_consumer() -> LaunchpadKafkaConsumer:
    """Create and configure a Kafka consumer using environment variables."""

    healthcheck_path = os.getenv("KAFKA_HEALTHCHECK_FILE")
    if not healthcheck_path:
        healthcheck_path = f"/tmp/launchpad-kafka-health-{os.getpid()}"
        os.environ["KAFKA_HEALTHCHECK_FILE"] = healthcheck_path
        logger.info(f"Using healthcheck file: {healthcheck_path}")

    config = get_kafka_config()
    configure_metrics(DatadogMetricsBackend(config.group_id))

    environment = os.getenv("LAUNCHPAD_ENV")
    if not environment:
        raise ValueError("LAUNCHPAD_ENV environment variable is required")

    consumer_config = {
        "bootstrap.servers": config.bootstrap_servers,
        "group.id": config.group_id,
        "auto.offset.reset": config.auto_offset_reset,
        "arroyo.strict.offset.reset": config.arroyo_strict_offset_reset,
        "enable.auto.commit": False,
        "enable.auto.offset.store": False,
        "security.protocol": config.security_protocol,
    }

    # SASL is used in some prod environments.
    if config.sasl_mechanism:
        consumer_config.update(
            {
                "sasl.mechanism": config.sasl_mechanism,
                "sasl.username": config.sasl_username,
                "sasl.password": config.sasl_password,
            }
        )

    arroyo_consumer = ArroyoKafkaConsumer(consumer_config)
    healthcheck_path = config.healthcheck_file
    assert healthcheck_path

    strategy_factory = LaunchpadStrategyFactory(healthcheck_path)

    topics = [Topic(topic) for topic in config.topics]
    topic = topics[0] if topics else Topic("default")
    processor = StreamProcessor(
        consumer=arroyo_consumer,
        topic=topic,
        processor_factory=strategy_factory,
        join_timeout=config.join_timeout_seconds,  # Drop in-flight work during rebalance before Kafka times out
    )
    return LaunchpadKafkaConsumer(processor, healthcheck_path)


class LaunchpadKafkaConsumer:
    processor: StreamProcessor[KafkaPayload]
    healthcheck_path: str | None
    _running: bool

    def __init__(self, processor: StreamProcessor[KafkaPayload], healthcheck_path: str):
        self.processor = processor
        self.healthcheck_path = healthcheck_path
        self._running = False

    def run(self):
        assert not self._running, "Already running"
        logger.info(f"{self} running")
        self._running = True

        try:
            self.processor.run()
        finally:
            self._running = False

    def stop(self):
        """Signal shutdown to the processor."""
        logger.info(f"{self} stop commanded")
        self.processor.signal_shutdown()

    def is_healthy(self) -> bool:
        try:
            mtime = os.path.getmtime(self.healthcheck_path)
            age = time.time() - mtime
        except OSError:
            return False
        else:
            return age <= HEALTHCHECK_MAX_AGE_SECONDS


class LaunchpadStrategyFactory(ProcessingStrategyFactory[KafkaPayload]):
    def __init__(self, healthcheck_path: str) -> None:
        assert healthcheck_path
        self.healthcheck_path = healthcheck_path

    def create_with_partitions(
        self,
        commit: Commit,
        partitions: Mapping[Partition, int],
    ) -> ProcessingStrategy[KafkaPayload]:
        do_commit = CommitOffsets(commit)
        do_health_check = Healthcheck(self.healthcheck_path, next_step=do_commit)
        do_task = RunTaskWithSubprocess(process_kafka_message_with_service, next_step=do_health_check, timeout_s=60 * 5)

        return do_task

    def shutdown(self) -> None:
        try:
            os.remove(self.healthcheck_path)
        except FileNotFoundError:
            logger.error(f"Failed to remove healthcheck file: {self.healthcheck_path}")
        else:
            logger.info(f"Removed healthcheck file: {self.healthcheck_path}")


@dataclass
class KafkaConfig:
    """Kafka configuration data."""

    bootstrap_servers: str
    group_id: str
    topics: list[str]
    concurrency: int
    max_pending_futures: int
    healthcheck_file: str | None
    auto_offset_reset: str
    arroyo_strict_offset_reset: bool | None
    security_protocol: str
    sasl_mechanism: str | None
    sasl_username: str | None
    sasl_password: str | None
    join_timeout_seconds: float


def get_kafka_config() -> KafkaConfig:
    """Get Kafka configuration from environment variables."""
    # Required configuration
    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS")
    if not bootstrap_servers:
        raise ValueError("KAFKA_BOOTSTRAP_SERVERS env var is required")

    group_id = os.getenv("KAFKA_GROUP_ID")
    if not group_id:
        raise ValueError("KAFKA_GROUP_ID env var is required")

    topics_env = os.getenv("KAFKA_TOPICS")
    if not topics_env:
        raise ValueError("KAFKA_TOPICS env var is required")

    # Parse arroyo_strict_offset_reset as boolean, default to None if invalid
    arroyo_strict_offset_reset = {"true": True, "false": False}.get(os.getenv("ARROYO_STRICT_OFFSET_RESET", "").lower())

    # Optional configuration with defaults
    return KafkaConfig(
        bootstrap_servers=bootstrap_servers,
        group_id=group_id,
        topics=topics_env.split(","),
        concurrency=int(os.getenv("KAFKA_CONCURRENCY", "2")),
        max_pending_futures=int(os.getenv("KAFKA_MAX_PENDING_FUTURES", "100")),
        healthcheck_file=os.getenv("KAFKA_HEALTHCHECK_FILE"),
        auto_offset_reset=os.getenv("KAFKA_AUTO_OFFSET_RESET", "latest"),  # latest = skip old messages
        arroyo_strict_offset_reset=arroyo_strict_offset_reset,
        security_protocol=os.environ.get("KAFKA_SECURITY_PROTOCOL", "plaintext"),
        sasl_mechanism=os.environ.get("KAFKA_SASL_MECHANISM", None),
        sasl_username=os.environ.get("KAFKA_SASL_USERNAME", None),
        sasl_password=os.environ.get("KAFKA_SASL_PASSWORD", None),
        join_timeout_seconds=float(os.getenv("KAFKA_JOIN_TIMEOUT_SECONDS", "10")),
    )
