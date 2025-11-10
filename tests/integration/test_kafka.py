import multiprocessing
import string
import time

from datetime import datetime
from unittest.mock import Mock

import pytest

from arroyo.backends.kafka import KafkaPayload
from arroyo.dlq import InvalidMessage
from arroyo.processing.strategies.abstract import MessageRejected
from arroyo.types import BrokerValue, Message, Partition, Topic

from launchpad.kafka import Job, RunTaskWithSubprocess

topic = Topic("topic")
partition = Partition(topic, 0)


def make_value(payload):
    return BrokerValue(payload, Partition, 0, datetime.now())


def run_multiply(payload: KafkaPayload) -> KafkaPayload:
    return KafkaPayload(payload.key, payload.value * 2, payload.headers)


def run_uppercase(payload: KafkaPayload) -> KafkaPayload:
    return KafkaPayload(payload.key, payload.value.upper(), payload.headers)


def run_raise(x: Message[KafkaPayload]) -> KafkaPayload:
    raise ValueError("Function failed intentionally")


def run_sleep(_: Message[KafkaPayload]) -> KafkaPayload:
    time.sleep(1000)


def test_successful_function_execution() -> None:
    next_step = Mock()

    strategy = RunTaskWithSubprocess(run_multiply, next_step)

    input_payload = KafkaPayload(None, b"hello", [])
    strategy.submit(Message(make_value(input_payload)))

    poll_count = 0
    while next_step.submit.call_count == 0:
        strategy.poll()
        poll_count += 1
        time.sleep(0)

    next_step.submit.assert_called_once()

    message = next_step.submit.call_args[0][0]

    assert message.payload.value == b"hellohello"
    assert message.payload.key is None
    assert message.payload.headers == []

    assert next_step.poll.call_count == poll_count

    strategy.close()
    strategy.join()


def test_real_timeout() -> None:
    next_step = Mock()

    strategy = RunTaskWithSubprocess(run_multiply, next_step, timeout_s=0.1)

    input_payload = KafkaPayload(None, b"hello", [])
    strategy.submit(Message(make_value(input_payload)))

    with pytest.raises(InvalidMessage):
        while next_step.submit.call_count == 0:
            strategy.poll()
            time.sleep(0)

    strategy.close()
    strategy.join()


def test_function_exception_propagation() -> None:
    next_step = Mock()

    strategy = RunTaskWithSubprocess(
        run_raise,
        next_step,
    )

    input_payload = KafkaPayload(None, b"test", [])
    strategy.submit(Message(make_value(input_payload)))

    with pytest.raises(ValueError, match=r".*Function failed intentionally.*"):
        while True:
            strategy.poll()
            time.sleep(0)

    next_step.submit.assert_not_called()

    strategy.close()
    strategy.join()


def test_can_be_terminated() -> None:
    next_step = Mock()

    strategy = RunTaskWithSubprocess(
        run_raise,
        next_step,
    )

    input_payload = KafkaPayload(None, b"test", [])
    strategy.submit(Message(make_value(input_payload)))
    strategy.poll()
    strategy.poll()
    strategy.terminate()


def test_applies_back_pressure() -> None:
    next_step = Mock()

    a = Message(make_value(KafkaPayload(None, b"a", [])))
    b = Message(make_value(KafkaPayload(None, b"b", [])))

    strategy = RunTaskWithSubprocess(run_multiply, next_step)
    strategy.submit(a)
    with pytest.raises(MessageRejected):
        strategy.submit(b)

    strategy.close()
    strategy.join()


def test_submit_does_no_work() -> None:
    next_step = Mock()

    a = Message(make_value(KafkaPayload(None, b"a", [])))
    b = Message(make_value(KafkaPayload(None, b"b", [])))
    c = Message(make_value(KafkaPayload(None, b"c", [])))

    strategy = RunTaskWithSubprocess(run_multiply, next_step)
    strategy.submit(a)

    # This poll() starts the task for a:
    strategy.poll()
    # ...freeing a slot to submit b:
    strategy.submit(b)
    # ...but submiting again will reject:
    with pytest.raises(MessageRejected):
        strategy.submit(c)

    strategy.close()
    strategy.join()


def test_many() -> None:
    next_step = Mock()

    alphabet = string.ascii_lowercase[:5]

    queue = list(alphabet)[::-1]

    strategy = RunTaskWithSubprocess(run_uppercase, next_step)

    poll_count = 0
    while next_step.submit.call_count != len(alphabet):
        if queue:
            letter = queue[-1]
            message = Message(make_value(KafkaPayload(None, letter, [])))
            try:
                strategy.submit(message)
            except MessageRejected:
                pass
            else:
                queue.pop()

        poll_count += 1
        strategy.poll()
        time.sleep(0.01)

    assert next_step.poll.call_count == poll_count
    actual = "".join(args[0][0].payload.value for args in next_step.submit.call_args_list)

    assert actual == alphabet.upper()

    strategy.close()
    strategy.join()


def return_hello_world(payload: KafkaPayload):
    return KafkaPayload(payload.key, "Hello, world!", payload.headers)


def test_benchmark_job(benchmark):
    log_queue = multiprocessing.Queue()

    def do_job():
        job = Job(return_hello_world, log_queue, Message(make_value(KafkaPayload(None, None, []))))
        while True:
            r = job.poll()
            if r is not None:
                return r
            time.sleep(0.01)

    final = benchmark(do_job)

    assert final.payload.value == "Hello, world!"
