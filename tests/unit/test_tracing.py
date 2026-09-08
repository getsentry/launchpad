import logging

from launchpad.tracing import RequestLogFilter, current_request_id, request_context


def _filtered_record() -> logging.LogRecord:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "msg", None, None)
    RequestLogFilter().filter(record)
    return record


def test_request_context_stamps_request_id_and_artifact_id_onto_records() -> None:
    with request_context(artifact_id="123"):
        record = _filtered_record()
        assert record.request_id == current_request_id()
    assert record.artifact_id == "123"


def test_request_context_fields_are_absent_outside_the_block() -> None:
    with request_context(artifact_id="123"):
        pass
    record = _filtered_record()
    assert not hasattr(record, "artifact_id")
    assert not hasattr(record, "request_id")


def test_request_context_without_artifact_id_only_stamps_request_id() -> None:
    with request_context():
        record = _filtered_record()
    assert record.request_id
    assert not hasattr(record, "artifact_id")
