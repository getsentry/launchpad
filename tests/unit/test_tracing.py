import logging

from launchpad.tracing import RequestLogFilter, current_request_id, log_context, request_context


def _filtered_record() -> logging.LogRecord:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "msg", None, None)
    RequestLogFilter().filter(record)
    return record


def test_log_context_fields_are_stamped_onto_records() -> None:
    with log_context(artifact_id="123", project_id="p"):
        record = _filtered_record()
    assert record.artifact_id == "123"
    assert record.project_id == "p"


def test_log_context_fields_are_absent_outside_the_block() -> None:
    with log_context(artifact_id="123"):
        pass
    assert not hasattr(_filtered_record(), "artifact_id")


def test_nested_log_context_merges_fields() -> None:
    with log_context(artifact_id="123"):
        with log_context(project_id="p"):
            record = _filtered_record()
        outer = _filtered_record()
    assert (record.artifact_id, record.project_id) == ("123", "p")
    assert outer.artifact_id == "123" and not hasattr(outer, "project_id")


def test_request_id_is_still_stamped_alongside_fields() -> None:
    with request_context(), log_context(artifact_id="123"):
        record = _filtered_record()
        assert record.request_id == current_request_id()
    assert record.artifact_id == "123"
