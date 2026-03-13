from __future__ import annotations

import multiprocessing
import threading

from unittest.mock import MagicMock, patch

from launchpad.kafka import process_kafka_message_with_service


def _make_decoded(project_id: str = "123", artifact_id: str = "art-1") -> dict:
    return {
        "project_id": project_id,
        "artifact_id": artifact_id,
        "organization_id": "org-1",
    }


def _call_process(decoded: dict) -> MagicMock:
    msg = MagicMock()
    msg.payload.value = b"raw"

    mock_process = MagicMock(spec=multiprocessing.Process)
    mock_process.pid = 999
    mock_process.exitcode = 0
    mock_process.is_alive.return_value = False

    factory = MagicMock()
    factory._killed_during_rebalance = set()

    with (
        patch("launchpad.kafka.PREPROD_ARTIFACT_SCHEMA") as mock_schema,
        patch("launchpad.kafka.multiprocessing.Process", return_value=mock_process) as mock_proc_cls,
    ):
        mock_schema.decode.return_value = decoded
        process_kafka_message_with_service(
            msg=msg,
            log_queue=MagicMock(),
            process_registry={},
            registry_lock=threading.Lock(),
            factory=factory,
        )

    return mock_proc_cls


class TestTaskworkerOnlyProjectSkip:
    def test_skips_project_in_taskworker_only_list(self):
        decoded = _make_decoded(project_id="42")

        with patch("launchpad.config._TASKWORKER_ONLY_PROJECT_IDS", {"42"}):
            mock_proc_cls = _call_process(decoded)

        mock_proc_cls.assert_not_called()

    def test_skips_with_multiple_projects_in_list(self):
        decoded = _make_decoded(project_id="99")

        with patch("launchpad.config._TASKWORKER_ONLY_PROJECT_IDS", {"42", "99", "7"}):
            mock_proc_cls = _call_process(decoded)

        mock_proc_cls.assert_not_called()

    def test_processes_project_not_in_list(self):
        decoded = _make_decoded(project_id="123")

        with patch("launchpad.config._TASKWORKER_ONLY_PROJECT_IDS", {"42", "99"}):
            mock_proc_cls = _call_process(decoded)

        mock_proc_cls.assert_called_once()

    def test_processes_when_env_var_empty(self):
        decoded = _make_decoded(project_id="123")

        with patch("launchpad.config._TASKWORKER_ONLY_PROJECT_IDS", set()):
            mock_proc_cls = _call_process(decoded)

        mock_proc_cls.assert_called_once()

    def test_processes_when_env_var_unset(self):
        decoded = _make_decoded(project_id="123")

        with patch("launchpad.config._TASKWORKER_ONLY_PROJECT_IDS", set()):
            mock_proc_cls = _call_process(decoded)

        mock_proc_cls.assert_called_once()

    def test_handles_integer_project_id(self):
        decoded = _make_decoded()
        decoded["project_id"] = 42

        with patch("launchpad.config._TASKWORKER_ONLY_PROJECT_IDS", {"42"}):
            mock_proc_cls = _call_process(decoded)

        mock_proc_cls.assert_not_called()
