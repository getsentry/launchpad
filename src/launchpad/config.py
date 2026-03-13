import os

_TASKWORKER_ONLY_PROJECT_IDS: set[str] = {
    p.strip() for p in os.getenv("PROJECT_IDS_TO_ONLY_TRY_TASKWORKER_PROCESSING", "").split(",") if p.strip()
}


def is_taskworker_only_project(project_id: str) -> bool:
    return project_id in _TASKWORKER_ONLY_PROJECT_IDS
