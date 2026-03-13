import os


def is_taskworker_only_project(project_id: str) -> bool:
    raw = os.getenv("PROJECT_IDS_TO_ONLY_TRY_TASKWORKER_PROCESSING", "")
    return project_id in {p.strip() for p in raw.split(",") if p.strip()}
