from launchpad.artifact_processor import ArtifactProcessor
from launchpad.config import is_taskworker_only_project
from launchpad.utils.logging import get_logger, setup_logging

from .app import app

logger = get_logger(__name__)

default = app.taskregistry.create_namespace("default")


@default.register(name="process_artifact")
def process_artifact(artifact_id: str, project_id: str, organization_id: str) -> None:
    setup_logging()
    logger.info(f"Processing artifact {artifact_id}")
    logger.info(f"Params: artifact_id={artifact_id}, project_id={project_id}, organization_id={organization_id}")
    if not is_taskworker_only_project(str(project_id)):
        logger.info("Skipping TaskWorker processing for project %s (not in taskworker-only list)", project_id)
        return
    ArtifactProcessor.process_message(artifact_id, project_id, organization_id)
    logger.info(f"Processed artifact {artifact_id}")
