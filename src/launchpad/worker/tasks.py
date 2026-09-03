from launchpad.artifact_processor import ArtifactProcessor
from launchpad.utils.logging import get_logger, setup_logging

from .app import app

logger = get_logger(__name__)

default = app.taskregistry.create_namespace("default", processing_deadline_duration=60 * 15)


@default.register(name="process_artifact")
def process_artifact(
    artifact_id: str, project_id: str, organization_id: str, organization_slug: str | None = None
) -> None:
    setup_logging()
    logger.info(f"Processing artifact {artifact_id}")
    logger.info(
        f"Params: artifact_id={artifact_id}, project_id={project_id}, "
        f"organization_id={organization_id}, organization_slug={organization_slug}"
    )
    ArtifactProcessor.process_message(artifact_id, project_id, organization_id, organization_slug=organization_slug)
    logger.info(f"Processed artifact {artifact_id}")
