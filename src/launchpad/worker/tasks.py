from launchpad.artifact_processor import ArtifactProcessor
from launchpad.constants import PreprodFeature
from launchpad.utils.logging import get_logger

from .app import app

logger = get_logger(__name__)

default = app.taskregistry.create_namespace("default")


@default.register(name="process_artifact")
def process_artifact(
    artifact_id: str, project_id: str, organization_id: str, requested_features: list[PreprodFeature], **kwargs
) -> None:
    logger.info(f"Processing artifact {artifact_id}")
    ArtifactProcessor.process_message(artifact_id, project_id, organization_id, requested_features)
    logger.info(f"Processed artifact {artifact_id}")
