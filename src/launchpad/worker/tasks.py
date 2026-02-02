
from typing import List

from launchpad.artifact_processor import ArtifactProcessor
from launchpad.constants import PreprodFeature

from .app import app

# Create a namespace and register tasks
default = app.taskregistry.create_namespace("default")


@default.register(name="process_artifact")
def process_artifact(
    artifact_id: str, project_id: str, organization_id: str, requested_features: List[PreprodFeature], **kwargs
) -> None:
    print("Processing artifact...")

    ArtifactProcessor.process_message(artifact_id, project_id, organization_id, requested_features)

    print("Processed artifact 🎉")
