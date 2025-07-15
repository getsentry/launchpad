"""Constants used throughout the Launchpad application."""

from enum import Enum

# Kafka topic names
PREPROD_ARTIFACT_EVENTS_TOPIC = "preprod-artifact-events"


# Error code constants (matching the Django model)
class ProcessingErrorCode(Enum):
    """Error codes for artifact processing (matching the Django model)."""

    UNKNOWN = 0
    UPLOAD_TIMEOUT = 1
    ARTIFACT_PROCESSING_TIMEOUT = 2
    ARTIFACT_PROCESSING_ERROR = 3


# Artifact type constants
class ArtifactType(Enum):
    """Artifact types for different platforms and formats."""

    XCARCHIVE = 0
    AAB = 1
    APK = 2


# Retry configuration
MAX_RETRY_ATTEMPTS = 3

# Health check threshold - consider unhealthy if file not touched in 60 seconds
HEALTHCHECK_MAX_AGE_SECONDS = 60.0


class OperationName(Enum):
    """Enum for operation names used in retry logic."""

    PREPROCESSING = "preprocessing"
    SIZE_ANALYSIS = "size analysis"


class ProcessingErrorMessage(Enum):
    """Fixed set of error messages for artifact processing."""

    # Network-related errors
    DOWNLOAD_FAILED = "Failed to download artifact from Sentry"
    UPLOAD_FAILED = "Failed to upload analysis results to Sentry"
    UPDATE_FAILED = "Failed to update artifact info in Sentry"

    # Processing-related errors
    PREPROCESSING_FAILED = "Failed to extract basic app information"
    SIZE_ANALYSIS_FAILED = "Failed to perform size analysis"
    ARTIFACT_PARSING_FAILED = "Failed to parse artifact file"
    UNSUPPORTED_ARTIFACT_TYPE = "Unsupported artifact type"

    # System-related errors
    TEMP_FILE_CREATION_FAILED = "Failed to create temporary file"
    CLEANUP_FAILED = "Failed to clean up temporary files"

    # Timeout errors
    PROCESSING_TIMEOUT = "Processing timed out"

    # Unknown errors
    UNKNOWN_ERROR = "An unknown error occurred"


# Operation to error message mapping
OPERATION_ERRORS = {
    OperationName.PREPROCESSING: ProcessingErrorMessage.PREPROCESSING_FAILED,
    OperationName.SIZE_ANALYSIS: ProcessingErrorMessage.SIZE_ANALYSIS_FAILED,
}
