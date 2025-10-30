from datetime import datetime
from enum import IntEnum
from typing import Annotated, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_serializer


class SizeAnalysisState(IntEnum):
    PENDING = 0
    PROCESSING = 1
    COMPLETED = 2
    FAILED = 3


class PutSizeFailed(BaseModel):
    model_config = ConfigDict()
    state: Literal[SizeAnalysisState.FAILED] = SizeAnalysisState.FAILED
    error_code: int
    error_message: str


class PutSizeProcessing(BaseModel):
    model_config = ConfigDict()
    state: Literal[SizeAnalysisState.PROCESSING] = SizeAnalysisState.PROCESSING


class PutSizePending(BaseModel):
    model_config = ConfigDict()
    state: Literal[SizeAnalysisState.PENDING] = SizeAnalysisState.PENDING


# Missing SizeAnalysisState.COMPLETED is on purpose. The only way to mark
# a size metrics as successful is via the assemble endpoint.
PutSize = Annotated[
    PutSizeFailed | PutSizePending | PutSizeProcessing,
    Field(discriminator="state"),
]


class AppleAppInfo(BaseModel):
    is_simulator: bool
    codesigning_type: Optional[str] = None
    profile_name: Optional[str] = None
    is_code_signature_valid: Optional[bool] = None
    code_signature_errors: Optional[List[str]] = None
    main_binary_uuid: Optional[str] = None
    profile_expiration_date: Optional[str] = None
    certificate_expiration_date: Optional[str] = None
    missing_dsym_binaries: Optional[List[str]] = None
    # TODO(EME-423): add "date_built" field once exposed in 'AppleAppInfo'


class AndroidAppInfo(BaseModel):
    has_proguard_mapping: bool


class UpdateData(BaseModel):
    app_name: str
    app_id: str
    build_version: str
    build_number: Optional[int]
    artifact_type: int
    apple_app_info: Optional[AppleAppInfo] = None
    android_app_info: Optional[AndroidAppInfo] = None
    dequeued_at: Optional[datetime] = Field(None, description="Timestamp when message was dequeued from Kafka")

    @field_serializer("dequeued_at")
    def serialize_datetime(self, dt: datetime | None) -> str | None:
        """Serialize datetime objects to ISO format strings for JSON compatibility."""
        return dt.isoformat() if dt is not None else None
