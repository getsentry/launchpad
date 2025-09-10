from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class AppleAppInfo(BaseModel):
    is_simulator: bool
    codesigning_type: Optional[str] = None
    profile_name: Optional[str] = None
    is_code_signature_valid: Optional[bool] = None
    code_signature_errors: Optional[List[str]] = None
    main_binary_uuid: Optional[str] = None
    profile_expiration_date: Optional[str] = None
    certificate_expiration_date: Optional[str] = None
    # TODO: add "date_built" field once exposed in 'AppleAppInfo'


class ExtraInfo(BaseModel):
    dequeued_at: datetime | None = Field(None, description="Timestamp when message was dequeued from Kafka")
    processed_at: datetime | None = Field(None, description="Timestamp when processing completed")


class UpdateData(BaseModel):
    app_name: str
    app_id: str
    build_version: str
    build_number: Optional[int]
    artifact_type: int
    apple_app_info: Optional[AppleAppInfo] = None
    extra_info: Optional[ExtraInfo] = None
    # TODO: add "date_built" and custom android fields
