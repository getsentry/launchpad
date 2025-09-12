from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, field_serializer


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


class UpdateData(BaseModel):
    app_name: str
    app_id: str
    build_version: str
    build_number: Optional[int]
    artifact_type: int
    apple_app_info: Optional[AppleAppInfo] = None
    dequeued_at: Optional[datetime] = Field(None, description="Timestamp when message was dequeued from Kafka")

    @field_serializer("dequeued_at")
    def serialize_datetime(self, dt: datetime | None) -> str | None:
        """Serialize datetime objects to ISO format strings for JSON compatibility."""
        return dt.isoformat() if dt is not None else None

    # TODO: add "date_built" and custom android fields
