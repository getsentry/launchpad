from typing import List, Optional

from pydantic import BaseModel


class AppleAppInfo(BaseModel):
    is_simulator: bool
    codesigning_type: Optional[str] = None
    profile_name: Optional[str] = None
    is_code_signature_valid: Optional[bool] = None
    code_signature_errors: Optional[List[str]] = None
    # TODO: add "date_built" field once exposed in 'AppleAppInfo'


class UpdateData(BaseModel):
    app_name: str
    app_id: str
    build_version: str
    build_number: Optional[int]
    artifact_type: str
    apple_app_info: Optional[AppleAppInfo] = None
    # TODO: add "date_built" and custom android fields
