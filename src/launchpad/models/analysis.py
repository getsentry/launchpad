"""
Data models for analysis results.
"""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ComponentSize(BaseModel):
    """Size information for a component (class, library, etc.)."""

    name: str = Field(..., description="Name of the component")
    file_size: int = Field(..., description="Size on disk in bytes")
    download_size: Optional[int] = Field(None, description="Estimated download size in bytes")
    percentage: float = Field(..., description="Percentage of total size")
    path: Optional[str] = Field(None, description="Path within the artifact")
    type: str = Field(..., description="Type of component (class, library, resource, etc.)")


class AnalysisResult(BaseModel):
    """Result of analyzing an artifact."""

    # Basic information
    artifact_path: str = Field(..., description="Path to the analyzed artifact")
    platform: str = Field(..., description="Platform (ios, android)")
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Size information
    total_file_size: int = Field(..., description="Total size on disk in bytes")
    total_download_size: Optional[int] = Field(None, description="Estimated total download size in bytes")

    # Component breakdown
    components: List[ComponentSize] = Field(default_factory=list, description="List of components with sizes")

    # Summary statistics
    summary: Dict[str, int] = Field(default_factory=dict, description="Summary statistics by type")

    # Metadata
    metadata: Dict[str, any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
