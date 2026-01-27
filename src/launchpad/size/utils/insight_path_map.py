"""Build path-to-insight-keys mapping from insight results."""

from __future__ import annotations

from collections import defaultdict

from launchpad.size.models.android import AndroidInsightResults
from launchpad.size.models.apple import AppleInsightResults
from launchpad.size.models.insights import (
    BaseInsightResult,
    FilesInsightResult,
    GroupsInsightResult,
    ImageOptimizationInsightResult,
    StripBinaryInsightResult,
    VideoCompressionInsightResult,
)


def build_insight_path_map(
    insights: AppleInsightResults | AndroidInsightResults | None,
) -> dict[str, list[str]]:
    """
    Map file paths to the insight keys that flag them.

    Uses Pydantic model introspection to dynamically iterate over all insight
    fields. Uses isinstance(BaseInsightResult) to identify insight fields,
    avoiding hardcoded lists and maintaining a single source of truth.
    """
    if insights is None:
        return {}

    path_map: dict[str, list[str]] = defaultdict(list)

    for field_name in insights.model_fields:
        result = getattr(insights, field_name, None)
        if result is None:
            continue

        # Only process actual insight results (skips 'platform' and any future non-insight fields)
        if not isinstance(result, BaseInsightResult):
            continue

        for path in _extract_paths(result):
            if field_name not in path_map[path]:
                path_map[path].append(field_name)

    return dict(path_map)


def _extract_paths(result: BaseInsightResult) -> list[str]:
    """Extract file paths from a single insight result based on its type."""
    # Pattern 1: FilesInsightResult and subclasses (most common)
    if isinstance(result, FilesInsightResult):
        return [f.file_path for f in result.files]

    # Pattern 2: GroupsInsightResult (DuplicateFiles, LooseImages)
    if isinstance(result, GroupsInsightResult):
        return [f.file_path for group in result.groups for f in group.files]

    # Pattern 3: ImageOptimizationInsightResult (uses optimizable_files)
    if isinstance(result, ImageOptimizationInsightResult):
        return [f.file_path for f in result.optimizable_files]

    # Pattern 4: StripBinaryInsightResult (uses StripBinaryFileInfo)
    if isinstance(result, StripBinaryInsightResult):
        return [f.file_path for f in result.files]

    # Pattern 5: VideoCompressionInsightResult
    if isinstance(result, VideoCompressionInsightResult):
        return [f.file_path for f in result.files]

    # LocalizedStringInsightResult and any future insights without file paths
    return []
