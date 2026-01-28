"""Build path-to-insight-keys mapping from insight results."""

from __future__ import annotations

from collections import defaultdict

from launchpad.size.models.android import AndroidInsightResults
from launchpad.size.models.apple import AppleInsightResults
from launchpad.size.models.insights import BaseInsightResult


def build_insight_path_map(
    insights: AppleInsightResults | AndroidInsightResults | None,
) -> dict[str, list[str]]:
    """
    Map file paths to the insight keys that flag them.

    Uses Pydantic model introspection to dynamically iterate over all insight
    fields. Each insight result implements get_file_paths() to return its
    associated paths.
    """
    if insights is None:
        return {}

    path_map: dict[str, set[str]] = defaultdict(set)

    for field_name in insights.model_fields:
        result = getattr(insights, field_name, None)
        if result is None:
            continue

        if not isinstance(result, BaseInsightResult):
            continue

        for path in result.get_file_paths():
            path_map[path].add(field_name)

    return {k: list(v) for k, v in path_map.items()}
