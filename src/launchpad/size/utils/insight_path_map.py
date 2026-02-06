"""Build path-to-insight mapping with per-file savings from insight results."""

from __future__ import annotations

from collections import defaultdict

from launchpad.size.models.android import AndroidInsightResults
from launchpad.size.models.apple import AppleInsightResults
from launchpad.size.models.insights import BaseInsightResult
from launchpad.size.models.treemap import FlaggedInsight


def build_insight_path_map(
    insights: AppleInsightResults | AndroidInsightResults | None,
) -> dict[str, list[FlaggedInsight]]:
    """
    Map file paths to flagged insights with per-file savings.

    Uses Pydantic model introspection to dynamically iterate over all insight
    fields. Each insight result implements get_file_path_savings() to return
    its associated (path, savings) pairs.

    Returns a dict mapping file_path -> list of FlaggedInsight(key, savings).
    O(n) where n is the total number of file entries across all insights.
    """
    if insights is None:
        return {}

    # path -> insight_key -> max savings (dedup same path+key, keep highest savings)
    path_map: dict[str, dict[str, int]] = defaultdict(dict)

    for field_name in insights.model_fields:
        result = getattr(insights, field_name, None)
        if result is None:
            continue

        if not isinstance(result, BaseInsightResult):
            continue

        for path, savings in result.get_file_path_savings():
            existing = path_map[path].get(field_name, -1)
            if savings > existing:
                path_map[path][field_name] = savings

    return {
        path: [FlaggedInsight(key=key, savings=savings) for key, savings in insight_map.items()]
        for path, insight_map in path_map.items()
    }
