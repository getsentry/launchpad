from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import StripBinaryInsightResult


class StripSymbolsInsight(Insight[StripBinaryInsightResult]):
    def generate(self, input: InsightsInput) -> StripBinaryInsightResult | None:
        return None
