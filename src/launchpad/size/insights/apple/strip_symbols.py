from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import StripBinaryInsightResult


class StripSymbolsInsight(Insight[StripBinaryInsightResult]):
    def generate(self, insights_input: InsightsInput) -> StripBinaryInsightResult:
        return StripBinaryInsightResult(files=[], total_savings=0)
