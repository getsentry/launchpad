from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.apple import LocalizedStringInsightResult


class LocalizedStringsInsight(Insight[LocalizedStringInsightResult]):
    def generate(self, input: InsightsInput) -> LocalizedStringInsightResult:
        return LocalizedStringInsightResult(
            files=[],
            file_count=0,
            total_size=0,
        )
