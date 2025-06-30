from launchpad.insights.insight import Insight, InsightsInput
from launchpad.models.android import WebPOptimizationInsightResult


class WebPOptimizationInsight(Insight[WebPOptimizationInsightResult]):
    def generate(self, insights_input: InsightsInput) -> WebPOptimizationInsightResult:
        # TODO do webp analysis
        return WebPOptimizationInsightResult(optimizeable_image_files=[])
