import json
import lief

from io import BytesIO, TextIOWrapper
from pathlib import Path

from launchpad.artifacts.artifact import AndroidArtifact, AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.android import AndroidAnalyzer
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.android import AndroidAppInfo
from launchpad.size.models.apple import AppleAppInfo
from launchpad.size.models.common import BaseAnalysisResults
from launchpad.parsers.apple.macho_parser import MachOParser

output_file = TextIOWrapper(BytesIO())
path = Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")

artifact = ArtifactFactory.from_path(path)
analyzer = AppleAppAnalyzer(skip_swift_metadata = True, skip_symbols = True, skip_range_mapping = False, skip_treemap = False, skip_image_analysis = True, skip_insights = True)
analyzer.analyze(artifact)

# fat_binary = lief.MachO.parse("Common")



