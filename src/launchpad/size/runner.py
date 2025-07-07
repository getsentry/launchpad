import json
import time

from pathlib import Path
from typing import Any, TextIO, cast

from launchpad.artifacts.artifact import AndroidArtifact, AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.android import AndroidAnalyzer
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.common import BaseAnalysisResults


def do_size(path: Path, **flags: Any) -> BaseAnalysisResults:
    start_time = time.time()
    artifact = ArtifactFactory.from_path(path)

    # isinstance switch below is a bit sad. Ryan suggested a
    # get_analyzer method on artifact which might be nicer.
    analyzer: AndroidAnalyzer | AppleAppAnalyzer
    if isinstance(artifact, AndroidArtifact):
        analyzer = AndroidAnalyzer(**flags)
    elif isinstance(artifact, AppleArtifact):
        analyzer = AppleAppAnalyzer(**flags)
    else:
        raise ValueError(f"Unknown artifact kind {artifact}")
    results = analyzer.analyze(cast(Any, artifact))

    end_time = time.time()
    duration = end_time - start_time
    results = results.model_copy(update={"analysis_duration": duration})
    return results


def write_results_as_json(results: BaseAnalysisResults, out: TextIO) -> None:
    json.dump(results.to_dict(), out, indent=2, ensure_ascii=False)
