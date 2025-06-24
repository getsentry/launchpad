import json
import time
from typing import Any, BinaryIO, TextIO, cast

from ..analyzers.android import AndroidAnalyzer
from ..analyzers.apple import AppleAppAnalyzer
from ..artifacts.artifact import AndroidArtifact, AppleArtifact
from ..artifacts.artifact_factory import ArtifactFactory
from ..models.common import BaseAnalysisResults


def do_size(input_file: BinaryIO, **flags: Any) -> BaseAnalysisResults:
    start_time = time.time()
    artifact = ArtifactFactory.from_file(input_file)

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
