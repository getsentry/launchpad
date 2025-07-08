import json
import time

from pathlib import Path
from typing import Any, TextIO, cast

from launchpad.artifacts.artifact import AndroidArtifact, AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.android import AndroidAnalyzer
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.android import AndroidAppInfo
from launchpad.size.models.apple import AppleAppInfo
from launchpad.size.models.common import BaseAnalysisResults


def do_preprocess(path: Path, **flags: Any) -> AndroidAppInfo | AppleAppInfo:
    """Perform preprocessing step only to extract basic app info.

    Args:
        path: Path to the artifact
        **flags: Additional flags passed to analyzer

    Returns:
        App info extracted during preprocessing
    """

    # isinstance switch below is a bit sad. Ryan suggested a
    # get_analyzer method on artifact which might be nicer.
    artifact = ArtifactFactory.from_path(path)
    if isinstance(artifact, AndroidArtifact):
        analyzer = AndroidAnalyzer(**flags)
        return analyzer.preprocess(cast(AndroidArtifact, artifact))
    elif isinstance(artifact, AppleArtifact):
        analyzer = AppleAppAnalyzer(**flags)
        return analyzer.preprocess(cast(AppleArtifact, artifact))
    else:
        raise ValueError(f"Unknown artifact kind {artifact}")


def do_size(
    path: Path, analyzer: AndroidAnalyzer | AppleAppAnalyzer | None = None, **flags: Any
) -> BaseAnalysisResults:
    """Perform full size analysis.

    Args:
        path: Path to the artifact
        analyzer: Optional pre-configured analyzer (with preprocessing already done)
        **flags: Additional flags passed to analyzer if creating new one

    Returns:
        Full analysis results
    """
    start_time = time.time()
    artifact = ArtifactFactory.from_path(path)

    # If no analyzer provided, create one
    if analyzer is None:
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
