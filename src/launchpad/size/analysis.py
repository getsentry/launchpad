import json
import time
from typing import Any, BinaryIO, TextIO, cast

from ..analyzers.android import AndroidAnalyzer
from ..analyzers.apple import AppleAppAnalyzer
from ..artifacts import AndroidArtifact, AppleArtifact, ArtifactFactory


def do_size_analysis(input_file: BinaryIO, output_file: TextIO) -> None:
    start_time = time.time()
    artifact = ArtifactFactory.from_file(input_file)

    # isinstance switch below is a bit sad. Ryan suggested a
    # get_analyzer method on artifact which might be nicer.
    analyzer: AndroidAnalyzer | AppleAppAnalyzer
    if isinstance(artifact, AndroidArtifact):
        analyzer = AndroidAnalyzer()
    elif isinstance(artifact, AppleArtifact):
        analyzer = AppleAppAnalyzer()
    else:
        raise ValueError(f"Unknown artifact kind {artifact}")
    results = analyzer.analyze(cast(Any, artifact))

    end_time = time.time()
    duration = end_time - start_time
    results = results.model_copy(update={"analysis_duration": duration})
    json.dump(results.to_dict(), output_file, indent=2, ensure_ascii=False)
