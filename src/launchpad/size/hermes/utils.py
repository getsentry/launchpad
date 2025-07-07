from pathlib import Path
from typing import Dict, List

from launchpad.size.hermes.parser import HermesBytecodeParser
from launchpad.size.hermes.reporter import HermesReport, HermesSizeReporter
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

HERMES_EXTENSIONS = {"jsbundle", "hbc"}


def make_hermes_reports(file_path: Path) -> Dict[str, HermesReport]:
    hermes_files = find_hermes_files(file_path)
    reports: Dict[str, HermesReport] = {}
    for hermes_file in hermes_files:
        report = make_hermes_report(hermes_file)
        if report is not None:
            # TODO: Add absolute path support to FileInfo so we can use the absolute path here
            reports[str(hermes_file.relative_to(file_path))] = report
    return reports


def find_hermes_files(file_path: Path) -> List[Path]:
    hermes_files: List[Path] = []
    for extension in HERMES_EXTENSIONS:
        hermes_files.extend(file_path.rglob(f"*.{extension}"))
    return hermes_files


def make_hermes_report(file_path: Path) -> HermesReport | None:
    data = file_path.read_bytes()

    if not HermesBytecodeParser.is_hermes_file(data):
        logger.warning("File %s is not a valid Hermes bytecode file", file_path)
        return None

    parser = HermesBytecodeParser(data)
    if not parser.parse():
        logger.warning("Failed to parse Hermes bytecode file %s", file_path)
        return None

    reporter = HermesSizeReporter(parser)
    report = reporter.report()
    return report
