"""Tests for Hermes bytecode size reporter."""

from pathlib import Path

from launchpad.size.hermes.parser import HermesBytecodeParser
from launchpad.size.hermes.reporter import HermesSizeReporter


def test_hermes_size_reporter_attributes_bytes_to_sections():
    """Test that the size reporter correctly attributes bytes to sections."""
    hbc_path = Path(__file__).parent / ".." / ".." / "_fixtures" / "hermes" / "test.hbc"
    hbc_data = hbc_path.read_bytes()

    parser = HermesBytecodeParser(hbc_data)
    success = parser.parse()
    assert success, "Should parse successfully"

    size_reporter = HermesSizeReporter(parser)
    report = size_reporter.report()

    # Test all section sizes match expected values
    assert report["sections"]["Header"]["bytes"] == 128
    assert report["sections"]["Function table"]["bytes"] == 190624
    assert report["sections"]["String Kinds"]["bytes"] == 12
    assert report["sections"]["Identifier hashes"]["bytes"] == 24036
    assert report["sections"]["String table"]["bytes"] == 44912
    assert report["sections"]["Overflow String table"]["bytes"] == 1984
    assert report["sections"]["String storage"]["bytes"] == 354448
    assert report["sections"]["Array buffer"]["bytes"] == 19755
    assert report["sections"]["Object key buffer"]["bytes"] == 3964
    assert report["sections"]["Object value buffer"]["bytes"] == 6034
    assert report["sections"]["BigInt storage"]["bytes"] == 0
    assert report["sections"]["Regular expression table"]["bytes"] == 1360
    assert report["sections"]["Regular expression storage"]["bytes"] == 20172
    assert report["sections"]["CommonJS module table"]["bytes"] == 0
    assert report["sections"]["Function body"]["bytes"] == 1381096
    assert report["sections"]["Function info"]["bytes"] == 140284
    assert report["sections"]["Debug info"]["bytes"] == 1088929
    assert report["sections"]["Function Source table"]["bytes"] == 440

    assert report["unattributed"]["bytes"] == 218
