# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Launchpad** is a Python-based microservice for analyzing iOS and Android app bundle sizes. It provides detailed analysis of app binaries, generates optimization insights, and offers size breakdowns with visualization. This is a Sentry internal service that processes mobile app artifacts.

## Development Commands

Always use `uv run` to run scripts instead of manually invoking python.

```bash
# Setup
devenv sync                    # or: make install-dev && source .venv/bin/activate

# Code quality (run before committing)
make check                     # All checks: lint, format, types, deps
make fix                       # Auto-fix formatting and imports

# Testing
make test                      # All tests (unit + integration)
make test-unit                 # Unit tests only
make test-integration          # Integration tests only

# Run a single test
uv run pytest tests/unit/path/to/test_file.py::test_function_name -v
uv run pytest tests/unit/path/to/test_file.py -v               # whole file
uv run pytest -k "test_name_pattern" -v                        # by pattern

# CLI usage
launchpad size path/to/app.xcarchive.zip                       # iOS
launchpad size path/to/app.apk                                 # Android
launchpad size app.xcarchive.zip --skip-swift-metadata --skip-symbols  # faster

# Service development
devservices up                 # Start Kafka infrastructure
make serve                     # Start Launchpad server
```

## Architecture

### Core Components
- **CLI** (`src/launchpad/cli.py`): Main entry point, uses Click
- **Service** (`src/launchpad/service.py`): Kafka consumer + HTTP server for production
- **Analyzers** (`src/launchpad/size/analyzers/`): Platform-specific analysis engines (AppleAppAnalyzer, AndroidAnalyzer)
- **Parsers** (`src/launchpad/parsers/`): Binary parsing - Mach-O via LIEF, custom DEX parsers
- **Insights** (`src/launchpad/size/insights/`): Optimization recommendations (image compression, symbol stripping, etc.)
- **Artifacts** (`src/launchpad/artifacts/`): Artifact handlers - ArtifactFactory creates appropriate handler by file type

### Data Flow
1. Artifact (`.xcarchive.zip`, `.apk`, `.aab`) → ArtifactFactory
2. Platform-specific analyzer extracts binaries, resources, metadata
3. Parsers analyze binary structure (symbols, sections, Swift metadata)
4. Insights engine generates optimization recommendations
5. Results serialized as JSON with treemap visualization data

### Key Data Models
- `AppleAnalysisResults` / `AndroidAnalysisResults`: Platform analysis output
- `BinaryComponent`: Individual binary analysis with symbols and sections
- `TreemapElement`: Hierarchical size data for visualization
- `InsightResult`: Optimization recommendation with potential savings

## Code Style

- **Python 3.13+** with type hints (use `| None` not `Optional`)
- **Ruff** for linting/formatting (120 char line length)
- **ty** for type checking (not mypy)
- **Empty `__init__.py` files** preferred
- **Comments**: Only add comments for complex logic or important business decisions

## Testing Strategy

- **Prefer integration tests** using real artifacts from `tests/_fixtures/` over unit tests with mocks
- Use pytest fixtures for setup
- Test artifacts include sample iOS (.xcarchive) and Android (.apk/.aab) files

## Feature Completion Requirements

A feature is not complete until:
1. All tests pass: `make test-unit`
2. All checks pass: `make check`
3. Code formatted: `make fix` if needed

## Adding New Insights

1. Create class in `insights/apple/` or `insights/android/`
2. Inherit from `Insight` base class
3. Implement `analyze()` returning `InsightResult`
4. Register in platform analyzer's insight list
5. Add integration tests
