# Launchpad - Claude Code Instructions

## Project Overview

**Launchpad** is a Python-based microservice for analyzing iOS and Android app bundle sizes. It provides detailed analysis of app binaries, generates optimization insights, and offers size breakdowns with visualization capabilities. This is a Sentry internal service that processes mobile app artifacts for size analysis.

## Architecture & Components

### Core Architecture
- **CLI Tool**: Primary interface for local analysis (`launchpad size`, `launchpad serve`)
- **Web Service**: HTTP server with health endpoints and Kafka consumer for processing analysis requests
- **Analysis Engine**: Platform-specific analyzers for iOS (.xcarchive) and Android (.apk/.aab) apps
- **Insights Engine**: Generates optimization recommendations for reducing app size
- **Visualization**: React-based web frontend for displaying treemap visualizations and analysis results. This is only for local testing and not a production frontend.

### Key Components

#### 1. Artifact Processing (`src/launchpad/artifacts/`)
- **Apple**: Handles `.xcarchive.zip` files, extracts Mach-O binaries, frameworks, and resources
- **Android**: Processes `.apk` and `.aab` files, analyzes DEX files, resources, and manifests
- **Factory Pattern**: `ArtifactFactory` dynamically creates appropriate artifact handlers

#### 2. Binary Parsers (`src/launchpad/parsers/`)
- **Apple/Mach-O**: Uses LIEF library to parse Mach-O binaries, extract symbols, Swift metadata
- **Android/DEX**: Custom DEX file parsers for method/class analysis and code size calculation
- **Symbol Analysis**: Objective-C and Swift symbol type aggregators for detailed breakdowns

#### 3. Size Analyzers (`src/launchpad/size/analyzers/`)
- **AppleAppAnalyzer**: Comprehensive iOS app analysis including binary components, frameworks, resources
- **AndroidAnalyzer**: Android app analysis covering DEX files, resources, native libraries
- **Treemap Generation**: Hierarchical size visualization data structure creation

#### 4. Insights Engine (`src/launchpad/size/insights/`)
- **Platform-specific**: iOS and Android optimization recommendations
- **Common**: Cross-platform insights (duplicate files, large media, debug info)
- **Examples**: Image optimization, symbol stripping, localized strings minification, unnecessary files detection

#### 5. Service Layer (`src/launchpad/service.py`)
- **Kafka Integration**: Consumes artifact events from `preprod-artifact-events` topic
- **HTTP Server**: Provides `/health` and `/ready` endpoints
- **Retry Logic**: Handles failed processing with exponential backoff
- **Sentry Integration**: Error tracking and monitoring

### Technology Stack

#### Backend (Python 3.13+)
- **LIEF**: Binary analysis library for Mach-O/ELF parsing
- **Pillow**: Image processing and optimization
- **Kafka**: Event streaming via confluent-kafka and sentry-arroyo
- **aiohttp**: Async HTTP server framework
- **Click**: CLI framework
- **Pydantic**: Data validation and serialization
- **Rich**: Terminal output formatting
- **FFmpeg**: Audio processing for compression analysis (system dependency)

#### Frontend (React/TypeScript)
- **React 19**: UI framework
- **TypeScript**: Type safety
- **ECharts**: Treemap visualization library
- **Vite**: Build tool and dev server

#### Infrastructure
- **Docker**: Containerized deployment
- **Google Cloud Build**: CI/CD pipeline
- **devservices**: Local development with shared Kafka infrastructure
- **GoCD**: Pipeline orchestration (jsonnet-based configuration)

## Development Workflow

### Environment Setup
```bash
# Clone and setup
git clone https://github.com/getsentry/launchpad.git
cd launchpad
devenv sync  # or manual setup below

# Manual setup
make install-dev
source .venv/bin/activate
```

### Git Workflow
**IMPORTANT**: Always start new feature work from the latest main branch:
```bash
git checkout main
git pull origin main
git checkout -b feature/your-feature-name
```

### Development Commands
```bash
# Code quality
make check          # Run all checks (lint, format, types, deps)
make fix            # Auto-fix issues (format, imports, etc.)
make check-lint     # Ruff linting
make check-format   # Code formatting check
make check-types    # Type checking with 'ty'

# Testing
make test           # All tests (unit + integration)
make test-unit      # Unit tests only
make test-integration # Integration tests only
make test-service-integration # Full service test with Kafka

# Service development
devservices up      # Start shared Kafka infrastructure
make serve          # Start Launchpad server
make test-kafka-message # Send test Kafka message
```

### CLI Usage
```bash
# Analyze iOS app
launchpad size path/to/app.xcarchive.zip

# Analyze Android app
launchpad size path/to/app.apk
launchpad size path/to/app.aab

# Performance options
launchpad size app.xcarchive.zip --skip-swift-metadata --skip-symbols

# Output options
launchpad size app.xcarchive.zip -o report.json --format json
```

## Key Files & Directories

### Configuration
- `/pyproject.toml` - Project metadata, dependencies, tool configuration (ruff, pytest, ty)
- `/Makefile` - Development workflow automation
- `/requirements.txt` - Python dependencies
- `/devservices/config.yml` - Local Kafka infrastructure setup

### Core Implementation
- `/src/launchpad/cli.py` - Main CLI entry point
- `/src/launchpad/service.py` - Web service orchestrator
- `/src/launchpad/size/analyzers/` - Platform-specific analysis engines
- `/src/launchpad/parsers/` - Binary parsing implementations
- `/src/launchpad/size/insights/` - Optimization recommendation engine

### Testing
- `/tests/unit/` - Unit tests
- `/tests/integration/` - Integration tests
- `/tests/_fixtures/` - Test artifacts (sample .apk, .xcarchive files)

### Web Frontend
- `/web/` - React application for visualization
- `/web/src/components/TreemapVisualization.tsx` - Main treemap component

## Data Models

### Analysis Results
- **AppleAnalysisResults**: iOS-specific analysis output
- **AndroidAnalysisResults**: Android-specific analysis output
- **BaseAppInfo**: Common app metadata (name, version, build info)
- **TreemapElement**: Hierarchical size representation for visualization

### Key Entities
- **BinaryComponent**: Individual binary analysis (symbols, sections, metadata)
- **FileInfo**: File-level analysis (path, size, type, hash)
- **InsightResult**: Optimization recommendation with size savings potential

## Development Guidelines

### Code Style
- **Python**: Ruff for linting and formatting (120 char line length)
- **Modern Python**: Always use the latest Python features when possible (project uses Python 3.13+)
- **Type Checking**: Uses 'ty' instead of mypy
- **Import Organization**: isort via ruff
- **Empty `__init__.py`**: Preferred pattern (see PR #56)
- **Comments**: Only add useful comments that explain complex logic or important business decisions. Avoid noise like "// Set variable" or references to legacy implementations

### Testing Strategy
- **Unit Tests**: Fast, isolated component testing
- **Integration Tests**: End-to-end analysis workflows
- **Fixtures**: Real app artifacts for comprehensive testing
- **Service Tests**: Full Kafka integration testing

### Feature Completion Requirements
**CRITICAL**: A feature is not considered complete until:
1. **All tests pass**: Run `make test-unit` (or `make test` for full suite) with zero failures
2. **Code quality checks pass**: Run `make check` to ensure all linting, formatting, and type checking passes
3. **No formatting issues**: Code must be properly formatted with `make fix` if needed

Features with failing tests or code quality issues should not be considered ready for review or production.

### Error Handling
- **Sentry Integration**: Automatic error tracking
- **Retry Logic**: Exponential backoff for transient failures
- **Graceful Degradation**: Continue analysis even if some components fail
- **Detailed Logging**: Rich console output with performance tracing

## Common Tasks

### Adding New Insights
1. Create insight class in appropriate platform directory (`insights/apple/` or `insights/android/`)
2. Inherit from `Insight` base class
3. Implement `analyze()` method returning `InsightResult`
4. Register in platform analyzer's insight list
5. Add unit tests

### Adding Binary Format Support
1. Create parser in `parsers/` directory
2. Implement format-specific parsing logic
3. Update `ArtifactFactory` to handle new format
4. Add corresponding analyzer support
5. Create test fixtures and integration tests

### Performance Optimization
- Use `@trace` decorator for performance monitoring
- Implement incremental parsing for large binaries
- Cache expensive operations (symbol demangling, metadata parsing)
- Consider skip flags for development (`--skip-symbols`, `--skip-swift-metadata`)

## Integration Points

### Kafka
- **Topic**: `preprod-artifact-events`
- **Schema**: `sentry-kafka-schemas.PreprodArtifactEvents`
- **Consumer Group**: Configurable via `KAFKA_GROUP_ID`

### Sentry API
- Uploads analysis results via `SentryClient`
- Handles authentication and retry logic
- Supports both artifact updates and size analysis uploads

### devservices
- Shared Kafka infrastructure for local development
- Automatic topic creation and configuration
- Integration with other Sentry services

This document should provide sufficient context for Claude Code instances to effectively work with the Launchpad codebase, understanding its architecture, development workflows, and integration patterns.
