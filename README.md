# App Size Analyzer

A CLI tool for analyzing iOS and Android app bundle sizes, providing detailed insights into file composition, binary structure, and optimization opportunities.

## Installation

### From Source

```bash
# Clone the repository
git clone <repository-url>
cd app-size-analyzer

# Install in development mode
pip install -e ".[dev]"
```

## Quick Start

### Analyze an iOS App

```bash
# Analyze a bundle
app-size-analyzer ios MyApp.xcarchive.zip

# Analyze a bundle with custom output location
app-size-analyzer ios MyApp.xcarchive.zip -o detailed-report.json

# Skip expensive operations for faster analysis
app-size-analyzer ios MyApp.xcarchive.zip --skip-swift-metadata --skip-symbols
```

### Command Line Options

```bash
app-size-analyzer ios [OPTIONS] INPUT_PATH

Options:
  -o, --output PATH           Output path for JSON report [default: analysis-report.json]
  --working-dir PATH          Working directory for temporary files
  --platform [ios|android]   Target platform (auto-detected if not specified)
  --skip-swift-metadata       Skip Swift metadata parsing
  --skip-symbols              Skip symbol extraction
  --format [json|table]       Output format [default: json]
  -v, --verbose               Enable verbose logging
  -q, --quiet                 Suppress all output except errors
  --help                      Show this message and exit
```

## Development

### Setup

```bash
# Clone and setup development environment
git clone <repository-url>
cd app-size-analyzer
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Code Quality

This project uses several tools to maintain code quality:

- **Black**: Code formatting
- **isort**: Import sorting
- **mypy**: Static type checking
- **flake8**: Linting
- **pytest**: Testing

Run all checks:

```bash
# Format code
black src tests
isort src tests

# Type checking
mypy src

# Linting
flake8 src tests

# Tests
pytest
```

### Testing

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
```

# Launchpad

Launchpad is a Sentry microservice for analyzing pre-production artifacts (like iOS and Android builds) and determining their size breakdown, similar to Emerge Tools.

This repository contains both:

- **🌐 Launchpad Web Service** - HTTP API for artifact analysis
- **⚡ CLI Tool** (`app-size-analyzer`) - Standalone command-line analysis

## Features

- **Multi-platform support**: Analyze iOS (.xcarchive.zip) and Android (.apk, .aab) artifacts
- **Dual interfaces**: Both web API and CLI for different use cases
- **Size breakdown**: Detailed component-level analysis showing what takes up space
- **RESTful API**: HTTP endpoints for artifact analysis
- **Health monitoring**: Built-in health checks for service monitoring
- **Kafka integration**: Event-driven architecture support
- **Redis caching**: For performance optimization

## Architecture

The service is built with:

- **Flask** - Web framework
- **LIEF** - Binary analysis library
- **Pydantic** - Data validation and settings
- **Structlog** - Structured logging
- **Gunicorn** - WSGI server for production

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/getsentry/launchpad.git
cd launchpad

# Install in development mode
make install-dev
```

## Quick Start

### CLI Tool Usage

The CLI tool provides direct analysis capabilities:

```bash
# Analyze an iOS app
app-size-analyzer ios MyApp.xcarchive.zip -o report.json

# Analyze with custom options
app-size-analyzer ios MyApp.xcarchive.zip --skip-swift-metadata --format table

# Show help
app-size-analyzer --help
app-size-analyzer ios --help
```

### Web Service Usage

Start the web service for API access:

```bash
# Start the development server
launchpad devserver --reload

# Or run with Docker Compose (includes Redis & Kafka)
docker-compose up

# Test the service
curl http://localhost:1218/health

# Upload file for analysis (when implemented)
curl -X POST -F "file=@MyApp.xcarchive.zip" http://localhost:1218/analyze
```

### Using devservices

If you're working within the Sentry ecosystem:

```bash
# Start with devservices
devservices up launchpad

# Check status
curl http://localhost:1218/health_envoy
```

## CLI Command Reference

```bash
app-size-analyzer [OPTIONS] COMMAND [ARGS]...

Commands:
  ios      Analyze an iOS app bundle (.xcarchive.zip)
  android  Analyze an Android app bundle (.apk, .aab) [Coming Soon]

iOS Options:
  -o, --output PATH           Output path for JSON report [default: ios-analysis-report.json]
  --working-dir PATH          Working directory for temporary files
  --skip-swift-metadata       Skip Swift metadata parsing for faster analysis
  --skip-symbols              Skip symbol extraction and analysis
  --format [json|table]       Output format [default: json]
  -v, --verbose               Enable verbose logging
  -q, --quiet                 Suppress all output except errors
```

## API Endpoints

- `GET /` - Service information
- `GET /health` - Basic health check
- `GET /health_envoy` - Health check for load balancers
- `POST /analyze` - Analyze an uploaded artifact

## Configuration

The service uses environment variables for configuration:

```bash
# Server
LAUNCHPAD_HOST=0.0.0.0
LAUNCHPAD_PORT=1218
DEBUG=false

# Dependencies
REDIS_HOST=localhost
REDIS_PORT=6379
DEFAULT_BROKERS=localhost:9092

# Analysis
MAX_FILE_SIZE=1073741824  # 1GB
TEMP_DIR=/tmp/launchpad
```

## Project Structure

```
src/
├── launchpad/              # Web service
│   ├── __init__.py         # Package initialization
│   ├── app.py              # Flask application setup
│   ├── cli.py              # Service CLI commands
│   ├── settings.py         # Configuration management
│   ├── analyzers/          # Web service analyzers (use CLI)
│   ├── models/             # API data models
│   ├── services/           # Business logic
│   └── utils/              # Utility functions
└── app_size_analyzer/      # CLI tool
    ├── __init__.py         # Package initialization
    ├── cli.py              # CLI commands
    ├── analyzers/          # Analysis engines
    ├── models/             # Data models
    └── utils/              # Utility functions
```

## Commands

```bash
# Development
make install-dev       # Install with dev dependencies
make test             # Run tests
make lint             # Check code quality
make format           # Format code

# CLI tool
app-size-analyzer ios /path/to/app.xcarchive.zip    # Analyze iOS app
app-size-analyzer android /path/to/app.apk          # Analyze Android app

# Web service management
launchpad devserver   # Start development server
launchpad health      # Check service health
launchpad config      # Show configuration

# Docker
docker-compose up     # Start with dependencies
docker build -t launchpad .  # Build container
```

## Development

### Prerequisites

- Python 3.11+
- Redis (for web service caching)
- Kafka (for web service events)

### Setup

```bash
# Clone and setup development environment
git clone https://github.com/getsentry/launchpad.git
cd launchpad
make install-dev

# Install pre-commit hooks
.venv/bin/pre-commit install
```

### Code Quality

This project uses several tools to maintain code quality:

- **Black**: Code formatting
- **isort**: Import sorting
- **mypy**: Static type checking
- **flake8**: Linting
- **pytest**: Testing

```bash
# Run all quality checks
make check

# Individual commands
make format     # Format code
make lint       # Run linting
make type-check # Type checking
```

## Testing

The service includes comprehensive tests:

```bash
# Run all tests
make test

# Run specific test types
make test-unit
make test-integration

# CLI tool tests
.venv/bin/python -m pytest tests/test_basic.py -v
```

Test artifacts are located in `test/artifacts/` for integration testing.

## Contributing

1. Follow Sentry's Python style guide
2. Add tests for new functionality
3. Use type hints throughout
4. Update documentation as needed

## License

This project is licensed under the same terms as Sentry.
