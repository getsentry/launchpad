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
# Analyze a .app bundle
app-size-analyzer ios MyApp.xcarchive.zip

# Analyze an .ipa file with custom output location
app-size-analyzer ios MyApp.ipa -o detailed-report.json

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