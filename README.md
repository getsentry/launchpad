# App Size Analyzer

A CLI tool for analyzing iOS and Android app bundle sizes, providing detailed insights into file composition, binary structure, and optimization opportunities.

## Features

- **Cross-platform Analysis**: Support for iOS (.app, .ipa) and Android (.apk, .aab) app bundles
- **Detailed File Analysis**: File type breakdown, duplicate detection, and size optimization suggestions
- **Binary Analysis**: Mach-O parsing with LIEF for architecture, symbols, and Swift metadata extraction
- **Rich Output**: JSON export and beautiful console tables with Rich
- **Performance Focused**: Efficient analysis with minimal memory footprint
- **Type Safe**: Full type annotations with Pydantic models and mypy validation

## Installation

### From Source

```bash
# Clone the repository
git clone <repository-url>
cd app-size-analyzer

# Install in development mode
pip install -e ".[dev]"
```

### From PyPI (when published)

```bash
pip install app-size-analyzer
```

## Quick Start

### Analyze an iOS App

```bash
# Analyze a .app bundle
app-size-analyzer analyze MyApp.app

# Analyze an .ipa file
app-size-analyzer analyze MyApp.ipa -o detailed-report.json

# Skip expensive operations for faster analysis
app-size-analyzer analyze MyApp.app --skip-swift-metadata --skip-symbols
```

### Command Line Options

```bash
app-size-analyzer analyze [OPTIONS] INPUT_PATH

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

## Output Format

The tool generates comprehensive JSON reports with the following structure:

```json
{
  "app_info": {
    "name": "MyApp",
    "bundle_id": "com.example.myapp",
    "version": "1.0.0",
    "build": "100",
    "executable": "MyApp",
    "minimum_os_version": "14.0",
    "supported_platforms": ["iPhoneOS"],
    "sdk_version": "iphoneos17.0"
  },
  "file_analysis": {
    "total_size": 52428800,
    "file_count": 1247,
    "files_by_type": {
      "png": [...],
      "nib": [...],
      "plist": [...]
    },
    "duplicate_files": [...],
    "largest_files": [...]
  },
  "binary_analysis": {
    "executable_size": 31457280,
    "architectures": ["arm64"],
    "linked_libraries": [...],
    "symbols": [...],
    "swift_metadata": {...},
    "sections": {...}
  },
  "generated_at": "2024-01-15T10:30:00Z",
  "analysis_duration": 12.34
}
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

# Run with coverage
pytest --cov=app_size_analyzer

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
```

### Project Structure

```
app-size-analyzer/
├── src/app_size_analyzer/          # Main package
│   ├── analyzers/                  # Platform-specific analyzers
│   │   ├── ios.py                  # iOS analyzer with LIEF
│   │   └── android.py              # Android analyzer (future)
│   ├── models/                     # Pydantic data models
│   │   └── results.py              # Analysis result models
│   ├── utils/                      # Utilities
│   │   ├── file_utils.py          # File operations
│   │   └── logging.py             # Logging setup
│   ├── cli.py                     # Click CLI interface
│   └── __init__.py
├── tests/                         # Test suite
│   ├── unit/                      # Unit tests
│   ├── integration/               # Integration tests
│   └── artifacts/                 # Test artifacts
├── pyproject.toml                 # Project configuration
└── README.md
```

## Requirements

- **Python**: 3.11+
- **Operating System**: macOS, Linux
- **Dependencies**:
  - `click`: CLI framework
  - `lief`: Binary analysis
  - `pydantic`: Data validation
  - `rich`: Terminal formatting

## Performance

The analyzer is optimized for performance:

- **Streaming analysis**: Large files are processed in chunks
- **Parallel processing**: Where applicable, operations run concurrently  
- **Memory efficient**: Minimal memory footprint even for large apps
- **Selective analysis**: Skip expensive operations with flags for faster results

## Roadmap

- [ ] Android APK/AAB analysis support
- [ ] Advanced Swift metadata parsing
- [ ] Symbol demangling and analysis
- [ ] Size optimization recommendations
- [ ] Integration with CI/CD pipelines
- [ ] Web dashboard for results visualization

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Run the test suite: `pytest`
5. Run code quality checks: `black src tests && mypy src`
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **LIEF**: For excellent binary analysis capabilities
- **Emerge Tools**: For inspiration from the original Swift implementation
- **Sentry**: For supporting this open source project