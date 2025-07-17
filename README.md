# Launchpad

A microservice for analyzing iOS and Android apps.

[![codecov](https://codecov.io/gh/getsentry/launchpad/graph/badge.svg?token=iF5K92yaUu)](https://codecov.io/gh/getsentry/launchpad)

## Installation

### Development Setup

```bash
git clone https://github.com/getsentry/launchpad.git
cd launchpad
devenv sync
```

If you don't have devenv installed, [follow these instructions](https://github.com/getsentry/devenv#install).

### Using devservices

[devservices](https://github.com/getsentry/devservices) provides shared Kafka infrastructure used by multiple Sentry services:

```bash
# Start shared dependencies (Kafka)
devservices up

# In another terminal, start the service
launchpad serve

# Or run integration tests
make test-service-integration

# Stop shared dependencies
devservices down
```

## Usage

### Analyze an Android App

```bash

# Analyze an apk with a custom output location
```

### Testing Kafka Integration

- `GET /health` - Basic health check
- `GET /ready` - Readiness check

### Testing Kafka Integration

```bash
# Send a test message to Kafka
make test-kafka-message

# Send multiple test messages
make test-kafka-multiple
```

### CLI Analysis (Development)

```bash
# Direct iOS analysis
launchpad size path/to/app.xcarchive.zip

# Analyze an APK, AAB or Zip containing a single APK or AAB
launchpad size path/to/app.apk
launchpad size path/to/app.aab
launchpad size path/to/zipped_aab.zip

# Skip time-consuming analysis for faster results
launchpad size path/to/app.xcarchive.zip --skip-swift-metadata --skip-symbols

# Custom output location
launchpad size path/to/app.xcarchive.zip -o my-report.json
launchpad size app.apk -o detailed-report.json
```

### Usage

```
$ launchpad size --help
Usage: launchpad size [OPTIONS] INPUT_PATH

  Analyze provided artifact and generate a size report.

Options:
  -o, --output FILENAME      Output path for the analysis.  [default: -]
  -v, --verbose              Enable verbose logging output.
  -q, --quiet                Suppress all output except errors.
  --format [json|table]      Output format for results.  [default: json]
  --working-dir PATH         Working directory for temporary files (default:
                             system temp).
  --skip-swift-metadata      Skip Swift metadata parsing for faster analysis.
  --skip-symbols             Skip symbol extraction and analysis.
  --skip-component-analysis  Skip detailed binary component analysis for
                             faster processing.
  --skip-treemap             Skip treemap generation for hierarchical size
                             analysis.
  --help                     Show this message and exit.
```

## Development

### Service Development

```bash
# Development with shared infrastructure
devservices up                  # Start Kafka via devservices
launchpad serve
```

### Testing

```bash
# All tests (unit + integration)
make test

# Unit tests only
make test-unit

# Integration tests only
make test-integration

# Integration test with devservices
make test-service-integration
```

### Code Quality

```bash
# Run all quality checks (check-format + check-lint + check-types)
make check

# Autofix as many checks as possible.
make fix

# Full CI pipeline
make ci
```
