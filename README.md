# Launchpad

A microservice for analyzing iOS and Android apps.

## Installation

### Development Setup

```bash
git clone https://github.com/getsentry/launchpad.git
cd launchpad
make dev-setup
devenv sync
```

### Using DevServices

DevServices provides shared Kafka infrastructure used by multiple Sentry services:

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

### Service Endpoints

### Analyze an Android App

```bash

# Analyze an APK
launchpad android app.apk

# Analyze an apk with a custom output location
launchpad android app.apk -o detailed-report.json
```

### Analyze an iOS App
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
launchpad ios path/to/app.xcarchive.zip
# Custom output location
launchpad ios path/to/app.xcarchive.zip -o my-report.json

# Skip time-consuming analysis for faster results
launchpad ios path/to/app.xcarchive.zip --skip-swift-metadata --skip-symbols

Options:
  -o, --output PATH           Output path for JSON report [default: analysis-report.json]
  --working-dir PATH          Working directory for temporary files
  --platform [ios|android]    Target platform (auto-detected if not specified)
  --skip-swift-metadata       [iOS] Skip Swift metadata parsing
  --skip-symbols              [iOS] Skip symbol extraction
  --format [json|table]       Output format [default: json]
  -v, --verbose               Enable verbose logging
  -q, --quiet                 Suppress all output except errors
  --help                      Show this message and exit
```

## Development

### Service Development

```bash
# Development with shared infrastructure (recommended)
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

# Integration test with standalone setup
make test-integration-standalone
```

### Code Quality

```bash
# Format code
make format

# Lint and type check
make lint

# All quality checks (format + lint + type-check)
make check

# Full CI pipeline
make ci
```

## Configuration

### Environment Variables

- `LAUNCHPAD_HOST` - Server host (default: 0.0.0.0)
- `LAUNCHPAD_PORT` - Server port (default: 2218)
- `KAFKA_BOOTSTRAP_SERVERS` - Kafka bootstrap servers (default: localhost:9092)
- `KAFKA_GROUP_ID` - Kafka consumer group ID (default: launchpad-consumer)
- `KAFKA_TOPICS` - Comma-separated list of topics (default: launchpad-events)

### Topic Management

The service automatically creates required Kafka topics on startup with sensible defaults:

- **Topic**: `launchpad-events`
- **Partitions**: 1
- **Replication Factor**: 1
- **Retention**: 7 days

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
