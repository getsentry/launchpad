# Launchpad

A microservice for analyzing iOS and Android apps.

## Installation

### Development Setup

```bash
git clone https://github.com/getsentry/launchpad.git
cd launchpad
devenv sync
```

If you don't have devenv installed, [follow these instructions](https://github.com/getsentry/devenv#install).

### Using DevServices

DevServices provides shared Kafka infrastructure used by multiple Sentry services:

```bash
# Start shared dependencies (Kafka)
devservices up

# In another terminal, start the development service
launchpad devserver

# Or run integration tests
make test-service-integration

# Stop shared dependencies
devservices down
```

## Usage

### Service Endpoints

- `GET /health` - Basic health check
- `GET /ready` - Readiness check

### Analyze an Android App

```bash

# Analyze an APK, AAB or Zip containing a single APK or AAB
launchpad android app.apk
launchpad android app.aab
launchpad android zipped_aab.zip

# Analyze an apk with a custom output location
launchpad android app.apk -o detailed-report.json
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
launchpad ios path/to/app.xcarchive.zip
# Direct Android analysis
launchpad android path/to/app.apk
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

#### Local Environment Setup

First, set up your local environment variables:

```bash
# Copy the example environment file
cp env.local.example .env
```

#### Development Server Options

```bash
devservices up                  # Start Kafka via devservices
launchpad devserver             # Start combined service
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

## Production Deployment

For production Kubernetes deployments, use separate web and consumer components:

```bash
# Web server only (for web pods)
launchpad web-server --prod --host 0.0.0.0 --port 8080

# Consumer only (for worker pods)
launchpad consumer --prod
```

This architecture allows you to:

- Scale web servers independently from consumers
- Deploy different configurations for each component
- Optimize resource allocation per component type
- Achieve better fault isolation

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
