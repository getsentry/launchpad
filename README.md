# Launchpad

A service for analyzing iOS and Android apps.

[![codecov](https://codecov.io/gh/getsentry/launchpad/graph/badge.svg?token=iF5K92yaUu)](https://codecov.io/gh/getsentry/launchpad)

## Installation

### Environment setup

```bash
git clone https://github.com/getsentry/launchpad.git
cd launchpad

# Installs our local dependencies
devenv sync
```

If you don't have devenv installed, [follow these instructions](https://github.com/getsentry/devenv#install).

### Using devservices

[devservices](https://github.com/getsentry/devservices) manages the dependencies used by Launchpad:

```bash
# Start dependency containers (e.g. Kafka)
devservices up

# Begin listening for messages (Kafka mode)
make serve

# Or run the TaskWorker instead
make worker

# Stop containers
devservices down
```

## Usage

Launchpad can run in two operational modes:

- **Kafka mode** (`launchpad serve`): HTTP server + Kafka consumer. This is the existing production mode that runs alongside the [Sentry monolith](https://github.com/getsentry/sentry).
- **TaskWorker mode** (`launchpad worker`): TaskWorker only, no HTTP server. This is a lighter-weight mode that receives work via the TaskBroker RPC interface instead of Kafka.

### Running in Kafka mode

```bash
devservices up
make serve
# or: launchpad serve --dev
```

### Running in TaskWorker mode

Requires `LAUNCHPAD_WORKER_RPC_HOST` and `LAUNCHPAD_WORKER_CONCURRENCY` environment variables (already configured in `.envrc`).

The TaskBroker handles task distribution and dispatches work to the worker via RPC. A single worker instance processes tasks in parallel — `LAUNCHPAD_WORKER_CONCURRENCY` controls how many child processes run simultaneously (e.g., 16 means up to 16 artifacts processed in parallel).

```bash
make worker
# or: launchpad worker -v
```

### One-off analysis

Alternatively for a one-off analysis, such as a local size analysis, you can invoke our various CLI subcommands.

### Size command

```bash
# iOS analysis
launchpad size path/to/app.xcarchive.zip

# Android analysis (AAB preferred)
launchpad size path/to/app.aab
launchpad size path/to/zipped_aab.zip
launchpad size path/to/app.apk

# Skip time-consuming analysis for faster results
launchpad size path/to/app.xcarchive.zip --skip-swift-metadata --skip-symbols

# Custom output location
launchpad size path/to/app.xcarchive.zip -o my-report.json
launchpad size app.apk -o detailed-report.json
```

See `launchpad size --help` for all options:

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

For full end-to-end development alongside the Sentry monolith, first run `sentry` in one terminal:

```bash
devenv sync
devservices up --mode ingest
devservices serve --workers
```

Next run `launchpad` in another terminal using either mode:

```bash
# Kafka mode (HTTP server + Kafka consumer)
devservices up
make serve

# TaskWorker mode (TaskWorker only, no HTTP server)
make worker
```

And finally use the `sentry-cli` (version 3.0.1 or higher) to upload to your local machine:

```bash
sentry-cli --log-level DEBUG \
  --url http://dev.getsentry.net:8000/ \
  --auth-token $SENTRY_TOKEN \
  build upload YourBuild.xcarchive \
  --org sentry \
  --project internal
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

## License

See [License](./LICENSE) for information about Sentry's licensing.

This project also uses compiled binaries for `strip` and `ld`. The source code of these is available at [https://github.com/tpoechtrager/cctools-port](https://github.com/tpoechtrager/cctools-port) and falls under the Apple Public Source License Version 2.0.

This project uses FFmpeg for audio and video processing. FFmpeg is licensed under the LGPL v2.1+ license. We do not distribute or modify FFmpeg; it is installed as a system dependency via package managers. For more information about FFmpeg licensing, see [https://ffmpeg.org/legal.html](https://ffmpeg.org/legal.html).
