UV=uv
UVX=uvx
PYTHON=$(UV) run python
RUN_PYTHON_MODULE=uv run

# Default target
.PHONY: help
help:
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install-dev:
	devenv sync

# Python, uv, and Python requirements (core and dev) installed via
# the github workflow.
install-dev-for-ci:
	$(PYTHON) scripts/deps

.PHONY: test
test:
	$(RUN_PYTHON_MODULE) pytest -n auto tests/unit/ tests/integration/ -v

.PHONY: test-unit
test-unit:
	$(RUN_PYTHON_MODULE) pytest -n auto tests/unit/ -v

.PHONY: test-integration
test-integration:
	$(RUN_PYTHON_MODULE) pytest -n auto tests/integration/ -v

.PHONY: coverage
coverage:
	$(RUN_PYTHON_MODULE) pytest tests/unit/ tests/integration/ -v --cov --cov-branch --cov-report=xml --junitxml=junit.xml

# Code quality targets (using ruff and ty)
.PHONY: check-lint
check-lint:
	$(RUN_PYTHON_MODULE) ruff check src/ tests/

# Check code format without modifying files
.PHONY: check-format
check-format:
	$(RUN_PYTHON_MODULE) ruff format --check src/ tests/

# Run type checking with ty
.PHONY: check-types
check-types:
	$(RUN_PYTHON_MODULE) ty check --error-on-warning src

# Check deps are up to date.
.PHONY: check-deps
check-deps:
	$(PYTHON) scripts/deps --check

# Run all check-* targets
.PHONY: check
check: check-lint check-format check-types check-deps

# Auto-fix code issues (format, remove unused imports, fix line endings)
.PHONY: fix
fix:
	$(RUN_PYTHON_MODULE) ruff format src/ tests/
	$(RUN_PYTHON_MODULE) ruff check --fix src/ tests/

.PHONY: build
build:
	$(UV) build

.PHONY: build-wheel
build-wheel:
	$(UV) build --wheel

# Maintenance targets
.PHONY: clean
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .ty_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

.PHONY: ci
ci: install-dev check test build

.PHONY: all
all: clean install-dev check test build

.PHONY: run-cli
run-cli:  ## Run the CLI tool (use ARGS="..." to pass arguments, DEBUG=1 to run with debugger)
	@if [ "$(DEBUG)" = "1" ]; then \
		$(RUN_PYTHON_MODULE) debugpy --listen 5678 --wait-for-client -m launchpad.cli $(ARGS); \
	else \
		$(RUN_PYTHON_MODULE) launchpad.cli $(ARGS); \
	fi

.PHONY: serve
serve:  ## Start the Launchpad server with proper Kafka configuration
	@echo "Ensuring Kafka topics exist..."
	$(PYTHON) scripts/ensure_kafka_topics.py
	@echo "Starting Launchpad server..."
	$(RUN_PYTHON_MODULE) launchpad.cli serve --verbose

# Send a test message to Kafka (requires Kafka running)z
.PHONY: test-kafka-message
test-kafka-message:
	$(PYTHON) scripts/test_kafka.py --count 1


# Send multiple test messages to Kafka
.PHONY: test-kafka-multiple
test-kafka-multiple:
	$(PYTHON) scripts/test_kafka.py --count 5 --interval 0

.PHONY: test-download-artifact
test-download-artifact:
	$(PYTHON) scripts/test_download_artifact.py --verbose

.PHONY: test-artifact-update
test-artifact-update:
	$(PYTHON) scripts/test_artifact_update.py --build-version "1.0.0" --build-number 42 --verbose

.PHONY: test-artifact-size-analysis-upload
test-artifact-size-analysis-upload:
	$(PYTHON) scripts/test_artifact_size_analysis_upload.py --verbose

# Run full integration test with devservices
.PHONY: test-service-integration
test-service-integration:
	@echo "Starting Kafka services via devservices..."
	@devservices up
	@echo "Waiting for Kafka to be ready..."
	@sleep 10
	@echo "Starting Launchpad server in background..."
	@set -e; \
	$(PYTHON) -m launchpad.cli serve --verbose & \
	LAUNCHPAD_PID=$$!; \
	echo "Launchpad started with PID: $$LAUNCHPAD_PID"; \
	sleep 5; \
	echo "Sending test messages..."; \
	$(PYTHON) scripts/test_kafka.py --count 3 --interval 1; \
	sleep 5; \
	echo "Stopping Launchpad gracefully..."; \
	kill -TERM $$LAUNCHPAD_PID 2>/dev/null && echo "SIGTERM sent" || echo "Process not found"; \
	sleep 8; \
	if kill -0 $$LAUNCHPAD_PID 2>/dev/null; then \
		echo "Process still running, sending SIGKILL..."; \
		kill -KILL $$LAUNCHPAD_PID 2>/dev/null || true; \
		sleep 2; \
	fi; \
	echo "Stopping devservices..."; \
	devservices down

# Build GoCD pipelines
.PHONY: gocd
gocd:
	rm -rf ./gocd/generated-pipelines
	mkdir -p ./gocd/generated-pipelines
	cd ./gocd/templates && jb install && jb update
	# Format
	find . -type f \( -name '*.libsonnet' -o -name '*.jsonnet' \) -print0 | xargs -n 1 -0 jsonnetfmt -i
	# Lint
	find . -type f \( -name '*.libsonnet' -o -name '*.jsonnet' \) -print0 | xargs -n 1 -0 jsonnet-lint -J ./gocd/templates/vendor
	# Build
	cd ./gocd/templates && find . -type f \( -name '*.jsonnet' \) -print0 | xargs -n 1 -0 jsonnet --ext-code output-files=true -J vendor -m ../generated-pipelines
	# Convert JSON to yaml
	cd ./gocd/generated-pipelines && find . -type f \( -name '*.yaml' \) -print0 | xargs -n 1 -0 yq -p json -o yaml -i

# Show current status
.PHONY: status
status:
	@echo "Python version: $$($(PYTHON) --version)"
	@echo "Virtual environment: $$(if [ -d .venv ]; then echo 'exists'; else echo 'missing'; fi)"
	@echo "Pre-commit hooks: $$(if [ -f .git/hooks/pre-commit ]; then echo 'installed'; else echo 'not installed'; fi)"
	@echo "UV version: $$($(UV) --version 2>/dev/null || echo 'not installed')"


