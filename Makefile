.PHONY: help test test-unit test-integration lint format type-check fix check-format check-types clean build build-wheel clean-venv check ci all run-cli status check-deps coverage

# Default target
help:
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Python and virtual environment setup
VENV_DIR := .venv
UV := uv
PYTHON_VENV := $(VENV_DIR)/bin/python

# Create virtual environment and install dependencies with uv
$(VENV_DIR):
	$(UV) venv

# Just used for CI
install-dev: $(VENV_DIR)
	$(UV) pip install -r requirements-dev.txt
	$(UV) pip install -e .
	$(PYTHON_VENV) scripts/deps
	$(VENV_DIR)/bin/pre-commit install

test:
	$(PYTHON_VENV) -m pytest tests/unit/ tests/integration/ -v --tb=short

test-unit:
	$(PYTHON_VENV) -m pytest tests/unit/ -v --tb=short

test-integration:
	$(PYTHON_VENV) -m pytest tests/integration/ -v --tb=short

coverage:
	$(PYTHON_VENV) -m pytest tests/unit/ tests/integration/ -v --tb=short --cov --cov-branch --cov-report=xml --junitxml=junit.xml

# Code quality targets (using ruff and ty)
check-lint:
	$(PYTHON_VENV) -m ruff check src/ tests/

check-format:  ## Check code format without modifying files
	$(PYTHON_VENV) -m ruff format --check src/ tests/

check-types:  ## Run type checking with ty
	$(PYTHON_VENV) -m ty check --error-on-warning src

check-deps:
	$(PYTHON_VENV) scripts/deps --check

fix:  ## Auto-fix code issues (format, remove unused imports, fix line endings)
	$(PYTHON_VENV) -m ruff format src/ tests/
	$(PYTHON_VENV) -m ruff check --fix src/ tests/

# Build targets
build: clean $(VENV_DIR)  ## Build the package
	$(UV) pip install build
	$(PYTHON_VENV) -m build

build-wheel:  ## Build wheel only
	$(PYTHON_VENV) -m build --wheel

# Maintenance targets
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
	rm -rf $(VENV_DIR)

# Combined targets for CI
check: check-lint check-format check-types check-deps

ci: install-dev check test

all: clean install-dev check test build

run-cli:  ## Run the CLI tool (use ARGS="..." to pass arguments, DEBUG=1 to run with debugger)
	@if [ "$(DEBUG)" = "1" ]; then \
		$(PYTHON_VENV) -m debugpy --listen 5678 --wait-for-client -m launchpad.cli $(ARGS); \
	else \
		$(PYTHON_VENV) -m launchpad.cli $(ARGS); \
	fi

serve:  ## Start the Launchpad server with proper Kafka configuration
	@echo "Ensuring Kafka topics exist..."
	$(PYTHON_VENV) scripts/ensure_kafka_topics.py
	@echo "Starting Launchpad server..."
	$(PYTHON_VENV) -m launchpad.cli serve --verbose

test-kafka-message:  ## Send a test message to Kafka (requires Kafka running)
	$(PYTHON_VENV) scripts/test_kafka.py --count 1

test-kafka-multiple:  ## Send multiple test messages to Kafka
	$(PYTHON_VENV) scripts/test_kafka.py --count 5 --interval 0

test-download-artifact:
	$(PYTHON_VENV) scripts/test_download_artifact.py --verbose

test-artifact-update:
	$(PYTHON_VENV) scripts/test_artifact_update.py --build-version "1.0.0" --build-number 42 --verbose

test-artifact-size-analysis-upload:
	$(PYTHON_VENV) scripts/test_artifact_size_analysis_upload.py --verbose

test-service-integration:  ## Run full integration test with devservices
	@echo "Starting Kafka services via devservices..."
	@devservices up
	@echo "Waiting for Kafka to be ready..."
	@sleep 10
	@echo "Starting Launchpad server in background..."
	@set -e; \
	$(PYTHON_VENV) -m launchpad.cli serve --verbose & \
	LAUNCHPAD_PID=$$!; \
	echo "Launchpad started with PID: $$LAUNCHPAD_PID"; \
	sleep 5; \
	echo "Sending test messages..."; \
	$(PYTHON_VENV) scripts/test_kafka.py --count 3 --interval 1; \
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

# Show current status
status:
	@echo "Python version: $$($(PYTHON_VENV) --version)"
	@echo "Virtual environment: $$(if [ -d $(VENV_DIR) ]; then echo 'exists'; else echo 'missing'; fi)"
	@echo "Pre-commit hooks: $$(if [ -f .git/hooks/pre-commit ]; then echo 'installed'; else echo 'not installed'; fi)"
	@echo "UV version: $$($(UV) --version 2>/dev/null || echo 'not installed')"
