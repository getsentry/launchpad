.PHONY: help test test-unit test-integration lint format autofix check-format type-check clean build build-wheel clean-venv check ci all run-cli status

# Default target
help:
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Python and virtual environment setup
VENV_DIR := .venv
PIP := $(VENV_DIR)/bin/pip
PYTHON_VENV := $(VENV_DIR)/bin/python

# Kafka configuration for local development
export KAFKA_BOOTSTRAP_SERVERS ?= localhost:9092
export KAFKA_GROUP_ID ?= launchpad-consumer
export KAFKA_TOPICS ?= launchpad-events

# # Create virtual environment
$(VENV_DIR):
	python -m venv $(VENV_DIR)
# Create virtual environment if it doesn't exist
# $(VENV_DIR):
# 	$(PYTHON) -m venv $(VENV_DIR)
# 	$(PIP) install --upgrade pip setuptools wheel

# Just used for CI
install-dev: $(VENV_DIR)  ## Install development dependencies
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .
	$(VENV_DIR)/bin/pre-commit install

test: test-unit test-integration

test-unit:
	$(PYTHON_VENV) -m pytest tests/unit/ -v --tb=short

test-integration:  ## Run integration tests only
	@if [ -d tests/integration ]; then \
		$(PYTHON_VENV) -m pytest tests/integration/ -v --tb=short; \
	else \
		echo "No integration tests found in tests/integration/. Skipping integration tests."; \
	fi

# Code quality targets
lint:  ## Run linting checks
	$(PYTHON_VENV) -m flake8 src/ tests/

format:  ## Format code with black and isort
	$(PYTHON_VENV) -m isort src/ tests/
	$(PYTHON_VENV) -m black src/ tests/

autofix:  ## Auto-fix code issues (format, remove unused imports, fix line endings)
	$(PYTHON_VENV) -m isort src/ tests/
	$(PYTHON_VENV) -m black src/ tests/

check-format:  ## Check code format without modifying files
	$(PYTHON_VENV) -m isort --check-only src/ tests/
	$(PYTHON_VENV) -m black --check src/ tests/

type-check:  ## Run type checking with mypy
	$(PYTHON_VENV) -m mypy src

# Build targets
build: clean $(VENV_DIR)  ## Build the package
	$(PIP) install build
	$(PYTHON_VENV) -m build

build-wheel:  ## Build wheel only
	$(PYTHON_VENV) -m build --wheel

# Maintenance targets
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf $(VENV_DIR)

# Combined targets for CI
check: autofix lint type-check

ci: install-dev check test

all: clean install-dev check test build

run-cli:  ## Run the CLI tool (use ARGS="..." to pass arguments, DEBUG=1 to run with debugger)
	@if [ "$(DEBUG)" = "1" ]; then \
		$(PYTHON_VENV) -m debugpy --listen 5678 --wait-for-client -m launchpad.cli $(ARGS); \
	else \
		$(PYTHON_VENV) -m launchpad.cli $(ARGS); \
	fi

serve:  ## Start the Launchpad server with proper Kafka configuration
	$(PYTHON_VENV) -m launchpad.cli serve --verbose

test-kafka-message:  ## Send a test message to Kafka (requires Kafka running)
	$(PYTHON_VENV) scripts/test_kafka.py --count 1

test-kafka-multiple:  ## Send multiple test messages to Kafka
	$(PYTHON_VENV) scripts/test_kafka.py --count 5 --interval 0

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
	@echo "Python version: $$($(PYTHON) --version)"
	@echo "Virtual environment: $$(if [ -d $(VENV_DIR) ]; then echo 'exists'; else echo 'missing'; fi)"
	@echo "Pre-commit hooks: $$(if [ -f .git/hooks/pre-commit ]; then echo 'installed'; else echo 'not installed'; fi)"
