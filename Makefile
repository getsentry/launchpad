.PHONY: help test test-unit test-integration lint format type-check fix check-format check-types clean build build-wheel clean-venv check ci all run-cli status check-deps coverage gocd

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

install-dev: $(VENV_DIR)
	$(UV) pip install -r requirements-dev.txt
	$(UV) pip install -e .
	$(PYTHON_VENV) scripts/deps
	$(VENV_DIR)/bin/pre-commit install

test:
	$(PYTHON_VENV) -m pytest -n auto tests/unit/ tests/integration/ -v

test-unit:
	$(PYTHON_VENV) -m pytest -n auto tests/unit/ -v

test-integration:
	$(PYTHON_VENV) -m pytest -n auto tests/integration/ -v

test-e2e:  ## Run E2E tests with Docker Compose
	@echo "Starting E2E test environment..."
	docker compose -f docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from e2e-tests
	@echo "Cleaning up E2E environment..."
	docker compose -f docker-compose.e2e.yml down -v

test-e2e-up:  ## Start E2E environment (for debugging)
	docker compose -f docker-compose.e2e.yml up --build

test-e2e-down:  ## Stop E2E environment
	docker compose -f docker-compose.e2e.yml down -v

test-e2e-logs:  ## Show logs from E2E environment
	docker compose -f docker-compose.e2e.yml logs -f

coverage:
	$(PYTHON_VENV) -m pytest tests/unit/ tests/integration/ -v --cov --cov-branch --cov-report=xml --junitxml=junit.xml

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

worker:  ## Start the Launchpad TaskWorker
	@echo "Starting Launchpad TaskWorker..."
	$(PYTHON_VENV) -m launchpad.cli worker --verbose

test-download-artifact:
	$(PYTHON_VENV) scripts/test_download_artifact.py --verbose

test-artifact-update:
	$(PYTHON_VENV) scripts/test_artifact_update.py --build-version "1.0.0" --build-number 42 --verbose

test-artifact-size-analysis-upload:
	$(PYTHON_VENV) scripts/test_artifact_size_analysis_upload.py --verbose

# Show current status
status:
	@echo "Python version: $$($(PYTHON_VENV) --version)"
	@echo "Virtual environment: $$(if [ -d $(VENV_DIR) ]; then echo 'exists'; else echo 'missing'; fi)"
	@echo "Pre-commit hooks: $$(if [ -f .git/hooks/pre-commit ]; then echo 'installed'; else echo 'not installed'; fi)"
	@echo "UV version: $$($(UV) --version 2>/dev/null || echo 'not installed')"


gocd: ## Build GoCD pipelines
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
