.PHONY: help test test-unit test-integration lint format type-check fix check-format check-types clean build build-wheel clean-venv check ci all run-cli status check-deps coverage gocd

# Default target
help:
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

VENV_DIR := .venv

install-dev: ## Install all dependencies including dev tools
	uv sync --group dev
	$(VENV_DIR)/bin/python scripts/deps
	$(VENV_DIR)/bin/pre-commit install

test:
	uv run pytest -n auto tests/unit/ tests/integration/ -v

test-unit:
	uv run pytest -n auto tests/unit/ -v

test-integration:
	uv run pytest -n auto tests/integration/ -v

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
	uv run pytest tests/unit/ tests/integration/ -v --cov --cov-branch --cov-report=xml --junitxml=junit.xml

# Code quality targets (using ruff and ty)
check-lint:
	uv run ruff check src/ tests/

check-format:  ## Check code format without modifying files
	uv run ruff format --check src/ tests/

check-types:  ## Run type checking with ty
	uv run ty check --error-on-warning src

check-deps:
	uv run python scripts/deps --check

fix:  ## Auto-fix code issues (format, remove unused imports, fix line endings)
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

# Build targets
build: clean  ## Build the package
	uv build

build-wheel:  ## Build wheel only
	uv build --wheel

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
		uv run python -m debugpy --listen 5678 --wait-for-client -m launchpad.cli $(ARGS); \
	else \
		uv run launchpad $(ARGS); \
	fi

worker:  ## Start the Launchpad TaskWorker
	@echo "Starting Launchpad TaskWorker..."
	uv run launchpad worker --verbose

test-download-artifact:
	uv run python scripts/test_download_artifact.py --verbose

test-artifact-update:
	uv run python scripts/test_artifact_update.py --build-version "1.0.0" --build-number 42 --verbose

test-artifact-size-analysis-upload:
	uv run python scripts/test_artifact_size_analysis_upload.py --verbose

# Show current status
status:
	@echo "Python version: $$(uv run python --version)"
	@echo "Virtual environment: $$(if [ -d $(VENV_DIR) ]; then echo 'exists'; else echo 'missing'; fi)"
	@echo "Pre-commit hooks: $$(if [ -f .git/hooks/pre-commit ]; then echo 'installed'; else echo 'not installed'; fi)"
	@echo "UV version: $$(uv --version 2>/dev/null || echo 'not installed')"


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
