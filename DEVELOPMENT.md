# Development Guide

This document explains how to set up your development environment and use the build system for the app-size-analyzer CLI tool.

## Quick Start

1. **Set up development environment:**
   ```bash
   make dev-setup
   ```

2. **Activate virtual environment:**
   ```bash
   source venv/bin/activate
   ```

3. **Run tests:**
   ```bash
   make test
   ```

## Available Commands

Run `make help` to see all available commands:

```bash
make help
```

### Development Setup

- `make dev-setup` - Set up complete development environment with dependencies and pre-commit hooks
- `make install` - Install the package in development mode
- `make install-dev` - Install development dependencies

### Testing

- `make test` - Run all tests (unit + integration)
- `make test-unit` - Run only unit tests
- `make test-integration` - Run only integration tests
- `make test-coverage` - Run tests with coverage report
- `make test-verbose` - Run tests with verbose output

### Code Quality

- `make check` - Run all code quality checks (lint + type-check)
- `make lint` - Run linting checks (flake8, isort, black)
- `make format` - Format code with black and isort
- `make type-check` - Run type checking with mypy

### Building

- `make build` - Build the package (wheel + source distribution)
- `make build-wheel` - Build wheel only

### Maintenance

- `make clean` - Clean build artifacts and cache files
- `make clean-venv` - Remove virtual environment
- `make status` - Show current project status

### CLI Testing

- `make run-cli ARGS="--help"` - Run the CLI with arguments

## GitHub Workflows

The project includes three GitHub workflows:

### 1. CI Workflow (`.github/workflows/ci.yml`)
- **Triggers:** Push to main, pull requests to main
- **What it does:**
  - Tests across Python 3.11 and 3.12
  - Runs linting, formatting checks, and type checking
  - Runs unit and integration tests
  - Generates coverage reports
  - Builds and tests package installation
  - Uploads build artifacts

### 2. Release Workflow (`.github/workflows/release.yml`)
- **Triggers:** Git tags starting with 'v' (e.g., v1.0.0)
- **What it does:**
  - Runs full test suite
  - Builds package
  - Publishes to PyPI (using trusted publishing)
  - Creates GitHub release with artifacts

### 3. Security Workflow (`.github/workflows/security.yml`)
- **Triggers:** 
  - Weekly schedule (Mondays at 9 AM UTC)
  - Changes to dependency files
  - Manual dispatch
- **What it does:**
  - Scans for known vulnerabilities with Safety and pip-audit
  - Runs security linter (Bandit)
  - Checks for outdated dependencies
  - Reviews dependency changes in PRs

## Development Workflow

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Set up development environment:**
   ```bash
   make dev-setup
   source venv/bin/activate
   ```

3. **Make your changes and test locally:**
   ```bash
   make check test
   ```

4. **Commit and push your changes:**
   ```bash
   git add .
   git commit -m "Your commit message"
   git push origin feature/your-feature-name
   ```

5. **Create a pull request**
   - The CI workflow will automatically run
   - Ensure all checks pass before merging

## Release Process

1. **Update version in `pyproject.toml`**

2. **Create and push a tag:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

3. **The release workflow will automatically:**
   - Run tests
   - Build the package
   - Publish to PyPI
   - Create a GitHub release

## Requirements

- Python 3.11 or 3.12
- Make (for using the Makefile)
- Git (for version control)

## Dependencies

All dependencies are managed through:
- `pyproject.toml` - Main project dependencies
- `requirements-dev.txt` - Legacy development dependencies file

The project uses modern Python packaging with:
- **Build system:** Hatchling
- **CLI framework:** Click
- **Binary analysis:** LIEF
- **Data validation:** Pydantic
- **Terminal UI:** Rich
- **Testing:** pytest
- **Code formatting:** Black + isort
- **Linting:** flake8
- **Type checking:** mypy

## Troubleshooting

### Virtual Environment Issues
```bash
make clean-venv
make dev-setup
```

### Dependency Issues
```bash
make clean
make install-dev
```

### Pre-commit Hook Issues
```bash
pre-commit uninstall
make install-dev  # This reinstalls hooks
```

### Test Failures
```bash
make test-verbose  # Get more detailed output
make test-coverage  # Check test coverage
```