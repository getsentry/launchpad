# Development Guide

## Quick Start

1. **Set up development environment:**
   ```bash
   make dev-setup
   ```

2. **Activate virtual environment:**
   ```bash
   source .venv/bin/activate
   ```

3. **Run tests:**
   ```bash
   make test
   ```

4. **Build the package:**
   ```bash
   make build
   ```

## Available Commands

Run `make help` to see all available commands.

### Essential Commands

- `make dev-setup` - Set up development environment with dependencies
- `make test` - Run all tests
- `make test-unit` - Run only unit tests
- `make test-integration` - Run only integration tests
- `make build` - Build the package
- `make clean` - Clean build artifacts
- `make lint` - Run code linting
- `make format` - Format code
- `make type-check` - Run type checking

## Requirements

- Python 3.11 or 3.12
- Make
