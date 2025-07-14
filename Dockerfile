# Use Python 3.12 slim image
FROM python:3.12-slim-bookworm

# Build argument to determine if this is a test build
ARG TEST_BUILD=false

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create app user and group
RUN groupadd --gid 1000 app && \
    useradd --uid 1000 --gid app --shell /bin/bash --create-home app

# Install system dependencies including JDK 17
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
        build-essential \
        openjdk-17-jdk \
        unzip \
        zip \
        file \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

# Copy source code, tests, and scripts
COPY src/ ./src/
COPY tests/ ./tests/
COPY scripts/ ./scripts/
COPY devservices/ ./devservices/
COPY pyproject.toml .
COPY README.md .
COPY LICENSE .

# Conditionally copy test fixtures only for test builds
RUN if [ "$TEST_BUILD" = "true" ]; then \
        echo "Test build detected - including test fixtures"; \
    else \
        echo "Production build - excluding test fixtures"; \
        rm -rf tests/_fixtures; \
    fi

RUN pip install -e .

RUN python scripts/deps --install --local-architecture=x86_64 --local-system=linux

# Change ownership to app user
RUN chown -R app:app /app

# Switch to app user
USER app

# Expose ports
EXPOSE 2218

# Default command
CMD ["launchpad", "serve"]
