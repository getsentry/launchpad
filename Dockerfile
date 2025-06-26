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

# Setup bundletool
RUN curl https://github.com/google/bundletool/releases/download/1.18.1/bundletool-all-1.18.1.jar -4 -sL -o /usr/local/bin/bundletool.jar && \
    echo '#!/bin/bash' > /usr/local/bin/bundletool && \
    echo 'java -jar /usr/local/bin/bundletool.jar "$@"' >> /usr/local/bin/bundletool && \
    chmod +x /usr/local/bin/bundletool

# Setup cwebp
RUN curl -L https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-1.5.0-linux-x86-64.tar.gz -o /tmp/webp.tar.gz && \
    tar -xzf /tmp/webp.tar.gz -C /usr/local --strip-components=1 && \
    rm /tmp/webp.tar.gz

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
COPY pyproject.toml pytest.ini ./
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

# Change ownership to app user
RUN chown -R app:app /app

# Switch to app user
USER app

# Expose ports
EXPOSE 2218

# Default command
CMD ["launchpad", "serve"]
