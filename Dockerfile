FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY pyproject.toml ./
RUN pip install -e .

# Copy source code
COPY src/ ./src/
COPY devservices/ ./devservices/

# Create temp directory
RUN mkdir -p /tmp/launchpad

# Expose ports
EXPOSE 1218 1219

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:1218/health_envoy || exit 1

# Default command
CMD ["launchpad", "devserver"]
