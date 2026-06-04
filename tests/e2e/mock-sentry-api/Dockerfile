FROM python:3.13-slim

# Install uv
RUN python3 -m pip --no-cache-dir --disable-pip-version-check install 'uv==0.11.17'

ENV UV_SYSTEM_PYTHON=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY tests/e2e/mock-sentry-api/pyproject.toml tests/e2e/mock-sentry-api/uv.lock ./
RUN uv sync --frozen --no-install-project

# Copy mock API server code
COPY tests/e2e/mock-sentry-api/server.py .

# Create data directory for storing artifacts and results
RUN mkdir -p /app/data/artifacts /app/data/results /app/data/chunks

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
