FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi==0.115.0 \
    uvicorn[standard]==0.32.0 \
    pydantic==2.9.2 \
    boto3==1.35.0 \
    python-multipart==0.0.20

# Copy mock API server code
COPY tests/e2e/mock-sentry-api/server.py .

# Create data directory for storing artifacts and results
RUN mkdir -p /app/data/artifacts /app/data/results /app/data/chunks

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
