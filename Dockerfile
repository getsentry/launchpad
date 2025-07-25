# Build libdispatch for the strip binary
FROM --platform=linux/amd64 debian:12-slim AS libdispatch-build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    cmake \
    git \
    libblocksruntime-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN git clone https://github.com/apple/swift-corelibs-libdispatch.git && \
    cd swift-corelibs-libdispatch && \
    git checkout swift-5.9-RELEASE && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_INSTALL_PREFIX=/usr && \
    make -j$(nproc) && \
    make install

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
        libbsd0 \
        liblzma5 \
        zlib1g \
        libblocksruntime0 \
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

# Copy libdispatch from the build stage
COPY --from=libdispatch-build /usr/lib/x86_64-linux-gnu/libdispatch.so* /usr/lib/x86_64-linux-gnu/

# Ensure the strip and ld binaries are executable and create necessary symlinks
RUN chmod +x /app/scripts/strip/dist/strip /app/scripts/strip/dist/ld && \
    ln -sf /usr/lib/x86_64-linux-gnu/libBlocksRuntime.so.0 /usr/lib/x86_64-linux-gnu/libBlocksRuntime.so && \
    ldconfig

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
