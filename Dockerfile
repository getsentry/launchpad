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
# Pin to specific commit hash for swift-5.9-RELEASE for security
# Commit hash: 731d5c61ab5437e0e9bbfca7d318519a9d34f395 (swift-5.9-RELEASE tag)
RUN git clone https://github.com/apple/swift-corelibs-libdispatch.git && \
    cd swift-corelibs-libdispatch && \
    # Verify we're cloning from the expected repository
    git remote -v | grep -q "github.com/apple/swift-corelibs-libdispatch" && \
    # Pin to specific commit hash instead of tag for security
    git checkout 731d5c61ab5437e0e9bbfca7d318519a9d34f395 && \
    # Verify the commit hash matches our expectation
    test "$(git rev-parse HEAD)" = "731d5c61ab5437e0e9bbfca7d318519a9d34f395" && \
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

# Install system dependencies including JDK 17 and FFmpeg
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
    ffmpeg \
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

# Copy and verify the strip and ld binaries, then make them executable
COPY scripts/strip/dist/strip scripts/strip/dist/ld /app/scripts/strip/dist/
RUN echo "4cd01dd28294a3ebeff031d6ba947aee1c2dd9c402f504f9866eec302466b11d  /app/scripts/strip/dist/strip" | sha256sum -c - && \
    echo "05b2cbe0786aab0e2ffba665a6fe2303d2a9e2e77ac8b18cfc015dffe2c2d3f7  /app/scripts/strip/dist/ld" | sha256sum -c - && \
    chmod +x /app/scripts/strip/dist/strip /app/scripts/strip/dist/ld && \
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

ARG LAUNCHPAD_VERSION_SHA
ENV LAUNCHPAD_VERSION_SHA=$LAUNCHPAD_VERSION_SHA

# Default command
CMD ["launchpad", "serve", "--verbose"]
