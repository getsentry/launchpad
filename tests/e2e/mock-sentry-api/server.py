"""Mock Sentry API server for E2E testing.

This server simulates the Sentry monolith API endpoints that Launchpad interacts with:
- Artifact download
- Artifact updates
- Size analysis uploads (chunked)
- Chunk assembly
"""

import hashlib
import hmac
import json
import os

from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse

app = FastAPI(title="Mock Sentry API for Launchpad E2E Tests")

# Storage paths
DATA_DIR = Path("/app/data")
ARTIFACTS_DIR = DATA_DIR / "artifacts"
RESULTS_DIR = DATA_DIR / "results"
CHUNKS_DIR = DATA_DIR / "chunks"

# Create directories
for dir_path in [ARTIFACTS_DIR, RESULTS_DIR, CHUNKS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)


def safe_filename(artifact_id: str, suffix: str = "") -> str:
    """Convert artifact_id to a safe filename using SHA256 hash.

    This prevents path traversal by ensuring user input never directly
    becomes part of the filename - only the hash is used.
    """
    hash_digest = hashlib.sha256(artifact_id.encode()).hexdigest()[:16]
    return f"{hash_digest}{suffix}"


def safe_chunk_filename(checksum: str) -> str:
    """Convert checksum to a safe filename using SHA256 hash.

    This prevents path traversal by ensuring user input never directly
    becomes part of the filename - only the hash is used.
    """
    return hashlib.sha256(checksum.encode()).hexdigest()[:16]


# In-memory storage for test data
artifacts_db: Dict[str, Dict[str, Any]] = {}
size_analysis_db: Dict[str, Dict[str, Any]] = {}

# Expected RPC secret (should match docker-compose env var)
RPC_SHARED_SECRET = os.getenv("LAUNCHPAD_RPC_SHARED_SECRET", "test-secret-key-for-e2e")


def verify_rpc_signature(authorization: str, body: bytes) -> bool:
    """Verify RPC signature from Authorization header."""
    if not authorization or not authorization.startswith("rpcsignature rpc0:"):
        return False

    signature = authorization.replace("rpcsignature rpc0:", "")
    expected_signature = hmac.new(RPC_SHARED_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()

    return hmac.compare_digest(signature, expected_signature)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "mock-sentry-api"}


@app.head("/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/")
@app.get("/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/")
async def download_artifact(
    org: str,
    project: str,
    artifact_id: str,
    request: Request,
    authorization: str = Header(None),
):
    """Download artifact file."""
    artifact_path = ARTIFACTS_DIR / safe_filename(artifact_id, ".zip")

    if not artifact_path.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")

    # Handle HEAD request
    if request.method == "HEAD":
        file_size = artifact_path.stat().st_size
        return Response(headers={"Content-Length": str(file_size)}, status_code=200)

    # Handle Range requests for resumable downloads
    range_header = request.headers.get("range")
    if range_header:
        # Parse range header (simplified implementation)
        file_size = artifact_path.stat().st_size
        range_start = int(range_header.replace("bytes=", "").split("-")[0])
        with open(artifact_path, "rb") as f:
            f.seek(range_start)
            content = f.read()
        range_end = range_start + len(content) - 1
        return Response(
            content=content,
            status_code=206,
            headers={"Content-Range": f"bytes {range_start}-{range_end}/{file_size}"},
        )

    return FileResponse(artifact_path)


@app.put("/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/update/")
async def update_artifact(
    org: str,
    project: str,
    artifact_id: str,
    request: Request,
    authorization: str = Header(None),
):
    """Update artifact metadata."""
    body = await request.body()

    # Verify signature
    if not verify_rpc_signature(authorization, body):
        raise HTTPException(status_code=403, detail="Invalid signature")

    data = json.loads(body)

    # Store update in database
    if artifact_id not in artifacts_db:
        artifacts_db[artifact_id] = {}

    artifacts_db[artifact_id].update(data)

    # Track which fields were updated
    updated_fields = list(data.keys())

    return {"success": True, "artifactId": artifact_id, "updatedFields": updated_fields}


@app.get("/api/0/organizations/{org}/chunk-upload/")
async def get_chunk_options(org: str):
    """Get chunk upload configuration."""
    return {
        "url": f"/api/0/organizations/{org}/chunk-upload/",
        "chunkSize": 8388608,  # 8MB
        "chunksPerRequest": 64,
        "maxFileSize": 2147483648,  # 2GB
        "maxRequestSize": 33554432,  # 32MB
        "concurrency": 8,
        "hashAlgorithm": "sha1",
        "compression": ["gzip"],
        "accept": ["*"],
    }


@app.post("/api/0/organizations/{org}/chunk-upload/")
async def upload_chunk(
    org: str,
    file: UploadFile,
    authorization: str = Header(None),
):
    """Upload a file chunk."""
    # Read chunk data
    chunk_data = await file.read()

    # Calculate checksum
    checksum = hashlib.sha1(chunk_data).hexdigest()

    # Store chunk using safe filename (hash of checksum prevents path injection)
    chunk_path = CHUNKS_DIR / safe_chunk_filename(checksum)
    chunk_path.write_bytes(chunk_data)

    # Return 200 if successful, 409 if already exists
    return JSONResponse({"checksum": checksum}, status_code=200)


@app.post("/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/assemble-generic/")
async def assemble_file(
    org: str,
    project: str,
    artifact_id: str,
    request: Request,
    authorization: str = Header(None),
):
    """Assemble uploaded chunks into complete file."""
    body = await request.body()

    # Verify signature
    if not verify_rpc_signature(authorization, body):
        raise HTTPException(status_code=403, detail="Invalid signature")

    data = json.loads(body)
    checksum = data["checksum"]
    chunks = data["chunks"]
    assemble_type = data["assemble_type"]

    # Check which chunks are missing (safe_chunk_filename hashes input to prevent path injection)
    missing_chunks = []
    for chunk_checksum in chunks:
        chunk_path = CHUNKS_DIR / safe_chunk_filename(chunk_checksum)
        if not chunk_path.exists():
            missing_chunks.append(chunk_checksum)

    if missing_chunks:
        return {"state": "not_found", "missingChunks": missing_chunks}

    # Assemble the file
    file_data = b""
    for chunk_checksum in chunks:
        chunk_path = CHUNKS_DIR / safe_chunk_filename(chunk_checksum)
        file_data += chunk_path.read_bytes()

    # Verify checksum
    actual_checksum = hashlib.sha1(file_data).hexdigest()
    if actual_checksum != checksum:
        return {
            "state": "error",
            "missingChunks": [],
            "detail": f"Checksum mismatch: expected {checksum}, got {actual_checksum}",
        }

    # Store assembled file
    if assemble_type == "size_analysis":
        result_path = RESULTS_DIR / safe_filename(artifact_id, "_size_analysis.json")
        result_path.write_bytes(file_data)

        # Parse and store in database - fail if JSON is invalid
        try:
            size_analysis_db[artifact_id] = json.loads(file_data.decode("utf-8"))
        except json.JSONDecodeError:
            return {
                "state": "error",
                "missingChunks": [],
                "detail": "Invalid JSON in size analysis",
            }

    elif assemble_type == "installable_app":
        app_path = RESULTS_DIR / safe_filename(artifact_id, "_app")
        app_path.write_bytes(file_data)

    else:
        return {
            "state": "error",
            "missingChunks": [],
            "detail": f"Unknown assemble_type: {assemble_type}",
        }

    return {"state": "ok", "missingChunks": []}


@app.put("/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/size/")
@app.put("/api/0/internal/{org}/{project}/files/preprodartifacts/{artifact_id}/size/{identifier}/")
async def update_size_analysis(
    org: str,
    project: str,
    artifact_id: str,
    request: Request,
    identifier: Optional[str] = None,
    authorization: str = Header(None),
):
    """Update size analysis metadata."""
    body = await request.body()

    # Verify signature
    if not verify_rpc_signature(authorization, body):
        raise HTTPException(status_code=403, detail="Invalid signature")

    data = json.loads(body)

    # Store in database
    key = f"{artifact_id}:{identifier}" if identifier else artifact_id
    if key not in size_analysis_db:
        size_analysis_db[key] = {}
    size_analysis_db[key].update(data)

    return {"artifactId": artifact_id}


# Test helper endpoints (not part of real Sentry API)


@app.post("/test/upload-artifact/{artifact_id}")
async def test_upload_artifact(artifact_id: str, file: UploadFile):
    """Test helper: Upload an artifact file for testing."""
    artifact_path = ARTIFACTS_DIR / safe_filename(artifact_id, ".zip")

    with open(artifact_path, "wb") as f:
        content = await file.read()
        f.write(content)

    return {"artifact_id": artifact_id, "size": len(content)}


@app.get("/test/results/{artifact_id}")
async def test_get_results(artifact_id: str):
    """Test helper: Get analysis results for an artifact."""
    size_analysis_path = RESULTS_DIR / safe_filename(artifact_id, "_size_analysis.json")
    installable_app_path = RESULTS_DIR / safe_filename(artifact_id, "_app")
    return {
        "artifact_metadata": artifacts_db.get(artifact_id, {}),
        "size_analysis": size_analysis_db.get(artifact_id, {}),
        "has_size_analysis_file": size_analysis_path.exists(),
        "has_installable_app": installable_app_path.exists(),
    }


@app.get("/test/results/{artifact_id}/size-analysis-raw")
async def test_get_size_analysis_raw(artifact_id: str):
    """Test helper: Get raw size analysis JSON."""
    result_path = RESULTS_DIR / safe_filename(artifact_id, "_size_analysis.json")

    if not result_path.exists():
        raise HTTPException(status_code=404, detail="Size analysis not found")

    return JSONResponse(json.loads(result_path.read_text()))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
