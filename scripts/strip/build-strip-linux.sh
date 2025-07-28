#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build the real Apple cctools `strip` and export it locally.

Usage:
  build-strip-linux.sh [-f DOCKERFILE] [-o OUT_DIR] [--no-verify]

Options:
  -f, --file DOCKERFILE   Dockerfile to use (default: Dockerfile.cctools)
  -o, --out  OUT_DIR      Output directory for the exported binary (default: dist)
      --no-verify         Skip the verify stage
  -h, --help              Show this help
EOF
}

DOCKERFILE="Dockerfile.cctools"
OUT_DIR="dist"
VERIFY=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--file)
      DOCKERFILE="$2"; shift 2;;
    -o|--out)
      OUT_DIR="$2"; shift 2;;
    --no-verify)
      VERIFY=0; shift;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1;;
  esac
done

STRIP_BIN="${OUT_DIR}/strip"
VERIFY_TAG="apple-strip:verify"

echo "==> Ensuring docker buildx is available"
if ! docker buildx ls >/dev/null 2>&1; then
  echo "buildx not found/enabled; you need Docker with BuildKit/buildx"
  exit 1
fi

echo "==> Building (verify stage) with ${DOCKERFILE}"
if [[ $VERIFY -eq 1 ]]; then
  docker buildx build \
    --target verify \
    -f "${DOCKERFILE}" \
    -t "${VERIFY_TAG}" \
    --load \
    . || { echo "Verification failed"; exit 1; }
fi

echo "==> Exporting binaries to ${OUT_DIR} via build stage"
# Export both strip and ld binaries
docker buildx build \
  --target build \
  -f "${DOCKERFILE}" \
  -t cctools-temp \
  --load \
  .


# Copy the necessary binaries
mkdir -p "${OUT_DIR}"
docker run --rm cctools-temp tar -cf - -C /out/bin strip ld | tar -xf - -C "${OUT_DIR}"


if [[ ! -f "${STRIP_BIN}" ]]; then
  echo "ERROR: ${STRIP_BIN} was not produced." >&2
  exit 1
fi

if [[ ! -f "${OUT_DIR}/ld" ]]; then
  echo "ERROR: ${OUT_DIR}/ld was not produced." >&2
  exit 1
fi

chmod +x "${STRIP_BIN}" "${OUT_DIR}/ld"

echo "==> Build complete!"
echo "Binary: ${STRIP_BIN}"
echo
echo "Quick checks:"
file "${STRIP_BIN}" || true
