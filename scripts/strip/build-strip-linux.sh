#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build the real Apple cctools `strip` (via osxcross) and export it locally.

Usage:
  build-strip.sh [-f DOCKERFILE] [-o OUT_DIR] [--no-verify]

Options:
  -f, --file DOCKERFILE   Dockerfile to use (default: Dockerfile.osxcross)
  -o, --out  OUT_DIR      Output directory for the exported binary (default: dist)
      --no-verify         Skip the verify stage
  -h, --help              Show this help
EOF
}

DOCKERFILE="Dockerfile.cctools-port"
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
    .
fi

echo "==> Exporting binary to ${OUT_DIR} via export stage"
docker buildx build \
  --target export \
  -f "${DOCKERFILE}" \
  -o "type=local,dest=${OUT_DIR}" \
  .

if [[ ! -f "${STRIP_BIN}" ]]; then
  echo "ERROR: ${STRIP_BIN} was not produced." >&2
  exit 1
fi

chmod +x "${STRIP_BIN}"

echo "==> Build complete!"
echo "Binary: ${STRIP_BIN}"
echo
echo "Quick checks:"
file "${STRIP_BIN}" || true
