#!/bin/bash
set -euo pipefail

# Script to create and push multi-platform Docker manifests
# Usage: create-manifest.sh <repository> <sha> <push_nightly>

REPOSITORY="$1"
SHA="$2"
PUSH_NIGHTLY="$3"

# Define registries and their prefixes
declare -A REGISTRIES=(
  ["ghcr.io"]="ghcr.io/${REPOSITORY}"
  ["docker.io"]="${REPOSITORY}"
)

# Extract short SHA (first 7 characters)
SHORT_SHA="${SHA:0:7}"

echo "Creating manifests for repository: ${REPOSITORY}"
echo "SHA: ${SHA} (short: ${SHORT_SHA})"
echo "Push nightly: ${PUSH_NIGHTLY}"

# Create manifests for each registry
for registry in "${!REGISTRIES[@]}"; do
  IMAGE_NAME="${REGISTRIES[$registry]}"
  echo ""
  echo "Creating manifests for ${IMAGE_NAME}"

  # Create long SHA manifest using buildx imagetools (handles manifest lists with attestations)
  echo "Creating long SHA manifest: ${IMAGE_NAME}:${SHA}"
  docker buildx imagetools create \
    --tag "${IMAGE_NAME}:${SHA}" \
    "${IMAGE_NAME}:${SHA}-amd64"
    # We do not currently support arm64
    # "${IMAGE_NAME}:${SHA}-arm64"
  echo "✓ Pushed ${IMAGE_NAME}:${SHA}"

  # Create short SHA manifest
  echo "Creating short SHA manifest: ${IMAGE_NAME}:${SHORT_SHA}"
  docker buildx imagetools create \
    --tag "${IMAGE_NAME}:${SHORT_SHA}" \
    "${IMAGE_NAME}:${SHA}-amd64"
    # We do not currently support arm64
    # "${IMAGE_NAME}:${SHA}-arm64"
  echo "✓ Pushed ${IMAGE_NAME}:${SHORT_SHA}"

  # Create nightly manifest if requested
  if [[ "${PUSH_NIGHTLY}" == "true" ]]; then
    echo "Creating nightly manifest: ${IMAGE_NAME}:nightly"
    docker buildx imagetools create \
      --tag "${IMAGE_NAME}:nightly" \
      "${IMAGE_NAME}:${SHA}-amd64"
      # We do not currently support arm64
      # "${IMAGE_NAME}:${SHA}-arm64"
    echo "✓ Pushed ${IMAGE_NAME}:nightly"
  else
    echo "Skipping nightly manifest"
  fi
done

echo ""
echo "🎉 All manifests created and pushed successfully!"
