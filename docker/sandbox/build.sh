#!/bin/bash
# 构建沙箱镜像

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="auditai-sandbox"
IMAGE_TAG="latest"
SEMGREP_VERSION="${SEMGREP_VERSION:-1.161.0}"

echo "Building sandbox image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "Semgrep version: ${SEMGREP_VERSION}"

docker build \
    --build-arg "SEMGREP_VERSION=${SEMGREP_VERSION}" \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${SCRIPT_DIR}"

echo "Build complete: ${IMAGE_NAME}:${IMAGE_TAG}"

# 验证镜像
echo "Verifying image..."
docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" python3 --version
docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" node --version
docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" semgrep --version

echo "Sandbox image ready!"
