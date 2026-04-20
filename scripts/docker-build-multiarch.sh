#!/usr/bin/env bash
#
# Multi-arch Docker 이미지 빌드 스크립트.
#
# 사용법:
#   scripts/docker-build-multiarch.sh [TAG]
#
# 예시:
#   scripts/docker-build-multiarch.sh v0.4.1
#   scripts/docker-build-multiarch.sh --push ghcr.io/sungalex/aisast:v0.4.1
#
# 전제:
#   - Docker Desktop 또는 buildx 플러그인 설치
#   - `docker buildx create --name aisast --use` 한 번 실행해두기
#   - 레지스트리 로그인 (`docker login ghcr.io` 등)

set -euo pipefail

TAG="${1:-aisast:local-multiarch}"
PLATFORMS="${OPENSAST_PLATFORMS:-linux/amd64,linux/arm64}"
PUSH="${OPENSAST_PUSH:-false}"

cd "$(dirname "$0")/.."

echo "== Building api+worker image for ${PLATFORMS} =="
BUILD_ARGS=(
  buildx build
  --platform "${PLATFORMS}"
  --tag "${TAG}"
  --file Dockerfile
  .
)

if [[ "${PUSH}" == "true" ]]; then
  BUILD_ARGS+=(--push)
  echo "== Push enabled: ${TAG} will be pushed to registry =="
else
  BUILD_ARGS+=(--load)
  echo "== Local load only (set OPENSAST_PUSH=true to push) =="
fi

docker "${BUILD_ARGS[@]}"

echo "== Building frontend image for ${PLATFORMS} =="
docker buildx build \
  --platform "${PLATFORMS}" \
  --tag "${TAG/aisast/aisast-frontend}" \
  --file frontend/Dockerfile \
  $([[ "${PUSH}" == "true" ]] && echo "--push" || echo "--load") \
  frontend/

echo "✓ Multi-arch build complete: ${TAG}"
