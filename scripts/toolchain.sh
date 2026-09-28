#!/usr/bin/env bash
# Containerised toolchain. No compiler, SDK or CLI is installed on the host:
# every tool runs in a pinned image with the repo bind-mounted at /src.
#
#   ./scripts/toolchain.sh go build ./...
#   ./scripts/toolchain.sh go test ./...
#   ./scripts/toolchain.sh shell            # interactive shell in the Go image
#
# Module and build caches live in named volumes, so only source crosses the
# host bind mount — incremental builds stay fast even on /mnt/c.
#
# The DynamoDB store tests need DynamoDB Local. Run it on a Docker network and
# point the container at it by name; without both variables those tests skip:
#
#   docker network create awesome-auth-test
#   docker run -d --name ddblocal --network awesome-auth-test \
#     amazon/dynamodb-local -jar DynamoDBLocal.jar -inMemory -sharedDb
#   DYNAMODB_ENDPOINT=http://ddblocal:8000 TOOLCHAIN_NETWORK=awesome-auth-test \
#     ./scripts/toolchain.sh go test ./internal/store/dynamodb/... ./cmd/auth/...
set -euo pipefail

GO_IMAGE="${GO_IMAGE:-golang:1.25-trixie}"
MOD_CACHE_VOL="${MOD_CACHE_VOL:-awesome-lambda-auth-gomod}"
BUILD_CACHE_VOL="${BUILD_CACHE_VOL:-awesome-lambda-auth-gobuild}"

# Resolve the repo root from this script's location. Quoting matters: the parent
# workspace directory contains a literal ${lang} that must never be expanded.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

run_in_go_image() {
  docker run --rm \
    -v "${REPO_ROOT}":/src \
    -v "${MOD_CACHE_VOL}":/go/pkg/mod \
    -v "${BUILD_CACHE_VOL}":/root/.cache/go-build \
    -w /src \
    -e GOFLAGS \
    -e GOPROXY \
    -e AWESOME_AUTH_CONTRACT_BASE_URL \
    -e AWESOME_AUTH_CONTRACT_API_PREFIX \
    -e AWESOME_AUTH_CONTRACT_REQUIRE \
    -e AWESOME_AUTH_CONTRACT_RATE_LIMIT \
    -e AWESOME_AUTH_CONTRACT_ADMIN_PATH \
    -e AWESOME_AUTH_CONTRACT_ADMIN_EMAIL \
    -e AWESOME_AUTH_CONTRACT_ADMIN_PASSWORD \
    -e DYNAMODB_ENDPOINT \
    -e GONOSUMDB \
    -e GOPRIVATE \
    ${TOOLCHAIN_NETWORK:+--network "${TOOLCHAIN_NETWORK}"} \
    "$@"
}

case "${1:-}" in
  go)
    shift
    run_in_go_image "${GO_IMAGE}" go "$@"
    ;;
  shell)
    run_in_go_image -it "${GO_IMAGE}" bash
    ;;
  "")
    echo "usage: $0 {go <args...>|shell}" >&2
    exit 2
    ;;
  *)
    echo "unknown command: $1" >&2
    echo "usage: $0 {go <args...>|shell}" >&2
    exit 2
    ;;
esac
