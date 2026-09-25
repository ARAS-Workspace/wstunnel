#!/usr/bin/env bash
# Trigger the linux release workflow.
# Version is read from wstunnel/Cargo.toml (single source of truth).
# Creates the linux-v<version> tag and pushes it.
# Usage: .github/scripts/release-linux.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

VERSION="$(awk -F\" '/^version *= */ {print $2; exit}' "${REPO_ROOT}/wstunnel/Cargo.toml")"
if [[ -z "$VERSION" ]]; then
    echo "ERROR: could not parse version from wstunnel/Cargo.toml" >&2
    exit 1
fi

TAG="linux-v${VERSION}"

if git -C "${REPO_ROOT}" rev-parse "${TAG}" &>/dev/null 2>&1; then
    echo "Tag ${TAG} already exists locally."
    printf "Delete and recreate? [y/N]: "
    read -r confirm
    if [[ "$confirm" != "y" ]]; then
        echo "Aborted."
        exit 1
    fi
    git -C "${REPO_ROOT}" tag -d "${TAG}"
    git -C "${REPO_ROOT}" push origin ":refs/tags/${TAG}" 2>/dev/null || true
fi

git -C "${REPO_ROOT}" tag "${TAG}"
git -C "${REPO_ROOT}" push origin "${TAG}"

echo ""
echo "Release triggered: ${TAG}"
echo "Watch: gh run list --workflow release-linux.yaml"
