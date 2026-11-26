#!/usr/bin/env bash
# Scans the whole git history (every branch and tag this clone has) for secrets with gitleaks, from an
# image pinned by digest. Run before the repository goes public, and in CI on every push.
#
#   scripts/secret-scan.sh              # needs docker (Colima locally)
#   scripts/secret-scan.sh --dir <dir>  # the files under <dir> instead: the unpacked packages
#                                       # (scripts/release/check-packages.mjs --extract), with gitleaks'
#                                       # default rules and no allow-list, since no package may ship a secret
#
# The scan reads a temporary mirror clone, so it works the same from a normal checkout and from a git
# worktree. Findings are printed redacted; the exit code is 1 when there is any. The TEST-ONLY keys and
# secrets of the shared vectors and tests are allowed by path in .gitleaks.toml, and only there.

set -euo pipefail

GITLEAKS_IMAGE='ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f' # v8.30.1

if [ "${1:-}" = "--dir" ]; then
    DIR="$(cd "${2:?usage: scripts/secret-scan.sh --dir <dir>}" && pwd)"
    echo "scanning $(find "${DIR}" -type f | wc -l | tr -d ' ') files under ${DIR}"
    # With no .gitleaks.toml in <dir>, gitleaks uses its default rules only.
    docker run --rm -v "${DIR}:/scan:ro" "${GITLEAKS_IMAGE}" \
        dir /scan --redact --no-banner --exit-code 1
    exit
fi

ROOT="$(git rev-parse --show-toplevel)"
COMMON_DIR="$(cd "$(git rev-parse --git-common-dir)" && pwd)"
# Under the repository, so Colima (which shares the home directory) can mount it; .gitignore'd.
WORK="${ROOT}/.secret-scan"
rm -rf "${WORK}"
mkdir -p "${WORK}"
trap 'rm -rf "${WORK}"' EXIT

git clone --quiet --mirror "${COMMON_DIR}" "${WORK}/repo.git"
echo "scanning $(git -C "${WORK}/repo.git" rev-list --all | wc -l | tr -d ' ') commits on $(git -C "${WORK}/repo.git" for-each-ref | wc -l | tr -d ' ') refs"

docker run --rm \
    -v "${WORK}/repo.git:/repo:ro" \
    -v "${ROOT}/.gitleaks.toml:/gitleaks.toml:ro" \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
    "${GITLEAKS_IMAGE}" \
    git /repo --log-opts=--all --config /gitleaks.toml --redact --no-banner --exit-code 1
