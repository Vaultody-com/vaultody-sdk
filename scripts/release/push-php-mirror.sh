#!/usr/bin/env bash
# Publishes php/ of the release commit (HEAD) to the read-only Packagist mirror: one commit on the mirror's
# main whose tree is php/ plus a .gitattributes, and the annotated tag v<version> on it.
#
#   scripts/release/push-php-mirror.sh <version> <mirror-url>
#
# Packagist needs composer.json at a repository's root, so the PHP package lives in its own repository,
# Vaultody-com/vaultody-sdk-php, which only this script writes to (the release workflow's publish-php job,
# with the mirror's deploy key). Each release adds one commit whose tree holds the very git objects of php/
# here, and one more file: .gitattributes from scripts/release/php-mirror.gitattributes, which keeps
# GitHub's zip of the tag (what Packagist serves) to the library. Anyone can check a mirror tag against the
# signed tag of this repository, with both fetched into one clone:
#
#   git diff --stat 'v<version>:php' '<mirror tag>^{tree}'    # only .gitattributes differs
#
# Packagist reads the tag through its GitHub integration. Run again for the same version, it changes
# nothing when the mirror's tag already holds that tree, and fails when the tag holds anything else: a
# published version is never moved. Main is only ever fast-forwarded.

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: scripts/release/push-php-mirror.sh <version> <mirror-url>" >&2
    exit 2
fi
VERSION="$1"
MIRROR="$2"
TAG="v${VERSION}"

cd "$(git rev-parse --show-toplevel)"
COMMIT="$(git rev-parse HEAD)"
if git cat-file -e "HEAD:php/.gitattributes" 2> /dev/null; then
    echo "php/.gitattributes exists: the mirror's comes from scripts/release/php-mirror.gitattributes" >&2
    exit 1
fi
# php/ as it is, plus the mirror's .gitattributes (git mktree sorts the entries).
TREE="$( (git ls-tree "HEAD:php"
    printf '100644 blob %s\t.gitattributes\n' "$(git rev-parse "HEAD:scripts/release/php-mirror.gitattributes")") | git mktree)"
export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-github-actions[bot]}"
export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"
export GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-${GIT_AUTHOR_NAME}}"
export GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-${GIT_AUTHOR_EMAIL}}"

if [ -n "$(git ls-remote --tags "${MIRROR}" "refs/tags/${TAG}")" ]; then
    git fetch --quiet --no-tags "${MIRROR}" "+refs/tags/${TAG}:refs/php-mirror/${TAG}"
    if [ "$(git rev-parse "refs/php-mirror/${TAG}^{tree}")" = "${TREE}" ]; then
        echo "${TAG} is on the mirror already, with php/ of ${COMMIT}"
        exit 0
    fi
    echo "${TAG} is on the mirror already, with another tree than php/ of ${COMMIT}: a published version is never moved" >&2
    exit 1
fi

PARENT=()
if [ -n "$(git ls-remote --heads "${MIRROR}" refs/heads/main)" ]; then
    git fetch --quiet --no-tags "${MIRROR}" "+refs/heads/main:refs/php-mirror/main"
    PARENT=(-p "$(git rev-parse refs/php-mirror/main)")
fi

MESSAGE="vaultody/sdk ${VERSION}

php/ of Vaultody-com/vaultody-sdk at ${COMMIT}, the signed tag ${TAG} there.
This repository is a read-only mirror for Packagist; changes go to Vaultody-com/vaultody-sdk."
MIRROR_COMMIT="$(git commit-tree "${TREE}" ${PARENT[@]+"${PARENT[@]}"} -m "${MESSAGE}")"
# git tag would write refs/tags/${TAG}, which is this repository's own signed tag: make the tag object only.
MIRROR_TAG="$(printf 'object %s\ntype commit\ntag %s\ntagger %s <%s> %s +0000\n\n%s\n' \
    "${MIRROR_COMMIT}" "${TAG}" "${GIT_COMMITTER_NAME}" "${GIT_COMMITTER_EMAIL}" "$(date +%s)" "${MESSAGE}" | git mktag)"

# Both or neither; main only fast-forwards.
git push --atomic "${MIRROR}" "${MIRROR_COMMIT}:refs/heads/main" "${MIRROR_TAG}:refs/tags/${TAG}"
echo "${TAG} pushed to the mirror: commit ${MIRROR_COMMIT}, tree ${TREE} (php/ of ${COMMIT})"
