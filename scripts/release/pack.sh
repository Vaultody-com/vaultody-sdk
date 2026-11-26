#!/usr/bin/env bash
# Builds every package, at the version in VERSION, from the files git tracks in this checkout:
#
#   scripts/release/pack.sh <out>
#
#   <out>/npm/vaultody-verify-<v>.tgz, vaultody-sdk-<v>.tgz         npm pack: @vaultody/verify, @vaultody/sdk
#   <out>/pypi/vaultody-verify/, <out>/pypi/vaultody-sdk/           python -m build (wheel and sdist), twine check
#   <out>/packagist/vaultody-sdk-<v>.zip                            composer validate, composer archive of php/
#
# Packagist serves the zip GitHub makes of the vaultody-sdk-php mirror's tag, whose tree is php/ plus
# scripts/release/php-mirror.gitattributes (push-php-mirror.sh); the zip here is made from the same two, so
# it holds the same files, for the checks, the checksums and the attestation.
#
# Nothing here runs package code or downloads anything unpinned: npm pack with --ignore-scripts and no
# install (neither package has a dependency outside the repository); the Python build tools from
# requirements.txt, locked with hashes, wheels only, and the build without isolation; composer without
# scripts or plugins. SOURCE_DATE_EPOCH is the commit time, so the archives' timestamps do not depend on
# when they were built. Needs node 22+, python3 3.10+ with venv, composer 2 and git.
#
# The release workflow and the release-dry-run job both run this; check-packages.mjs then checks what each
# package ships.

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: scripts/release/pack.sh <out>" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"

if ! node scripts/version.mjs check > /dev/null; then
    node scripts/version.mjs check
    exit 1
fi
VERSION="$(node scripts/version.mjs print)"
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export SOURCE_DATE_EPOCH

rm -rf "$1"
mkdir -p "$1/npm" "$1/pypi" "$1/packagist"
OUT="$(cd "$1" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# The files git tracks under a directory, as they are in the checkout, copied to ${WORK}/src: nothing left
# over from an earlier build (build/, *.egg-info, vendor/) can get into a package.
tracked() {
    mkdir -p "${WORK}/src"
    git ls-files -z -- "$1" | tar --null -T - -cf - | tar -xf - -C "${WORK}/src"
}

echo "== npm: @vaultody/verify, @vaultody/sdk ${VERSION}"
(cd node && npm pack --workspaces --ignore-scripts --loglevel=warn --no-update-notifier --pack-destination "${OUT}/npm" > /dev/null)

echo "== PyPI: vaultody-verify, vaultody-sdk $(node scripts/version.mjs print --pep440)"
python3 -m venv "${WORK}/venv"
"${WORK}/venv/bin/python" -I -m pip install --quiet --disable-pip-version-check --require-hashes --only-binary :all: \
    -r scripts/release/requirements.txt
for package in vaultody-verify vaultody-sdk; do
    tracked "python/${package}"
    "${WORK}/venv/bin/python" -I -m build --no-isolation --outdir "${OUT}/pypi/${package}" "${WORK}/src/python/${package}" > /dev/null
done
"${WORK}/venv/bin/python" -I -m twine check --strict "${OUT}"/pypi/*/*

echo "== Packagist: vaultody/sdk ${VERSION}"
composer validate --strict --no-plugins --no-interaction --working-dir=php
tracked php
cp scripts/release/php-mirror.gitattributes "${WORK}/src/php/.gitattributes"
composer archive --no-plugins --no-scripts --no-interaction --working-dir="${WORK}/src/php" \
    --format=zip --dir="${OUT}/packagist" --file="vaultody-sdk-${VERSION}"

echo "== built"
(cd "${OUT}" && find . -type f | sort | sed 's|^\./|  |')
