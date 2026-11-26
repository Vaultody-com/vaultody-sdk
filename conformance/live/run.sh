#!/usr/bin/env bash
# The live conformance run against a non-production Vaultody API (README.md in this directory).
#
#   conformance/live/run.sh [--env-file FILE] [--out DIR] [node] [python-sync] [python-async] [php]
#
# Needs VAULTODY_BASE_URL, VAULTODY_API_KEY, VAULTODY_API_SECRET and VAULTODY_PASSPHRASE (from the
# environment, or --env-file, a mode 0600 file of NAME=value lines). Refuses the production API. Writes the
# fixture, each client's results, summary.json and report.md to DIR (default: a new private temporary
# directory). Not part of CI: it needs a test client's credentials, which this repository's CI never holds.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
env_file=""
out="${VAULTODY_CONFORMANCE_OUT:-}"
clients=()
while [ $# -gt 0 ]; do
    case "$1" in
        --env-file) env_file="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        node|python-sync|python-async|php) clients+=("$1"); shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ ${#clients[@]} -gt 0 ] || clients=(node python-sync python-async php)

if [ -n "$env_file" ]; then
    mode="$(stat -f '%Lp' "$env_file" 2>/dev/null || stat -c '%a' "$env_file")"
    case "$mode" in
        600|400) ;;
        *) echo "$env_file must be readable by its owner only (mode 0600; it is $mode)" >&2; exit 2 ;;
    esac
    set -a
    # shellcheck disable=SC1090
    . "$env_file"
    set +a
fi
for name in VAULTODY_BASE_URL VAULTODY_API_KEY VAULTODY_API_SECRET VAULTODY_PASSPHRASE; do
    if [ -z "${!name:-}" ]; then
        echo "$name is not set" >&2
        exit 2
    fi
done
case "${VAULTODY_BASE_URL%/}" in
    https://rest.vaultody.com) echo "the live conformance run never targets the production API" >&2; exit 2 ;;
esac
export VAULTODY_BASE_URL VAULTODY_API_KEY VAULTODY_API_SECRET VAULTODY_PASSPHRASE

umask 077
if [ -z "$out" ]; then
    out="$(mktemp -d "${TMPDIR:-/tmp}/vaultody-conformance.XXXXXX")"
fi
mkdir -p "$out"
chmod 700 "$out"
export VAULTODY_CONFORMANCE_RUN_ID="${VAULTODY_CONFORMANCE_RUN_ID:-$(date -u +%m%d%H%M%S)}"
node_bin="${VAULTODY_CONFORMANCE_NODE:-node}"
python_bin="${VAULTODY_CONFORMANCE_PYTHON:-python3}"
php_bin="${VAULTODY_CONFORMANCE_PHP:-php}"

if [ -n "${VAULTODY_CONFORMANCE_FIXTURE:-}" ]; then
    cp "$VAULTODY_CONFORMANCE_FIXTURE" "$out/fixture.json"
else
    "$node_bin" "$here/discover.js" "$out"
fi

status=0
for client in "${clients[@]}"; do
    case "$client" in
        node)
            "$node_bin" "$here/run-node.js" "$out" || status=1 ;;
        python-sync|python-async)
            "$python_bin" -I "$here/run_python.py" --client "${client#python-}" "$out" || status=1 ;;
        php)
            case "$php_bin" in
                docker:*)
                    # The output directory may be outside what the Docker VM mounts (Colima mounts only $HOME):
                    # the fixture goes in on stdin, the results come back on stdout, and only the repository is
                    # mounted, read only. The credentials are passed by name, never on the command line.
                    if docker run --rm -i \
                        -e VAULTODY_BASE_URL -e VAULTODY_API_KEY -e VAULTODY_API_SECRET -e VAULTODY_PASSPHRASE \
                        -e VAULTODY_CONFORMANCE_RUN_ID -e VAULTODY_CONFORMANCE_BURST -e VAULTODY_CONFORMANCE_RPS \
                        -e VAULTODY_CONFORMANCE_CASES \
                        -v "$root:/sdk:ro" "${php_bin#docker:}" \
                        sh -c 'mkdir -m 700 /out && cat > /out/fixture.json && php -d display_errors=stderr /sdk/conformance/live/run-php.php /out && cat /out/results-php.json' \
                        < "$out/fixture.json" > "$out/results-php.json.part"; then
                        mv "$out/results-php.json.part" "$out/results-php.json"
                    else
                        rm -f "$out/results-php.json.part"
                        status=1
                    fi ;;
                *)
                    "$php_bin" -d display_errors=stderr "$here/run-php.php" "$out" || status=1 ;;
            esac ;;
    esac
    sleep "${VAULTODY_CONFORMANCE_PAUSE:-2}"
done

"$node_bin" "$here/report.js" "$out" > "$out/report.md"
echo "report: $out/report.md" >&2
exit "$status"
