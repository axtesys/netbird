#!/bin/bash
#
# OPNsense Port Diff Generator for the axtesys NetBird fork
#
# Generates the security/netbird port diff (Makefile + distinfo) for a new
# version, against the OPNsense ports tree. The CI uploads the resulting diff as
# an artifact; it is hand-carried to the internal OPNsense build node, which
# builds the port from it (see MAINTENANCE).
#
# Usage: ./opnsense-port-diff.sh [new_version]
# Example: ./opnsense-port-diff.sh 0.73.2-axt
#
# If no version is provided, it fetches the latest tag from GitHub.
#
# ⚠️ GO_MODULE / Go-proxy caveat (verify on the build node):
#   This script bumps DISTVERSION + GO_MODULE and computes distinfo checksums by
#   pulling the module .mod/.zip from the public Go proxy. The fork's go.mod
#   module path is still `github.com/netbirdio/netbird`, so proxy.golang.org will
#   NOT serve `github.com/axtesys/netbird` (path mismatch / private repo). That
#   means either GO_MODULE must stay `netbirdio/netbird` (matching go.mod) with
#   only the source repo pointed at axtesys, or the build node regenerates
#   distinfo itself (`make makesum`) and these computed checksums are scaffold
#   only. The org rename below preserves the fork's prior behaviour verbatim;
#   confirm which mechanism your build node actually relies on before trusting
#   the generated distinfo.

set -e

GITHUB_REPO="axtesys/netbird"
PORTS_CGIT_BASE="https://raw.githubusercontent.com/opnsense/ports/refs/heads/master/security/netbird"
GO_PROXY="https://proxy.golang.org/github.com/axtesys/netbird/@v"
OUTPUT_DIR="${OUTPUT_DIR:-.}"
AWK_FIRST_FIELD='{print $1}'

fetch_all_tags() {
    # Fetch tags from GitHub tags page (no rate limiting, no auth needed).
    # The trailing `-k4,4r` keeps the "-axt" prerelease suffix sorted so the
    # newest axtesys release is selected (not the upstream base tag).
    curl -sL "https://github.com/${GITHUB_REPO}/tags" 2>/dev/null | \
        grep -oE '/releases/tag/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?' | \
        sed 's/.*\/v//' | \
        sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4r
    return 0
}

fetch_current_ports_version() {
    echo "Fetching current version from OPNsense ports..." >&2
    curl -sL "${PORTS_CGIT_BASE}/Makefile" 2>/dev/null | \
        grep -E "^DISTVERSION=" | \
        sed 's/DISTVERSION=[[:space:]]*//' | \
        tr -d '\t '
    return 0
}

fetch_latest_github_release() {
    echo "Fetching latest release from GitHub..." >&2
    fetch_all_tags | tail -1
    return 0
}

fetch_ports_file() {
    local filename="$1"
    curl -sL "${PORTS_CGIT_BASE}/${filename}" 2>/dev/null
    return 0
}

compute_checksums() {
    local version="$1"
    local tmpdir
    tmpdir=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmpdir'" EXIT

    echo "Downloading files from Go module proxy for v${version}..." >&2

    local mod_file="${tmpdir}/v${version}.mod"
    local zip_file="${tmpdir}/v${version}.zip"

    curl -sL "${GO_PROXY}/v${version}.mod" -o "$mod_file" 2>/dev/null
    curl -sL "${GO_PROXY}/v${version}.zip" -o "$zip_file" 2>/dev/null

    if [[ ! -s "$mod_file" ]] || [[ ! -s "$zip_file" ]]; then
        echo "Error: Could not download files from Go module proxy" >&2
        return 1
    fi

    local mod_sha256 mod_size zip_sha256 zip_size

    if command -v sha256sum &>/dev/null; then
        mod_sha256=$(sha256sum "$mod_file" | awk "$AWK_FIRST_FIELD")
        zip_sha256=$(sha256sum "$zip_file" | awk "$AWK_FIRST_FIELD")
    elif command -v shasum &>/dev/null; then
        mod_sha256=$(shasum -a 256 "$mod_file" | awk "$AWK_FIRST_FIELD")
        zip_sha256=$(shasum -a 256 "$zip_file" | awk "$AWK_FIRST_FIELD")
    else
        echo "Error: No sha256 command found" >&2
        return 1
    fi

    if [[ "$OSTYPE" == "darwin"* ]]; then
        mod_size=$(stat -f%z "$mod_file")
        zip_size=$(stat -f%z "$zip_file")
    else
        mod_size=$(stat -c%s "$mod_file")
        zip_size=$(stat -c%s "$zip_file")
    fi

    echo "TIMESTAMP = $(date +%s)"
    echo "SHA256 (go/security_netbird/netbird-v${version}/v${version}.mod) = ${mod_sha256}"
    echo "SIZE (go/security_netbird/netbird-v${version}/v${version}.mod) = ${mod_size}"
    echo "SHA256 (go/security_netbird/netbird-v${version}/v${version}.zip) = ${zip_sha256}"
    echo "SIZE (go/security_netbird/netbird-v${version}/v${version}.zip) = ${zip_size}"
    return 0
}

generate_new_makefile() {
    local new_version="$1"
    local old_makefile="$2"

    # Check if old version had PORTREVISION
    if echo "$old_makefile" | grep -q "^PORTREVISION="; then
        # Remove PORTREVISION line and update DISTVERSION and GO_MODULE
        echo "$old_makefile" | \
            sed "s/^DISTVERSION=.*/DISTVERSION=	${new_version}/" | \
            sed "s|^GO_MODULE=.*|GO_MODULE=        github.com/${GITHUB_REPO}|" | \
            grep -v "^PORTREVISION="
    else
        # Just update DISTVERSION and GO_MODULE
        echo "$old_makefile" | \
            sed "s/^DISTVERSION=.*/DISTVERSION=	${new_version}/" | \
            sed "s|^GO_MODULE=.*|GO_MODULE=        github.com/${GITHUB_REPO}|"
    fi

    return 0
}

# Parse arguments
NEW_VERSION="${1:-}"

# Auto-detect versions if not provided
OLD_VERSION=$(fetch_current_ports_version)
if [[ -z "$OLD_VERSION" ]]; then
    echo "Error: Could not fetch current version from OPNsense ports" >&2
    exit 1
fi
echo "Current OPNsense ports version: ${OLD_VERSION}" >&2

if [[ -z "$NEW_VERSION" ]]; then
    NEW_VERSION=$(fetch_latest_github_release)
    if [[ -z "$NEW_VERSION" ]]; then
        echo "Error: Could not fetch latest release from GitHub" >&2
        exit 1
    fi
fi
echo "Target version: ${NEW_VERSION}" >&2

if [[ "$OLD_VERSION" = "$NEW_VERSION" ]]; then
    echo "Port is already at version ${NEW_VERSION}. Nothing to do." >&2
    exit 0
fi

echo "" >&2

# Fetch current files
echo "Fetching current Makefile from OPNsense ports..." >&2
OLD_MAKEFILE=$(fetch_ports_file "Makefile")
if [[ -z "$OLD_MAKEFILE" ]]; then
    echo "Error: Could not fetch Makefile" >&2
    exit 1
fi

echo "Fetching current distinfo from OPNsense ports..." >&2
OLD_DISTINFO=$(fetch_ports_file "distinfo")
if [[ -z "$OLD_DISTINFO" ]]; then
    echo "Error: Could not fetch distinfo" >&2
    exit 1
fi

# Generate new files
echo "Generating new Makefile..." >&2
NEW_MAKEFILE=$(generate_new_makefile "$NEW_VERSION" "$OLD_MAKEFILE")

echo "Computing checksums for new version..." >&2
NEW_DISTINFO=$(compute_checksums "$NEW_VERSION")
if [[ -z "$NEW_DISTINFO" ]]; then
    echo "Error: Could not compute checksums" >&2
    exit 1
fi

# Create temp files for diff
TMPDIR=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$TMPDIR'" EXIT

mkdir -p "${TMPDIR}/a/security/netbird" "${TMPDIR}/b/security/netbird"

echo "$OLD_MAKEFILE" > "${TMPDIR}/a/security/netbird/Makefile"
echo "$OLD_DISTINFO" > "${TMPDIR}/a/security/netbird/distinfo"
echo "$NEW_MAKEFILE" > "${TMPDIR}/b/security/netbird/Makefile"
echo "$NEW_DISTINFO" > "${TMPDIR}/b/security/netbird/distinfo"

# Generate diff
OUTPUT_FILE="${OUTPUT_DIR}/netbird-${NEW_VERSION}.diff"

echo "" >&2
echo "Generating diff..." >&2

# Generate diff and clean up temp paths to show standard a/b paths
(cd "${TMPDIR}" && diff -ruN "a/security/netbird" "b/security/netbird") > "$OUTPUT_FILE" || true

if [[ ! -s "$OUTPUT_FILE" ]]; then
    echo "Error: Generated diff is empty" >&2
    exit 1
fi

echo "" >&2
echo "========================================="
echo "Diff saved to: ${OUTPUT_FILE}"
echo "========================================="
echo ""
cat "$OUTPUT_FILE"
echo ""
echo "========================================="
echo ""
echo "Next steps (internal):"
echo "1. Review the diff above."
echo "2. Hand-carry ${OUTPUT_FILE} to the OPNsense build node."
echo "3. Apply it against the node's security/netbird port and build the package."
echo ""
