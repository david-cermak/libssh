#!/bin/bash

# libssh installation script
# This script downloads, extracts, and patches libssh for the ESP-IDF port

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Configuration
LIBSSH_VERSION="0.12.0"
LIBSSH_URL="https://git.libssh.org/projects/libssh.git/snapshot/libssh-${LIBSSH_VERSION}.tar.xz"
LIBSSH_DIR="libssh-${LIBSSH_VERSION}"
PATCH_DIR="${SCRIPT_DIR}/patches"

echo "Downloading libssh ${LIBSSH_VERSION}..."

# Download libssh
if ! wget -q --show-progress "$LIBSSH_URL"; then
    echo "Failed to download libssh"
    exit 1
fi

echo "Extracting libssh..."

# Extract the archive
if ! tar -xf "libssh-${LIBSSH_VERSION}.tar.xz"; then
    echo "Failed to extract libssh"
    exit 1
fi

rm "libssh-${LIBSSH_VERSION}.tar.xz"

# Apply ESP-IDF port patches
if [ -d "${PATCH_DIR}" ]; then
    for patch_file in "${PATCH_DIR}"/*.patch; do
        [ -f "$patch_file" ] || continue
        echo "Applying patch: $(basename "$patch_file")..."
        if ! patch -p0 < "$patch_file"; then
            echo "Failed to apply patch: $(basename "$patch_file")"
            exit 1
        fi
    done
fi

echo "libssh ${LIBSSH_VERSION} installed successfully."
