#!/bin/bash

# libssh installation script
# This script patches the libssh upstream (adds optional MLKEM support)

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Configuration
LIBSSH_VERSION="mirror"    # Developer's mode
PATCH_DIR="${SCRIPT_DIR}/patches"

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
