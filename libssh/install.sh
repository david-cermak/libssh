#!/bin/bash

# libssh installation script
# This script downloads, extracts, and builds libssh from source

set -e  # Exit on any error

# Configuration
LIBSSH_VERSION="0.11.0"
LIBSSH_URL="https://www.libssh.org/files/0.11/libssh-${LIBSSH_VERSION}.tar.xz"
LIBSSH_DIR="libssh-${LIBSSH_VERSION}"
INSTALL_DIR="/usr/local"


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
