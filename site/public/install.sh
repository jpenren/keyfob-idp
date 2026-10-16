#!/bin/sh
# keyfob installation script for Linux and macOS
# Usage:
#   curl -fsSL https://jpenren.github.io/keyfob-idp/install.sh | sh
# or:
#   curl -fsSL https://raw.githubusercontent.com/jpenren/keyfob-idp/main/install.sh | sh

set -e

REPO="jpenren/keyfob-idp"
APP="keyfob"

# Colors for terminal output
ESC=$(printf '\033')
RED="${ESC}[0;31m"
GREEN="${ESC}[0;32m"
BLUE="${ESC}[0;34m"
YELLOW="${ESC}[0;33m"
BOLD="${ESC}[1m"
RESET="${ESC}[0m"

# Disable colors if not in a terminal or NO_COLOR is set
if [ ! -t 1 ] || [ -n "$NO_COLOR" ]; then
  RED=''
  GREEN=''
  BLUE=''
  YELLOW=''
  BOLD=''
  RESET=''
fi

info() {
  printf "${BLUE}${BOLD}==>${RESET} %s\n" "$1"
}

success() {
  printf "${GREEN}${BOLD}✓${RESET} %s\n" "$1"
}

warn() {
  printf "${YELLOW}${BOLD}!${RESET} %s\n" "$1"
}

error() {
  printf "${RED}${BOLD}Error:${RESET} %s\n" "$1" >&2
  exit 1
}

# 1. Detect operating system
OS="$(uname -s)"
case "$OS" in
  Linux)
    PLATFORM_OS="linux"
    ;;
  Darwin)
    PLATFORM_OS="macos"
    ;;
  CYGWIN*|MINGW*|MSYS*)
    error "Windows shell detected. Please use the PowerShell installer:\n  irm https://jpenren.github.io/keyfob-idp/install.ps1 | iex"
    ;;
  *)
    error "Unsupported operating system: $OS"
    ;;
esac

# 2. Detect machine architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)
    PLATFORM_ARCH="x86_64"
    ;;
  arm64|aarch64)
    if [ "$PLATFORM_OS" = "macos" ]; then
      PLATFORM_ARCH="arm64"
    else
      error "Prebuilt binaries for Linux $ARCH are not available yet. Please build with: cargo install --git https://github.com/$REPO"
    fi
    ;;
  *)
    error "Unsupported architecture: $ARCH"
    ;;
esac

ASSET_NAME="${APP}-${PLATFORM_OS}-${PLATFORM_ARCH}.tar.gz"

# 3. Determine target version and download URLs
if [ -n "$KEYFOB_VERSION" ]; then
  VERSION="$KEYFOB_VERSION"
  case "$VERSION" in
    v*) ;;
    *) VERSION="v$VERSION" ;;
  esac
  DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET_NAME"
  CHECKSUM_URL="https://github.com/$REPO/releases/download/$VERSION/SHA256SUMS"
else
  DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/$ASSET_NAME"
  CHECKSUM_URL="https://github.com/$REPO/releases/latest/download/SHA256SUMS"
fi

# 4. Check for downloader tool
if command -v curl >/dev/null 2>&1; then
  DOWNLOAD_CMD="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOAD_CMD="wget -qO-"
else
  error "Neither 'curl' nor 'wget' was found on your system. Please install one to continue."
fi

# 5. Determine installation directory
if [ -n "$KEYFOB_INSTALL_DIR" ]; then
  INSTALL_DIR="$KEYFOB_INSTALL_DIR"
elif [ -n "$BINDIR" ]; then
  INSTALL_DIR="$BINDIR"
elif [ -d "$HOME/.local/bin" ] || [ ! -w "/usr/local/bin" ]; then
  INSTALL_DIR="$HOME/.local/bin"
else
  INSTALL_DIR="/usr/local/bin"
fi

mkdir -p "$INSTALL_DIR" || error "Failed to create directory $INSTALL_DIR"

info "Installing ${BOLD}${APP}${RESET} (${PLATFORM_OS}-${PLATFORM_ARCH}) into ${BOLD}${INSTALL_DIR}${RESET}..."

# 6. Create temporary working directory
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'keyfob-install')"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# 7. Download asset and checksums
info "Downloading release archive..."
if [ "${DOWNLOAD_CMD%% *}" = "curl" ]; then
  curl -fSL "$DOWNLOAD_URL" -o "$TMP_DIR/$ASSET_NAME" || error "Failed to download $DOWNLOAD_URL"
  curl -fsSL "$CHECKSUM_URL" -o "$TMP_DIR/SHA256SUMS" 2>/dev/null || true
else
  wget -q "$DOWNLOAD_URL" -O "$TMP_DIR/$ASSET_NAME" || error "Failed to download $DOWNLOAD_URL"
  wget -q "$CHECKSUM_URL" -O "$TMP_DIR/SHA256SUMS" 2>/dev/null || true
fi

# 8. Verify checksum if SHA256SUMS is available
if [ -s "$TMP_DIR/SHA256SUMS" ]; then
  EXPECTED_SHA=$(grep "$ASSET_NAME" "$TMP_DIR/SHA256SUMS" | awk '{print $1}' || true)
  if [ -n "$EXPECTED_SHA" ]; then
    info "Verifying SHA256 checksum..."
    if command -v sha256sum >/dev/null 2>&1; then
      ACTUAL_SHA=$(sha256sum "$TMP_DIR/$ASSET_NAME" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
      ACTUAL_SHA=$(shasum -a 256 "$TMP_DIR/$ASSET_NAME" | awk '{print $1}')
    else
      ACTUAL_SHA=""
    fi

    if [ -n "$ACTUAL_SHA" ]; then
      if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
        error "Checksum mismatch! Expected $EXPECTED_SHA, got $ACTUAL_SHA"
      fi
      success "Checksum verified"
    fi
  fi
fi

# 9. Extract and install binary
info "Extracting archive..."
tar -xzf "$TMP_DIR/$ASSET_NAME" -C "$TMP_DIR"

BINARY_PATH=$(find "$TMP_DIR" -type f -name "$APP" | head -n 1)
if [ -z "$BINARY_PATH" ] || [ ! -f "$BINARY_PATH" ]; then
  error "Could not find binary '$APP' in the downloaded archive"
fi

mv "$BINARY_PATH" "$INSTALL_DIR/$APP"
chmod 755 "$INSTALL_DIR/$APP"

# On macOS, clear quarantine attribute if needed
if [ "$PLATFORM_OS" = "macos" ]; then
  xattr -d com.apple.quarantine "$INSTALL_DIR/$APP" 2>/dev/null || true
fi

success "Installed ${BOLD}${APP}${RESET} to ${BOLD}$INSTALL_DIR/$APP${RESET}"

# 10. Check PATH
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    warn "${INSTALL_DIR} is not in your PATH."
    printf "To add it to your current shell session, run:\n"
    printf "  ${BOLD}export PATH=\"%s:\$PATH\"${RESET}\n\n" "$INSTALL_DIR"
    printf "To make it permanent, add that line to your ${BOLD}~/.bashrc${RESET} or ${BOLD}~/.zshrc${RESET}.\n\n"
    ;;
esac

# 11. Quickstart instructions
printf "\n${GREEN}${BOLD}Keyfob has been installed successfully!${RESET}\n\n"
printf "Get started:\n"
printf "  ${BOLD}keyfob init${RESET}       # generate a default keyfob.yaml\n"
printf "  ${BOLD}keyfob run${RESET}        # start the in-memory OIDC provider\n\n"
