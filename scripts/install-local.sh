#!/usr/bin/env bash
set -euo pipefail

APP_NAME="KS"
BIN_NAME="ks"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
STAGE_DIR="$REPO_DIR/target/release/ks-install"

usage() {
    cat <<EOF_USAGE
Usage: scripts/install-local.sh [--cli-only]

Build and install $APP_NAME from this source checkout.

Options:
  --cli-only    Install only the $BIN_NAME command to KS_BIN_DIR or ~/.local/bin.

Environment:
  KS_BIN_DIR      Directory for the $BIN_NAME command symlink or binary.
  KS_APP_DIR      macOS .app install path when installing the desktop app.
  KS_INSTALL_DIR  Linux app install path.
EOF_USAGE
}

install_cli_only() {
    local bin_dir="${KS_BIN_DIR:-$HOME/.local/bin}"

    mkdir -p "$bin_dir"
    cp "$REPO_DIR/target/release/$BIN_NAME" "$bin_dir/$BIN_NAME"
    chmod 755 "$bin_dir/$BIN_NAME"

    printf '%s CLI installed.\n' "$APP_NAME"
    printf 'Binary: %s\n' "$bin_dir/$BIN_NAME"
}

install_app_and_cli() {
    mkdir -p "$STAGE_DIR"
    cp "$REPO_DIR/target/release/$BIN_NAME" "$STAGE_DIR/$BIN_NAME"
    cp "$REPO_DIR/assets/icon.png" "$STAGE_DIR/icon.png"
    cp "$REPO_DIR/scripts/install.sh" "$STAGE_DIR/install.sh"
    [ -f "$REPO_DIR/scripts/uninstall.sh" ] && cp "$REPO_DIR/scripts/uninstall.sh" "$STAGE_DIR/uninstall.sh"
    chmod 755 "$STAGE_DIR/$BIN_NAME" "$STAGE_DIR/install.sh"
    [ -f "$STAGE_DIR/uninstall.sh" ] && chmod 755 "$STAGE_DIR/uninstall.sh"

    (cd "$STAGE_DIR" && ./install.sh)
}

cli_only=false
case "${1:-}" in
    "")
        ;;
    --cli-only)
        cli_only=true
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

cargo build --release --manifest-path "$REPO_DIR/Cargo.toml"

if [ "$cli_only" = true ]; then
    install_cli_only
else
    install_app_and_cli
fi
