#!/usr/bin/env bash
set -euo pipefail

APP_NAME="KS"
APP_ID="ks"
BIN_NAME="ks"

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

uninstall_linux() {
    local xdg_data="${XDG_DATA_HOME:-$HOME/.local/share}"
    local install_dir="${KS_INSTALL_DIR:-$xdg_data/ks}"
    local bin_dir="${KS_BIN_DIR:-$HOME/.local/bin}"
    local desktop_file="$xdg_data/applications/$APP_ID.desktop"
    local icon_file="$xdg_data/icons/hicolor/256x256/apps/$APP_ID.png"

    rm -f "$desktop_file" "$icon_file"
    if [ -L "$bin_dir/$BIN_NAME" ]; then
        rm -f "$bin_dir/$BIN_NAME"
    fi
    if [ -d "$install_dir" ]; then
        rm -f "$install_dir/$BIN_NAME" "$install_dir/uninstall.sh"
        rmdir "$install_dir" 2>/dev/null || true
    fi

    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$xdg_data/applications" >/dev/null 2>&1 || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q "$xdg_data/icons/hicolor" >/dev/null 2>&1 || true
    fi

    printf '%s uninstalled.\n' "$APP_NAME"
}

uninstall_macos() {
    local app_dir="${KS_APP_DIR:-$HOME/Applications/$APP_NAME.app}"
    local bin_dir="${KS_BIN_DIR:-$HOME/.local/bin}"

    case "$app_dir" in
        ""|"/"|"$HOME") fail "refusing to remove unsafe app path: $app_dir" ;;
    esac

    if [ -L "$bin_dir/$BIN_NAME" ]; then
        rm -f "$bin_dir/$BIN_NAME"
    fi
    if [ -d "$app_dir" ]; then
        rm -rf "$app_dir"
    fi

    printf '%s uninstalled.\n' "$APP_NAME"
}

case "$(uname -s)" in
    Linux*) uninstall_linux ;;
    Darwin*) uninstall_macos ;;
    *) fail "uninstall.sh supports Linux and macOS. Use uninstall.ps1 on Windows." ;;
esac
