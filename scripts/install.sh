#!/usr/bin/env bash
set -euo pipefail

APP_NAME="KS"
APP_ID="ks"
BIN_NAME="ks"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="$SCRIPT_DIR/$BIN_NAME"
ICON_PNG="$SCRIPT_DIR/icon.png"

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

desktop_quote() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '"%s"' "$value"
}

require_release_files() {
    [ -f "$BIN_PATH" ] || fail "missing $BIN_NAME next to install.sh"
    [ -f "$ICON_PNG" ] || fail "missing icon.png next to install.sh"
}

install_linux() {
    local xdg_data="${XDG_DATA_HOME:-$HOME/.local/share}"
    local install_dir="${KS_INSTALL_DIR:-$xdg_data/ks}"
    local bin_dir="${KS_BIN_DIR:-$HOME/.local/bin}"
    local applications_dir="$xdg_data/applications"
    local icons_dir="$xdg_data/icons/hicolor/256x256/apps"
    local desktop_file="$applications_dir/$APP_ID.desktop"
    local desktop_exec

    mkdir -p "$install_dir" "$bin_dir" "$applications_dir" "$icons_dir"
    cp "$BIN_PATH" "$install_dir/$BIN_NAME"
    chmod 755 "$install_dir/$BIN_NAME"
    cp "$ICON_PNG" "$icons_dir/$APP_ID.png"
    [ -f "$SCRIPT_DIR/uninstall.sh" ] && cp "$SCRIPT_DIR/uninstall.sh" "$install_dir/uninstall.sh"
    ln -sf "$install_dir/$BIN_NAME" "$bin_dir/$BIN_NAME"

    desktop_exec="$(desktop_quote "$install_dir/$BIN_NAME")"
    cat > "$desktop_file" <<EOF_DESKTOP
[Desktop Entry]
Type=Application
Name=$APP_NAME
Comment=Encrypted key store
Exec=$desktop_exec
Icon=$APP_ID
Terminal=false
Categories=Utility;Security;
StartupNotify=true
EOF_DESKTOP
    chmod 644 "$desktop_file"

    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$applications_dir" >/dev/null 2>&1 || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q "$xdg_data/icons/hicolor" >/dev/null 2>&1 || true
    fi

    printf '%s installed.\n' "$APP_NAME"
    printf 'Application launcher: %s\n' "$desktop_file"
    printf 'Binary: %s\n' "$install_dir/$BIN_NAME"
}

create_macos_icon() {
    local resources_dir="$1"
    local temp_dir iconset

    cp "$ICON_PNG" "$resources_dir/icon.png"
    if command -v sips >/dev/null 2>&1 && \
        sips -s format icns "$ICON_PNG" --out "$resources_dir/icon.icns" >/dev/null 2>&1; then
        return
    fi

    if ! command -v sips >/dev/null 2>&1 || ! command -v iconutil >/dev/null 2>&1; then
        return
    fi

    temp_dir="$(mktemp -d)"
    iconset="$temp_dir/$APP_NAME.iconset"
    mkdir -p "$iconset"

    sips -z 16 16 "$ICON_PNG" --out "$iconset/icon_16x16.png" >/dev/null
    sips -z 32 32 "$ICON_PNG" --out "$iconset/icon_16x16@2x.png" >/dev/null
    sips -z 32 32 "$ICON_PNG" --out "$iconset/icon_32x32.png" >/dev/null
    sips -z 64 64 "$ICON_PNG" --out "$iconset/icon_32x32@2x.png" >/dev/null
    sips -z 128 128 "$ICON_PNG" --out "$iconset/icon_128x128.png" >/dev/null
    sips -z 256 256 "$ICON_PNG" --out "$iconset/icon_128x128@2x.png" >/dev/null
    sips -z 256 256 "$ICON_PNG" --out "$iconset/icon_256x256.png" >/dev/null
    sips -z 512 512 "$ICON_PNG" --out "$iconset/icon_256x256@2x.png" >/dev/null
    sips -z 512 512 "$ICON_PNG" --out "$iconset/icon_512x512.png" >/dev/null
    sips -z 1024 1024 "$ICON_PNG" --out "$iconset/icon_512x512@2x.png" >/dev/null

    iconutil -c icns "$iconset" -o "$resources_dir/icon.icns" >/dev/null
    rm -rf "$temp_dir"
}

install_macos() {
    local app_dir="${KS_APP_DIR:-$HOME/Applications/$APP_NAME.app}"
    local contents_dir="$app_dir/Contents"
    local macos_dir="$contents_dir/MacOS"
    local resources_dir="$contents_dir/Resources"
    local bin_dir="${KS_BIN_DIR:-$HOME/.local/bin}"

    mkdir -p "$macos_dir" "$resources_dir" "$bin_dir"
    cp "$BIN_PATH" "$macos_dir/$BIN_NAME"
    chmod 755 "$macos_dir/$BIN_NAME"
    create_macos_icon "$resources_dir"
    [ -f "$SCRIPT_DIR/uninstall.sh" ] && cp "$SCRIPT_DIR/uninstall.sh" "$resources_dir/uninstall.sh"
    ln -sf "$macos_dir/$BIN_NAME" "$bin_dir/$BIN_NAME"

    cat > "$contents_dir/Info.plist" <<EOF_PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundleDisplayName</key>
    <string>$APP_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>local.rust-keystore.ks</string>
    <key>CFBundleExecutable</key>
    <string>$BIN_NAME</string>
    <key>CFBundleIconFile</key>
    <string>icon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleSignature</key>
    <string>KS00</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.13</string>
</dict>
</plist>
EOF_PLIST

    printf '%s installed.\n' "$APP_NAME"
    printf 'Application bundle: %s\n' "$app_dir"
    printf 'Binary: %s\n' "$macos_dir/$BIN_NAME"
}

require_release_files

case "$(uname -s)" in
    Linux*) install_linux ;;
    Darwin*) install_macos ;;
    *) fail "install.sh supports Linux and macOS. Use install.ps1 on Windows." ;;
esac
