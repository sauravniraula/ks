$ErrorActionPreference = "Stop"

$AppName = "KS"
$InstallRoot = if ($env:KS_INSTALL_DIR) { $env:KS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\KS" }
$StartMenuShortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\KS.lnk"
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)) "KS.lnk"

Remove-Item -LiteralPath $StartMenuShortcut -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $DesktopShortcut -Force -ErrorAction SilentlyContinue

if (Test-Path -LiteralPath $InstallRoot) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
}

Write-Host "$AppName uninstalled."
