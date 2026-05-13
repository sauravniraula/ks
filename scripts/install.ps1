$ErrorActionPreference = "Stop"

$AppName = "KS"
$BinaryName = "ks.exe"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BinaryPath = Join-Path $ScriptDir $BinaryName
$IconPng = Join-Path $ScriptDir "icon.png"
$IconIco = Join-Path $ScriptDir "icon.ico"
$InstallRoot = if ($env:KS_INSTALL_DIR) { $env:KS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\KS" }
$TargetBinary = Join-Path $InstallRoot $BinaryName

if (!(Test-Path -LiteralPath $BinaryPath)) {
    throw "Missing $BinaryName next to install.ps1"
}
if (!(Test-Path -LiteralPath $IconPng)) {
    throw "Missing icon.png next to install.ps1"
}

New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
Copy-Item -LiteralPath $BinaryPath -Destination $TargetBinary -Force
Copy-Item -LiteralPath $IconPng -Destination (Join-Path $InstallRoot "icon.png") -Force

if (Test-Path -LiteralPath $IconIco) {
    Copy-Item -LiteralPath $IconIco -Destination (Join-Path $InstallRoot "icon.ico") -Force
}
foreach ($ScriptName in @("install.ps1", "uninstall.ps1")) {
    $ScriptPath = Join-Path $ScriptDir $ScriptName
    if (Test-Path -LiteralPath $ScriptPath) {
        Copy-Item -LiteralPath $ScriptPath -Destination (Join-Path $InstallRoot $ScriptName) -Force
    }
}

function New-KsShortcut {
    param(
        [Parameter(Mandatory = $true)][string]$ShortcutPath
    )

    $ShortcutDir = Split-Path -Parent $ShortcutPath
    New-Item -ItemType Directory -Force -Path $ShortcutDir | Out-Null

    $Shell = New-Object -ComObject WScript.Shell
    $Shortcut = $Shell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $TargetBinary
    $Shortcut.WorkingDirectory = $InstallRoot
    $Shortcut.Description = "Encrypted key store"

    $InstalledIcon = Join-Path $InstallRoot "icon.ico"
    if (Test-Path -LiteralPath $InstalledIcon) {
        $Shortcut.IconLocation = "$InstalledIcon,0"
    } else {
        $Shortcut.IconLocation = "$TargetBinary,0"
    }

    $Shortcut.Save()
}

$StartMenuShortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\KS.lnk"
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)) "KS.lnk"

New-KsShortcut -ShortcutPath $StartMenuShortcut
New-KsShortcut -ShortcutPath $DesktopShortcut

Write-Host "$AppName installed."
Write-Host "Start Menu shortcut: $StartMenuShortcut"
Write-Host "Desktop shortcut: $DesktopShortcut"
Write-Host "Binary: $TargetBinary"
