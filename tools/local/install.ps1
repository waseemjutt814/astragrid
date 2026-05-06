param(
    [string]$InstallDir = "$env:LOCALAPPDATA\AstraGrid\bin",
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
)

$ErrorActionPreference = "Stop"

Push-Location $ProjectRoot
try {
    cargo build -p astragrid --release
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $ProjectRoot "target\release\astragrid.exe") -Destination (Join-Path $InstallDir "astragrid.exe") -Force
    Write-Host "Installed astragrid.exe to $InstallDir"
    Write-Host "Add this directory to PATH if needed."
}
finally {
    Pop-Location
}
