param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
)

$ErrorActionPreference = "Stop"

$toolRoot = Join-Path $ProjectRoot ".tools"
$env:CARGO_TARGET_DIR = Join-Path $ProjectRoot "target"
$env:ASTRAGRID_TOOL_ROOT = $toolRoot

New-Item -ItemType Directory -Path $toolRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $toolRoot "cache") -Force | Out-Null

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    throw "cargo was not found. Install Rust with a D-drive RUSTUP_HOME/CARGO_HOME before continuing."
}

$rustc = Get-Command rustc -ErrorAction SilentlyContinue
if (-not $rustc) {
    throw "rustc was not found. Install Rust with a D-drive RUSTUP_HOME/CARGO_HOME before continuing."
}

Write-Host "AstraGrid local tool root: $toolRoot"
Write-Host "Cargo target dir: $env:CARGO_TARGET_DIR"
& cargo --version
& rustc --version
