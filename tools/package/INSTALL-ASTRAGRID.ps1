param(
    [string]$InstallDir = "$env:LOCALAPPDATA\AstraGrid\bin",
    [switch]$AddToUserPath,
    [switch]$SkipStartMenuShortcut
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $Root "astragrid.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "astragrid.exe not found in package root: $Root"
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

$files = @(
    "astragrid.exe",
    "START-ASTRAGRID.cmd",
    "VERIFY-ASTRAGRID.ps1",
    "WINDOWS-README.txt",
    "README.md",
    "SECURITY.md",
    "LICENSE"
)
foreach ($file in $files) {
    $source = Join-Path $Root $file
    if (Test-Path -LiteralPath $source) {
        Copy-Item -LiteralPath $source -Destination (Join-Path $InstallDir $file) -Force
    }
}

$installedExe = Join-Path $InstallDir "astragrid.exe"
$versionOutput = (& $installedExe --version | Select-Object -First 1)
if ($LASTEXITCODE -ne 0) {
    throw "installed astragrid.exe failed version smoke"
}

if ($AddToUserPath) {
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $segments = @()
    if ($currentPath) {
        $segments = $currentPath -split ';' | Where-Object { $_ }
    }
    $alreadyPresent = $segments | Where-Object { $_.TrimEnd('\') -ieq $InstallDir.TrimEnd('\') } | Select-Object -First 1
    if (-not $alreadyPresent) {
        $newPath = (@($segments) + $InstallDir) -join ';'
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    }
}

if (-not $SkipStartMenuShortcut) {
    $programs = [Environment]::GetFolderPath("Programs")
    if ($programs) {
        $shortcutDir = Join-Path $programs "AstraGrid"
        New-Item -ItemType Directory -Path $shortcutDir -Force | Out-Null
        $shortcutPath = Join-Path $shortcutDir "AstraGrid.lnk"
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $installedExe
        $shortcut.WorkingDirectory = $InstallDir
        $shortcut.Description = "AstraGrid mission control CLI"
        $shortcut.Save()
    }
}

$manifest = [ordered]@{
    schema = 1
    installed_at = (Get-Date).ToUniversalTime().ToString("o")
    source_root = $Root
    install_dir = $InstallDir
    executable = $installedExe
    version = $versionOutput
    user_path_updated = [bool]$AddToUserPath
    start_menu_shortcut = -not [bool]$SkipStartMenuShortcut
}
$manifestPath = Join-Path $InstallDir "astragrid-install.json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "Installed AstraGrid to $InstallDir"
Write-Host "Version: $versionOutput"
Write-Host "Manifest: $manifestPath"
