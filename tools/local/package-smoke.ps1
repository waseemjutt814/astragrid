param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$Artifact,
    [string]$SmokeRoot = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path ".cache\package-smoke"),
    [switch]$KeepExtracted
)

$ErrorActionPreference = "Stop"

function Remove-TreeWithRetry {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Attempts = 10,
        [int]$DelayMilliseconds = 250
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force
            return
        }
        catch {
            if ($attempt -eq $Attempts) {
                throw
            }
            Start-Sleep -Milliseconds $DelayMilliseconds
        }
    }
}

Push-Location $ProjectRoot
try {
    if (-not $Artifact) {
        $latest = Get-ChildItem -LiteralPath (Join-Path $ProjectRoot "dist") -Filter "astragrid-windows-x64-*.zip" -File |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1
        if (-not $latest) {
            throw "no dist\astragrid-windows-x64-*.zip artifact found"
        }
        $Artifact = $latest.FullName
    }

    $artifactPath = (Resolve-Path $Artifact).Path
    $projectPath = (Resolve-Path $ProjectRoot).Path
    $smokePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SmokeRoot)
    $cachePath = Join-Path $projectPath ".cache"
    $cachePrefix = $cachePath.TrimEnd('\') + '\'
    if (-not $smokePath.StartsWith($cachePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "SmokeRoot must stay under $cachePath"
    }

    if (Test-Path -LiteralPath $smokePath) {
        Remove-TreeWithRetry -Path $smokePath
    }
    New-Item -ItemType Directory -Path $smokePath -Force | Out-Null
    Expand-Archive -LiteralPath $artifactPath -DestinationPath $smokePath -Force

    $exe = Join-Path $smokePath "astragrid.exe"
    $verifier = Join-Path $smokePath "VERIFY-ASTRAGRID.ps1"
    $installer = Join-Path $smokePath "INSTALL-ASTRAGRID.ps1"
    $launcher = Join-Path $smokePath "START-ASTRAGRID.cmd"
    foreach ($required in @($exe, $verifier, $installer, $launcher)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "package smoke missing required file: $required"
        }
    }

    $versionOutput = (& $exe --version | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0) {
        throw "package astragrid --version failed"
    }

    $launcherOutput = (& $exe | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "package astragrid no-argument launch failed"
    }
    if (-not $launcherOutput.Contains("AstraGrid is installed and ready.")) {
        throw "package astragrid no-argument launch did not print install guidance"
    }

    & powershell -ExecutionPolicy Bypass -File $verifier -Root $smokePath
    if ($LASTEXITCODE -ne 0) {
        throw "VERIFY-ASTRAGRID.ps1 failed"
    }

    $installRoot = Join-Path $smokePath "installed"
    & powershell -ExecutionPolicy Bypass -File $installer -InstallDir $installRoot -SkipStartMenuShortcut
    if ($LASTEXITCODE -ne 0) {
        throw "INSTALL-ASTRAGRID.ps1 failed"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $installRoot "astragrid-install.json"))) {
        throw "installer did not write astragrid-install.json"
    }

    $report = [ordered]@{
        schema = 1
        artifact = $artifactPath
        smoke_root = $smokePath
        version = $versionOutput
        required_files = @(
            "astragrid.exe",
            "VERIFY-ASTRAGRID.ps1",
            "INSTALL-ASTRAGRID.ps1",
            "START-ASTRAGRID.cmd"
        )
        installed_manifest = (Join-Path $installRoot "astragrid-install.json")
        status = "passed"
    }
    $report | ConvertTo-Json -Depth 6

    if (-not $KeepExtracted) {
        Remove-TreeWithRetry -Path $smokePath
    }
}
finally {
    Pop-Location
}
