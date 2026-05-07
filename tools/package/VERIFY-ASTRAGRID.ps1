param(
    [string]$Root = (Split-Path -Parent $MyInvocation.MyCommand.Path)
)

$ErrorActionPreference = "Stop"

$exe = Join-Path $Root "astragrid.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "astragrid.exe not found in $Root"
}

& $exe --version
if ($LASTEXITCODE -ne 0) {
    throw "astragrid --version failed"
}

& $exe --help | Out-String | Write-Host
if ($LASTEXITCODE -ne 0) {
    throw "astragrid --help failed"
}

Write-Host "AstraGrid executable smoke test passed."
