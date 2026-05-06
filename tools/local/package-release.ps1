param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$Configuration = "release",
    [string]$SigningIdentity,
    [string]$PassphraseFile
)

$ErrorActionPreference = "Stop"

Push-Location $ProjectRoot
try {
    if ($PassphraseFile -and -not $SigningIdentity) {
        throw "-PassphraseFile requires -SigningIdentity"
    }

    cargo build --workspace --release

    $dist = Join-Path $ProjectRoot "dist"
    New-Item -ItemType Directory -Path $dist -Force | Out-Null

    $binary = Join-Path $ProjectRoot "target\$Configuration\astragrid.exe"
    if (-not (Test-Path -LiteralPath $binary)) {
        throw "release binary not found: $binary"
    }

    $version = (cargo metadata --no-deps --format-version 1 | ConvertFrom-Json).packages |
        Where-Object { $_.name -eq "astragrid" } |
        Select-Object -First 1 -ExpandProperty version

    $artifact = Join-Path $dist "astragrid-windows-x64-$version.zip"
    if (Test-Path -LiteralPath $artifact) {
        Remove-Item -LiteralPath $artifact -Force
    }

    Compress-Archive -Path $binary, "README.md", "SECURITY.md", "LICENSE" -DestinationPath $artifact

    $gitCommit = $null
    $gitDirty = $null
    try {
        $gitCommit = (git rev-parse --verify HEAD 2>$null)
        if (-not $gitCommit) {
            $gitCommit = $null
        }
    }
    catch {
        $gitCommit = $null
    }
    try {
        $gitDirty = ((git status --porcelain 2>$null | Measure-Object).Count -gt 0)
    }
    catch {
        $gitDirty = $null
    }

    $provenancePath = Join-Path $dist "astragrid-windows-x64-$version.provenance.json"
    if (Test-Path -LiteralPath $provenancePath) {
        Remove-Item -LiteralPath $provenancePath -Force
    }
    $provenanceName = Split-Path -Leaf $provenancePath
    if ($provenanceName.EndsWith(".json")) {
        $signatureName = "$($provenanceName.Substring(0, $provenanceName.Length - 5)).sig.json"
    }
    else {
        $signatureName = "$provenanceName.sig.json"
    }
    $signaturePath = Join-Path $dist $signatureName
    if (Test-Path -LiteralPath $signaturePath) {
        Remove-Item -LiteralPath $signaturePath -Force
    }

    $provenance = [ordered]@{
        schema = 1
        package = "astragrid"
        version = $version
        target = "windows-x64"
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        artifact = [ordered]@{
            path = (Split-Path -Leaf $artifact)
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash.ToLowerInvariant()
        }
        binary = [ordered]@{
            path = "..\target\$Configuration\astragrid.exe"
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant()
        }
        included_files = @("target\$Configuration\astragrid.exe", "README.md", "SECURITY.md", "LICENSE")
        toolchain = [ordered]@{
            cargo = (cargo --version)
            rustc = (rustc --version)
        }
        git = [ordered]@{
            commit = $gitCommit
            dirty = $gitDirty
        }
    }
    $provenance | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $provenancePath -Encoding UTF8
    Write-Host "Packaged $artifact"
    Write-Host "Provenance $provenancePath"

    if ($SigningIdentity) {
        $signArgs = @(
            "provenance",
            "sign",
            "--input",
            $provenancePath,
            "--identity",
            $SigningIdentity
        )
        if ($PassphraseFile) {
            $signArgs += @("--passphrase-file", $PassphraseFile)
        }
        & $binary @signArgs
        if ($LASTEXITCODE -ne 0) {
            throw "provenance signing failed"
        }

        & $binary "provenance" "verify-signature" "--signature" $signaturePath
        if ($LASTEXITCODE -ne 0) {
            throw "provenance signature verification failed"
        }
        Write-Host "Provenance signature $signaturePath"
    }
}
finally {
    Pop-Location
}
