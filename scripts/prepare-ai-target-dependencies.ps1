param(
    [string]$Uv = ".venv\Scripts\uv.exe"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$TargetRoot = Join-Path $ProjectRoot "containers\ai-target"
$InputFile = Join-Path $TargetRoot "requirements.in"
$LockFile = Join-Path $TargetRoot "requirements.lock"

if (-not [System.IO.Path]::IsPathRooted($Uv)) {
    $Uv = Join-Path $ProjectRoot $Uv
}

if (-not (Test-Path -LiteralPath $Uv)) {
    throw "uv executable not found: $Uv"
}

& $Uv pip compile $InputFile `
    --output-file $LockFile `
    --generate-hashes `
    --only-binary :all: `
    --universal `
    --python-version 3.12 `
    --system-certs `
    --custom-compile-command "scripts/prepare-ai-target-dependencies.ps1"
if ($LASTEXITCODE -ne 0) {
    throw "failed to resolve AI Target dependencies"
}

Write-Host "Updated hash-locked AI Target dependencies in $LockFile"
