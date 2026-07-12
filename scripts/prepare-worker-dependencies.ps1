param(
    [string]$Uv = ".venv\Scripts\uv.exe"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$WorkerRoot = Join-Path $ProjectRoot "containers\worker"
$InputFile = Join-Path $WorkerRoot "requirements.in"
$LockFile = Join-Path $WorkerRoot "requirements.lock"
$Vendor = Join-Path $WorkerRoot "vendor"

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
    --python-platform x86_64-manylinux_2_17 `
    --python-version 3.12 `
    --system-certs `
    --custom-compile-command "scripts/prepare-worker-dependencies.ps1"
if ($LASTEXITCODE -ne 0) {
    throw "failed to resolve worker dependencies"
}

if (Test-Path -LiteralPath $Vendor) {
    $ResolvedVendor = [System.IO.Path]::GetFullPath($Vendor)
    $ResolvedWorker = [System.IO.Path]::GetFullPath($WorkerRoot)
    if (-not $ResolvedVendor.StartsWith($ResolvedWorker, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to remove vendor directory outside worker root"
    }
    Remove-Item -LiteralPath $ResolvedVendor -Recurse -Force
}
New-Item -ItemType Directory -Path $Vendor | Out-Null

& $Uv pip install `
    --requirements $LockFile `
    --target $Vendor `
    --require-hashes `
    --only-binary :all: `
    --python-platform x86_64-manylinux_2_17 `
    --python-version 3.12 `
    --system-certs
if ($LASTEXITCODE -ne 0) {
    throw "failed to prepare worker dependency bundle"
}

Write-Host "Prepared verified Linux worker dependencies in $Vendor"
