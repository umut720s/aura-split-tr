# SPDX-License-Identifier: GPL-3.0-or-later
#
# Authenticode-signs one file with signtool and a code-signing certificate
# supplied as a base64 .pfx in SIGN_CERT_PFX_BASE64 / SIGN_CERT_PASSWORD
# (GitHub secrets). Used by .github/workflows/release.yml only when
# vars.AURA_SIGNING_METHOD == 'signtool-pfx'.
#
# It fails (never silently continues) when the certificate is missing, when
# signing fails or when the resulting signature does not verify. It never
# creates a self-signed or test certificate.

param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$Description = "AURA Split TR"
)

$ErrorActionPreference = "Stop"

if (-not $env:SIGN_CERT_PFX_BASE64 -or -not $env:SIGN_CERT_PASSWORD) {
    throw "Signing requested but SIGN_CERT_PFX_BASE64 / SIGN_CERT_PASSWORD are not set."
}
if (-not (Test-Path -LiteralPath $Path)) {
    throw "File to sign not found: $Path"
}
$timestamp = $env:SIGN_TIMESTAMP_URL
if (-not $timestamp) {
    throw "Signing requested but vars.SIGN_TIMESTAMP_URL (RFC 3161 timestamp server of the CA) is not set."
}

# Newest x64 signtool from the Windows SDK on the runner.
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object { [version]($_.Directory.Parent.Name) } -Descending |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) { throw "signtool.exe not found (Windows SDK)." }

$pfx = Join-Path $env:RUNNER_TEMP ("sign-" + [guid]::NewGuid().ToString("N") + ".pfx")
try {
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:SIGN_CERT_PFX_BASE64))
    & $signtool sign /fd SHA256 /td SHA256 /tr $timestamp /d $Description /f $pfx /p $env:SIGN_CERT_PASSWORD $Path
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed ($LASTEXITCODE) for $Path" }
} finally {
    Remove-Item -LiteralPath $pfx -Force -ErrorAction SilentlyContinue
}

& $signtool verify /pa /v $Path
if ($LASTEXITCODE -ne 0) { throw "signtool verify failed ($LASTEXITCODE) for $Path" }
Write-Host "Signed and verified: $Path"
