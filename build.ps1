# SPDX-License-Identifier: GPL-3.0-or-later
# Builds dist\aurasplit.exe (Windows x64), the Windows Installer package
# dist\AuraSplitTR-<version>-x64.msi and dist\SHA256SUMS.txt.
# Requires the Go toolchain and, for the MSI, WiX Toolset 5.0.2 as a .NET
# global tool with the WixToolset.Util.wixext 5.0.2 extension:
#   dotnet tool install --global wix --version 5.0.2
#   wix extension add -g WixToolset.Util.wixext/5.0.2
#
# Usage:  powershell -ExecutionPolicy Bypass -File .\build.ps1 [-Version 1.0.0] [-Strict] [-NoMsi | -MsiOnly]
#
#   -NoMsi    build only aurasplit.exe
#   -MsiOnly  skip the Go build and package the existing dist\aurasplit.exe
#             (the release workflow signs the exe in between, see
#             .github/workflows/release.yml)
#
# Reproducibility: the same source tree + the same Go toolchain version + the
# same -Version value produce a byte-identical aurasplit.exe. -Strict makes a
# toolchain (Go or WiX) mismatch a hard error (used by the release workflow).
# The MSI is NOT byte-reproducible (it carries a new ProductCode/PackageCode
# and timestamps on every build); compare the aurasplit.exe it contains.
# See docs/BUILD.md.

param(
    [string]$Version = "dev",
    [switch]$Strict,
    [switch]$NoMsi,
    [switch]$MsiOnly
)

# Build tags MUST match the tags required by internal/engine (sing-box features).
$Tags = "with_gvisor,with_wireguard,with_external_windivert"
# Pinned WiX version (WiX 6+ requires accepting the OSMF EULA; not used).
$WixWant = "5.0.2"

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if ($NoMsi -and $MsiOnly) {
    throw "-NoMsi ve -MsiOnly birlikte kullanilamaz."
}
if ($Version -notmatch '^[0-9A-Za-z.+_-]+$') {
    throw "Gecersiz surum metni: $Version"
}

$dist = Join-Path $PSScriptRoot "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$out = Join-Path $dist "aurasplit.exe"

if (-not $MsiOnly) {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw "Go bulunamadi. https://go.dev/dl/ adresinden kurun."
    }

    # Toolchain check: the expected version is the go.mod 'toolchain' line if
    # present, otherwise the 'go' line.
    $gomod = Get-Content -Path (Join-Path $PSScriptRoot "go.mod")
    $want = ($gomod | Where-Object { $_ -match '^toolchain\s+(go\S+)' } | ForEach-Object { $Matches[1] } | Select-Object -First 1)
    if (-not $want) {
        $want = ($gomod | Where-Object { $_ -match '^go\s+(\S+)' } | ForEach-Object { "go" + $Matches[1] } | Select-Object -First 1)
    }
    $have = (& go env GOVERSION).Trim()
    if ($want -and $have -ne $want) {
        $msg = "Go surumu $have, go.mod $want bekliyor; cikti tekrar uretilebilir (reproducible) olmayabilir."
        if ($Strict) { throw $msg } else { Write-Warning $msg }
    }

    # Fixed target and environment so local settings cannot change the output.
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:GOAMD64 = "v1"
    $env:CGO_ENABLED = "0"
    $env:GOFLAGS = "-mod=readonly"
    $env:GOEXPERIMENT = ""

    # Pinned build-time tool only; never add it to the application's go.mod.
    # The resource is deterministic; no timestamp or git-derived version.
    $resourceVersion = "0.0.0.0"
    if ($Version -match '^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$') {
        $parts = @($Matches[1], $Matches[2], $Matches[3])
        foreach ($part in $parts) {
            if ([long]$part -gt 65535) { throw "PE surum siniri asildi: $Version" }
        }
        $resourceVersion = (($parts | ForEach-Object { [int]$_ }) -join '.') + '.0'
    } elseif ($Strict) {
        throw "Surum PE surumune cevrilemiyor: $Version"
    } else {
        Write-Warning "PE surumu $resourceVersion kullaniliyor: $Version"
    }
    $savedGoFlags = $env:GOFLAGS
    try {
        $env:GOFLAGS = "-mod=mod"
        go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --arch amd64 --out cmd/aurasplit/rsrc --file-version $resourceVersion --product-version $resourceVersion
        if ($LASTEXITCODE -ne 0) { throw "go-winres basarisiz (cikis kodu $LASTEXITCODE)" }
    } finally {
        $env:GOFLAGS = $savedGoFlags
    }

    Write-Host "Derleniyor: $out (surum $Version, etiketler $Tags, $have)"
    # -trimpath: no local paths; -buildvcs=false: no VCS stamp (dirty flag/time);
    # -buildid=: empty build ID; -s -w: no symbol/DWARF tables.
    go build -trimpath -buildvcs=false -tags $Tags -ldflags "-s -w -buildid= -X main.version=$Version" -o $out ./cmd/aurasplit
    if ($LASTEXITCODE -ne 0) { throw "go build basarisiz (cikis kodu $LASTEXITCODE)" }
} elseif (-not (Test-Path -LiteralPath $out)) {
    throw "-MsiOnly: $out bulunamadi; once exe'yi derleyin."
}

# Files listed in SHA256SUMS.txt: only what this run produced or packaged.
$artifacts = @($out)

if (-not $NoMsi) {
    # Windows Installer versions are major.minor.build (major, minor <= 255,
    # build <= 65535); a pre-release suffix is dropped: 0.1.0-beta -> 0.1.0.
    # Same-version packages upgrade each other (MajorUpgrade
    # AllowSameVersionUpgrades), so 0.1.0 replaces 0.1.0-beta.
    if ($Version -match '^v?(\d+)\.(\d+)\.(\d+)') {
        $msiVersion = "$([int]$Matches[1]).$([int]$Matches[2]).$([int]$Matches[3])"
        if ([int]$Matches[1] -gt 255 -or [int]$Matches[2] -gt 255 -or [int]$Matches[3] -gt 65535) {
            throw "Surum MSI sinirlarini asiyor (major/minor <= 255, build <= 65535): $Version"
        }
    } else {
        $msiVersion = "0.0.0"
        $msg = "Surum '$Version' MSI surumune cevrilemiyor; MSI surumu $msiVersion kullaniliyor."
        if ($Strict) { throw $msg } else { Write-Warning $msg }
    }

    # Locate wix: PATH first, then the default .NET global tool folder.
    $wix = (Get-Command wix -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $wix) {
        $candidate = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
        if (Test-Path -LiteralPath $candidate) { $wix = $candidate }
    }
    if (-not $wix) {
        throw "WiX bulunamadi. Kurulum: dotnet tool install --global wix --version $WixWant ; wix extension add -g WixToolset.Util.wixext/$WixWant  (MSI olmadan derlemek icin: -NoMsi)"
    }
    $wixHave = ((& $wix --version) | Select-Object -First 1).Trim()
    if ($wixHave -notmatch ("^" + [regex]::Escape($WixWant) + "(\+|$)")) {
        $msg = "WiX surumu $wixHave, beklenen $WixWant."
        if ($Strict) { throw $msg } else { Write-Warning $msg }
    }
    $extList = (& $wix extension list -g) -join "`n"
    $wixExtension = "WixToolset.Util.wixext"
    if ($extList -notmatch ("WixToolset\.Util\.wixext\s+" + [regex]::Escape($WixWant))) {
        # Some global caches contain the installed DLL but are not listed by
        # the CLI. Use that exact pinned version without changing the cache.
        $extensionRoot = Join-Path $env:USERPROFILE ".wix\extensions\WixToolset.Util.wixext\$WixWant"
        $extensionDll = @("wixext5", "wixext4") |
            ForEach-Object { Join-Path $extensionRoot "$_\WixToolset.Util.wixext.dll" } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
        if (-not $extensionDll) {
            throw "WixToolset.Util.wixext $WixWant kurulu degil: wix extension add -g WixToolset.Util.wixext/$WixWant"
        }
        $wixExtension = $extensionDll
    }

    $msiName = "AuraSplitTR-$Version-x64.msi"
    $msi = Join-Path $dist $msiName
    $obj = Join-Path $PSScriptRoot "obj\installer"
    New-Item -ItemType Directory -Force -Path $obj | Out-Null
    $pdb = Join-Path $obj ([IO.Path]::ChangeExtension($msiName, ".wixpdb"))
    # Stale packages from earlier runs are not part of this build.
    Get-ChildItem -Path $dist -Filter "AuraSplitTR-*-x64.msi" -File | Remove-Item -Force

    Write-Host "MSI olusturuluyor: $msi (MSI surumu $msiVersion, WiX $wixHave)"
    & $wix build -arch x64 -ext $wixExtension `
        -d "Version=$msiVersion" -d "BinDir=$dist" -d "DocDir=$PSScriptRoot" `
        -intermediatefolder $obj -pdb $pdb `
        -o $msi (Join-Path $PSScriptRoot "installer\AuraSplitTR.wxs")
    if ($LASTEXITCODE -ne 0) { throw "wix build basarisiz (cikis kodu $LASTEXITCODE)" }

    # Static ICE validation (nothing is installed). ICE43/ICE57 are
    # suppressed: they assume ProgramMenuFolder is per-user, but this package
    # is per-machine (Scope="perMachine", ALLUSERS=1), so the Start Menu
    # shortcut lives in the all-users Start Menu with a per-machine key path.
    Write-Host "MSI dogrulaniyor (ICE)"
    & $wix msi validate -sice ICE43 -sice ICE57 -pdb $pdb $msi
    if ($LASTEXITCODE -ne 0) { throw "wix msi validate basarisiz (cikis kodu $LASTEXITCODE)" }

    $artifacts += $msi
}

$sums = Join-Path $dist "SHA256SUMS.txt"
$lines = $artifacts |
    ForEach-Object { Get-Item -LiteralPath $_ } |
    Sort-Object Name |
    ForEach-Object {
        $h = (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLower()
        "$h  $($_.Name)"
    }
# UTF-8 without BOM, LF line endings, so sha256sum -c works on other systems.
$text = ($lines -join "`n") + "`n"
[System.IO.File]::WriteAllText($sums, $text, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "Tamam."
Get-Content $sums
