# Building and verifying AURA Split TR

## Requirements

- Windows 10/11 x64 (cross-compiling from Linux/macOS also works, see below).
- The Go toolchain version named in `go.mod` (the `toolchain` line if present,
  otherwise the `go` line). No C compiler (CGO is disabled).
- **go-winres v0.3.3**: pinned build-time tool invoked with `go run`; it is not linked into the application or required by its `go.mod`. Cache the tool and its dependencies before offline builds. If `GOPROXY=off` prevents Go from checking cached deprecation metadata, use a `file:///` GOPROXY pointing to the local module cache download directory; this also stays offline.
- For the Windows Installer package (MSI): **WiX Toolset 5.0.2** as a .NET
  global tool plus the util extension, both pinned (needs the .NET SDK):

  ```powershell
  dotnet tool install --global wix --version 5.0.2
  wix extension add -g WixToolset.Util.wixext/5.0.2
  # the tool lands in %USERPROFILE%\.dotnet\tools (build.ps1 also looks there)
  ```

  WiX 6 and later are deliberately **not** used: they require accepting the
  Open Source Maintenance Fee EULA, which this project has not accepted.
  `build.ps1` warns on another WiX version (error with `-Strict`). Without
  WiX, build only the exe with `-NoMsi`.

`build.ps1` compares `go env GOVERSION` with `go.mod` and warns on a mismatch;
with `-Strict` (used by the release workflow) a mismatch is an error. With
Go's default `GOTOOLCHAIN=auto`, an *older* local Go automatically downloads
the toolchain required by `go.mod`; a *newer* local Go builds with itself, so
set it explicitly to reproduce a release, e.g.
`$env:GOTOOLCHAIN = "go1.26.11"` (use the version from `go.mod`).

> **Maintainer note:** pin the toolchain explicitly with a `toolchain goX.Y.Z`
> line in `go.mod` (e.g. `go mod edit -toolchain=go1.26.11`). The release
> workflow (`actions/setup-go` with `go-version-file: go.mod`) and
> `build.ps1 -Strict` then use exactly that version.

## Build

```powershell
git clone https://github.com/umut720s/aura-split-tr.git
cd aura-split-tr
git checkout v0.1.0-beta          # a release tag
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Version 0.1.0-beta -Strict
```

Output: `dist\aurasplit.exe`, `dist\AuraSplitTR-<version>-x64.msi` and
`dist\SHA256SUMS.txt` (both files). Switches: `-NoMsi` (exe only), `-MsiOnly`
(package the existing `dist\aurasplit.exe`; when signing is configured for a later
release, the release workflow signs the exe between the two steps).

`build.ps1`, `dist\auraclean.exe` yardımcısını da aynı hedef ve tekrarlanabilir
derleme bayraklarıyla, özel build tag olmadan üretir. `-NoMsi` iki exe'yi derler;
`-MsiOnly` ikisinin de mevcut olmasını gerektirir. `auraclean.exe`, yalnızca MSI'nin
`AuraCleanupExe` Binary akışında bulunur; kurulum klasörüne, yayın zip'ine,
bağımsız yayın dosyalarına veya `SHA256SUMS.txt` listesine eklenmez. MSI'nin
sağlama toplamı ve provenance kaydı gömülü yardımcıyı da kapsar. CI ve release
iş akışları iki exe için de `build.ps1` kullanır; yayın dosya listeleri değişmez.
Yardımcı, `uninstall --msi` ile yönetici/SYSTEM bağlamında ortak
`internal/msiclean` yolunu çalıştırır: hizmeti devre dışı bırakıp durdurur,
`internal/wfp` ile politikayı kaldırır ve başarıdan sonra `paths.CleanDataDir`
güvenlik denetimleriyle temizler. Engine/sing-box bağımlılığı yoktur;
`go list -deps ./cmd/auraclean` ile doğrulanabilir.

### MSI

`installer/AuraSplitTR.wxs` is built with

```powershell
wix build -arch x64 -ext WixToolset.Util.wixext -d Version=<msi version> `
  -d BinDir=dist -d DocDir=. -o dist\AuraSplitTR-<version>-x64.msi installer\AuraSplitTR.wxs
wix msi validate -sice ICE43 -sice ICE57 dist\AuraSplitTR-<version>-x64.msi
```

- **Version:** Windows Installer needs `major.minor.build` (major/minor ≤ 255,
  build ≤ 65535). `build.ps1` drops a pre-release suffix: `0.1.0-beta` →
  `0.1.0`; a non-numeric version such as `dev` becomes `0.0.0` (warning; error
  with `-Strict`). The file name keeps the full version string. Same-version
  packages upgrade each other (`AllowSameVersionUpgrades`), so `0.1.0`
  replaces `0.1.0-beta`; this triggers the expected ICE61 warning.
- **UpgradeCode** `3722A804-04C6-4115-AE01-641B4549159E` is fixed forever;
  ProductCode/PackageCode are new on every build.
- **Validation** (`wix msi validate`) runs the standard ICE rules on the
  database; nothing is installed. ICE43/ICE57 are suppressed: they assume
  `ProgramMenuFolder` is per-user, but the package is per-machine
  (`ALLUSERS=1`). Expected warning: ICE61 (same-version upgrades). The EXE now has an actual PE version resource; no DefaultVersion workaround or WIX1103 warning is expected.
- **Not reproducible byte for byte:** new GUIDs and timestamps per build.
  Compare the `aurasplit.exe` inside it with an independent build, e.g. after
  an administrative extraction `msiexec /a <msi> /qn TARGETDIR=<empty folder>`
  (only unpacks the files; registers nothing).
- Ara dosyalar (`.wixpdb`, cabinet), `GOTMPDIR` veya sistem geçici klasörü
  altındaki `aurasplit-installer` klasörüne yazılır.

What `build.ps1` fixes so the output does not depend on the build machine:

| Setting | Value | Why |
|---|---|---|
| `GOOS` / `GOARCH` / `GOAMD64` | `windows` / `amd64` / `v1` | fixed target |
| `CGO_ENABLED` | `0` | no C toolchain, no host libraries |
| `GOFLAGS` | `-mod=readonly` | build fails instead of silently changing `go.mod`/`go.sum` |
| `GOEXPERIMENT` | empty | no experimental compiler features |
| `-tags` | `with_gvisor,with_wireguard,with_external_windivert` | sing-box features required by `internal/engine` |
| `-trimpath` | | no local file system paths in the binary |
| `-buildvcs=false` | | no VCS revision/time/dirty flag embedded |
| `-ldflags -s -w -buildid=` | | no symbol/DWARF tables, empty build ID |
| `-ldflags -X main.version=` | release version | only intentional variable input |

Before each Go build, `build.ps1` regenerates the ignored
`cmd/aurasplit/rsrc_windows_amd64.syso` from `winres/winres.json` and
`assets/aura.ico` using go-winres v0.3.3. File/product versions are numeric:
`0.1.0-beta` becomes `0.1.0.0`. Interactive elevation stays in the app;
the manifest uses asInvoker. Resource bytes are deterministic given the same
JSON, icon, tool version and numeric version, so those inputs are also part
of reproducibility. CI and release EXE builds use this same build.ps1 step.

Go does not embed timestamps, so no `SOURCE_DATE_EPOCH` equivalent is needed:
the same source, the same toolchain version and the same `-Version` produce a
byte-identical `aurasplit.exe`. (Checked locally: two clean builds, one with
`-a`, gave the same SHA-256.)

The release zip is **not** byte-reproducible (`Compress-Archive` stores file
times). Compare the `aurasplit.exe` inside it, not the zip itself.

### Cross-compiling from Linux/macOS

```sh
GOFLAGS=-mod=mod go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json \
  --arch amd64 --out cmd/aurasplit/rsrc --file-version 0.1.0.0 --product-version 0.1.0.0
GOOS=windows GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 GOFLAGS=-mod=readonly \
  go build -trimpath -buildvcs=false -tags with_gvisor,with_wireguard,with_external_windivert \
  -ldflags "-s -w -buildid= -X main.version=0.1.0-beta" \
  -o aurasplit.exe ./cmd/aurasplit
sha256sum aurasplit.exe
```

This should match the Windows build when the Go version is the same.

## Verifying a downloaded release

Official builds are produced only by `.github/workflows/release.yml` from a
tagged commit. Each release has `SHA256SUMS.txt` and a GitHub build provenance
attestation for `aurasplit.exe`, `AuraSplitTR-<version>-x64.msi` and the zip.
The `.exe` and the `.msi` are **not** Authenticode-signed yet.

### Code signing (prepared, not configured)

The release workflow contains signing steps (`.github/scripts/sign.ps1`,
signtool + timestamp) that run only when the repository variable
`AURA_SIGNING_METHOD` is `signtool-pfx` and the secrets
`SIGN_CERT_PFX_BASE64` / `SIGN_CERT_PASSWORD` plus the variable
`SIGN_TIMESTAMP_URL` are set. Order: sign the exe → build the MSI around the
signed exe → sign the MSI → compute SHA256SUMS.txt and the attestation. The
comments name Azure Trusted Signing and SignPath as alternatives behind the
same gate. When nothing is configured the steps are skipped and the
"Signing status" step prints a warning; no placeholder or self-signed
signature is ever produced. Check a downloaded file with
`Get-AuthenticodeSignature .\AuraSplitTR-<version>-x64.msi`.

1. Checksum (PowerShell):

   ```powershell
   (Get-FileHash .\AuraSplitTR-0.1.0-beta-x64.msi -Algorithm SHA256).Hash.ToLower()
   (Get-FileHash .\aurasplit.exe -Algorithm SHA256).Hash.ToLower()
   Get-Content .\SHA256SUMS.txt
   ```

   or on Linux/macOS/Git Bash: `sha256sum -c SHA256SUMS.txt --ignore-missing`.

2. Provenance (requires the GitHub CLI):

   ```sh
   gh attestation verify AuraSplitTR-0.1.0-beta-x64.msi --repo umut720s/aura-split-tr
   gh attestation verify aurasplit.exe --repo umut720s/aura-split-tr
   ```

   This proves the file was built by this repository's release workflow and
   shows the commit and workflow run it came from.

3. Independent rebuild: build the same tag as described above with the same Go
   version and compare the SHA-256 of `dist\aurasplit.exe` with the one in
   `SHA256SUMS.txt`.

## Third-party license list

`THIRD_PARTY_LICENSES.md` must match the modules linked into the binary.
Regenerate/review it whenever `go.mod` changes:

```powershell
$env:GOOS="windows"; $env:GOARCH="amd64"
go list -deps -tags with_gvisor,with_wireguard,with_external_windivert -f '{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}' ./cmd/aurasplit | Sort-Object -Unique
```
