# Katkıda bulunma / Contributing

Katkılarınız memnuniyetle karşılanır. Kısa Türkçe özet aşağıda; ayrıntılar
İngilizce.

- Güvenlik açıklarını **herkese açık issue olarak açmayın**; [SECURITY.md](SECURITY.md)
  içindeki özel bildirim yolunu kullanın.
- Hata bildirirken `aurasplit.exe version` çıktısını ve günlükten ilgili satırları
  ekleyin; **kullanıcı adlarını** (`C:\Users\<ad>\...`), IP adreslerini ve `.conf`
  içeriğini paylaşmayın. `.conf` dosyaları ve `profile.json` özel anahtar içerir.
- Katkılarınız GPL-3.0-or-later lisansı altında dağıtılır.

## License of contributions

By submitting a contribution you agree that it is licensed under
**GPL-3.0-or-later**, the license of this project, and that you have the right
to submit it. Please add `Signed-off-by: Name <email>` (`git commit -s`,
[Developer Certificate of Origin](https://developercertificate.org/)) to your
commits. New Go files start with:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
```

Do not copy code from projects whose license is not GPL-3.0-compatible.
Adding or upgrading a dependency must keep `THIRD_PARTY_LICENSES.md` accurate
(see [docs/BUILD.md](docs/BUILD.md)).

## Development

Requirements: the Go version from `go.mod`, Windows 10/11 x64.

```powershell
gofmt -l .                                         # must print nothing
go vet -tags with_gvisor,with_wireguard ./...
go test ./...
go test -tags with_gvisor,with_wireguard ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 -tags with_gvisor,with_wireguard ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 -tags with_gvisor,with_wireguard ./...
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

CI (`.github/workflows/ci.yml`) runs the same checks on every push and pull
request.

## Pull requests

- Keep changes focused; one topic per pull request.
- Explain *why* in the description, and how you tested it. Say clearly what was
  **tested on a real network**, what was only unit-tested, and what was not
  tested.
- Security-relevant changes (ACLs, service install, tunnel/kill-switch, DNS,
  key handling, logging of personal data) need a test and a note in
  [SECURITY.md](SECURITY.md) if the threat model changes.
- Never commit build output (`dist/`, `*.exe`), WireGuard `.conf` files,
  `profile.json`, `tunnel-state.json`, logs or real keys. `.gitignore` covers
  these; double-check `git status` before committing.
- Do not log secrets (private keys, preshared keys, tokens) or browsing
  history at the default log level.

## Reporting bugs

Open an issue with: version (`aurasplit.exe version`), Windows version,
provider type (WARP / Proton / other WireGuard, no account details), steps to
reproduce, expected vs. actual behaviour, and **redacted** log lines from
`%ProgramData%\AuraSplitTR\service.log`. Replace user names in paths such as
`C:\Users\<name>\...`, and remove IP addresses and host names you do not want
to share.
