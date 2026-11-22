# Phase 3 — Security review (Agent B, Go security)

Date: 2026-11-22 · Scope: the whole `aurasplit` module, with a focus on the
second-remediation code that had not been reviewed before:
`internal/paths/secure_windows.go` (adoption, quarantine, `replaceWithCopy`,
`OpenSecureAppend`), `internal/engine/logpump.go`, `internal/logfile`,
`cmd/aurasplit/elevate_windows.go` (tombstone uninstall), `setup.go`
(preflight, rollback, staging), `selfimage_windows.go`, `state_windows.go`
(heartbeat, `stateValid`) and `engine.go` (retry with `prepareBox`).

Method: I read the code and the relevant dependency sources in the module
cache: sing-box v1.14.4, sing, sing-tun, sagernet/wireguard-go and the Go
1.26.5 `os` package. I ran these non-elevated checks, with the output kept
in the session scratchpad:

- `go vet -tags with_gvisor,with_wireguard ./...` exited 0 with no output.
- `go build -trimpath -buildvcs=false -tags with_gvisor,with_wireguard ./cmd/aurasplit` exited 0.
- `go test -count=1 -tags with_gvisor,with_wireguard ./...` passed in every package. `-race` could not run because CGO is off.
- `go list -deps` with the release tags found the import paths to the vulnerable packages (§5).

I did not run the ACL tests (`-tags acltests`): they need elevation and set
off AV heuristics on this machine. I edited no code. I ran nothing elevated
and touched no services, firewall rules or routes.

Severity reflects this app's threat model. A standard local user (or
malware running as that user) is the attacker; the elevated administrator
and SYSTEM are trusted. I found **no Critical or High issue**: I found no
path that lets a standard user take control of the LocalSystem service,
replace its binary or read the private key.

## 1. Ranked summary

| ID | Severity | Title |
|---|---|---|
| S-1 | Medium | Unpatched dependencies, some reachable: Go 1.26.5 stdlib (`net/textproto` via HTTP sniffing), x/net, grpc, x/crypto, brotli, klauspost/compress |
| S-2 | Low (uncertain → Medium) | `protectQuarantine` re-opens the quarantine **by path** after the move and re-owns/re-ACLs it with SeRestore/SeTakeOwnership enabled; an attacker-placed object there gets its descriptor rewritten |
| S-3 | Low | `uninstall` lists attacker-plantable `AuraSplitTR.quarantine-*` paths as ours and tells the admin to delete them by hand |
| S-4 | Low | A read-exposed `profile.json` (DACL lets non-admins *read*) is silently "trusted", its ACL is reset and the possibly leaked key stays in use |
| S-5 | Low | Pre-install / re-install DoS: a junction or file at `%ProgramData%\AuraSplitTR` makes setup and the service fail permanently (no quarantine for that case) |
| S-6 | Low | Uninstall reports success even if the service did not stop; the data dir is then deleted only partly |
| S-7 | Low | The engine's `OnState` callback does synchronous disk I/O and takes the log-file mutex, which goes against the "non-blocking logging" design |
| S-8 | Low | Setup "rollback" restarts the old service with the **new** binary (the old binary is gone), and the message says otherwise |
| S-9 | Informational | The key lives in immutable Go strings and in config buffers; zeroing is cosmetic; crash leftovers (`.profile.json.*.tmp`) last until the next sweep |
| S-10 | Informational | The service runs as full LocalSystem with no service SID, privilege trimming or explicit service DACL |
| S-11 | Informational | Event-log and state details are not scrubbed of the endpoint and user paths, and sing-box/wireguard-go log lines are not passed through `redact()` |
| S-12 | Informational | The UAC relaunch elevates whatever file is at `os.Executable()` in a user-writable folder (needs consent; no boundary crossed) |

## 2. Findings

### S-1 — Unpatched dependencies (Medium)

- **Component:** `go.mod`. Current versions: Go 1.26.5, `golang.org/x/net v0.57.0` (line 169), `golang.org/x/crypto v0.54.0` (166), `google.golang.org/grpc v1.79.1` (179), `github.com/andybalholm/brotli v1.1.0` (18), `github.com/klauspost/compress v1.19.1` (63). The baseline lists the fixed versions as Go 1.26.11, x/net v0.60.0, x/crypto v0.56.0, grpc v1.83.1, brotli v1.2.7 and klauspost v1.20.2. **None has been applied yet.**
- **Root cause:** sing-box's `include` package registers every protocol, so govulncheck's call graph (which is interface-conservative) marks nearly everything as reachable through `box.Start`.
- **Reachability with the configuration this app generates** (typed structs in `internal/engine/config.go`: TUN inbound, direct outbound, WireGuard endpoint, `local`/`udp` DNS, no `services`, no `experimental`):

| Package / vuln | Who imports it (`go list -deps`) | Reachable at runtime? |
|---|---|---|
| `net/textproto` GO-2026-6608 (MIME header memory-limit bypass), plus other `net/http` request parsing | `sing/protocol/http.ReadRequest` is `//go:linkname`d to `net/http.readRequest` and called by `sing-box/common/sniff/http.go:17` | **Yes.** The first route rule `{Action:"sniff"}` (`config.go:305`) has no conditions, so every TCP flow from **any local process, any user** is sniffed by the LocalSystem service. Input is capped at one `buf.NewPacket()` (64 KiB, `route/route.go:767`), so the amplification is bounded. Impact is DoS or a crash of the service, which means a fail-open window until the SCM restarts it 5 s later. |
| `crypto/tls` server-side ClientHello parsing | `common/sniff/tls.go:18` runs `tls.Server(...).HandshakeContext` on local traffic | Parsing is reachable. GO-2026-6607 (ECH outer extensions) needs server ECH keys, and none are configured. GO-2026-6090 (post-handshake) is never reached because the handshake is aborted. **Probably not exploitable; not proven.** |
| `crypto/tls`/`crypto/x509` client (GO-2026-6809, 6090, 6607) | `provider.RegisterWARP` (setup only, to `api.cloudflareclient.com`) | Reachable during setup only. On Windows, `x509.Verify` with nil roots uses the platform verifier, so whether the distrust fix even applies there is **uncertain**. Low. |
| `net/http` **server** and HTTP/2 server bugs (6859, 6613, 6612, 6611, 6603, 6609, 6617, 6089) | sing-box HTTP/mixed inbounds, clash/v2ray APIs, `debug_http.go` | **No.** No HTTP inbound, API service or `experimental.debug.listen` is configured. `debug_http.go` uses chi, not `DefaultServeMux`. |
| `google.golang.org/grpc` (6348, 6061, 4762) | `sing-box/service/api` → `sing-box/daemon` → grpc (registered by `include.ServiceRegistry`) | **No.** It is only instantiated for a `services:[{type:"api"}]` entry, and we never emit `services`. |
| `html/template` (6600, 6599, 6091) | `golang.org/x/net/trace` (a grpc dependency; its init registers `/debug/requests` on `http.DefaultServeMux`) and `net/http/pprof` in `debug_http.go` | **No.** Nothing serves `DefaultServeMux`, and the debug listener is not configured. |
| `x/crypto/ssh` (6355, 6354) | `sing-box/protocol/ssh` (SSH outbound) | **No.** No SSH outbound. |
| `brotli` GO-2026-6888, `klauspost/compress` GO-2026-6865 | `github.com/metacubex/utls` (TLS certificate compression for uTLS outbounds) | **No.** No uTLS/TLS outbound. |
| `net/url` 6218, `golang.org/x/net/idna` 5026 | WARP client request | Setup only, with a fixed URL. Negligible. |

- **Exploitability:** S-1's reachable part needs only a standard local user. A browser cannot send the oversized raw headers, so a local program is needed.
- **Impact:** DoS of the tunnel service. No sign of code execution.
- **Remediation:** build with Go ≥ 1.26.11 (add a `toolchain go1.26.11` line or bump the `go` directive) and `go get golang.org/x/net@v0.60.0 golang.org/x/crypto@v0.56.0 google.golang.org/grpc@v1.83.1 github.com/andybalholm/brotli@v1.2.7 github.com/klauspost/compress@v1.20.2`. Then rerun govulncheck and the engine tests. Also consider narrowing sniffing to what routing needs (`sniff` with `sniffer: ["tls","http","quic","dns"]` is already the default set; restricting it to flows not already matched by process is optional). Upgrading is the real fix.
- **Evidence:** `docs/audits/govulncheck_baseline_2026-11-21.txt`; `go list -deps -f '{{.ImportPath}}: {{.Imports}}'` (importers listed above); sing-box sources `include/registry.go`, `common/sniff/{http,tls}.go`, `route/route.go:767`, `debug_http.go`; sing `protocol/http/link.go`.

### S-2 — Quarantine descriptor applied by path after the move (Low; Medium if hard links to unwritable files can be created)

- **Component:** `internal/paths/secure_windows.go:428-447` (`replaceUntrustedDir`) and `:452-469` (`protectQuarantine`).
- **Root cause:** an untrusted directory (for example `%ProgramData%\AuraSplitTR` pre-created by a standard user) is moved to `AuraSplitTR.quarantine-<ts>-<rand>`. `protectQuarantine` then *re-opens that name* with `openNoFollow` and calls `applySD`, which sets owner BA and a protected DACL. If that fails, it retries with **SeRestorePrivilege + SeTakeOwnershipPrivilege** enabled. Nothing checks that the object it opened is the directory that was moved: there is no file-key comparison and no directory-attribute check.
- **Exploitability:** the attacker owns the moved directory, so they can grant themselves DELETE and rename it away. `%ProgramData%` gives Users `WD/AD` (add file / add subdirectory), so the attacker can then put another object at the quarantine name before `protectQuarantine` runs. They learn the name from directory-change notifications on `%ProgramData%`, which they can list. The window is between `moveFile` and `protectQuarantine` (a `CreateDirectory` sits in between), so a tight race.
  - Junction or symlink: harmless, because `FILE_FLAG_OPEN_REPARSE_POINT` changes the link object only.
  - **Hard link to a file the attacker cannot write:** `applySD` would rewrite that file's owner and DACL to `O:BA ... SY/BA only`. Restore privilege bypasses the DACL, so this works even on TrustedInstaller-owned system files. Whether a standard user can still create such a hard link depends on the Windows hard-link mitigation on this build; **I did not verify this**.
- **Impact:** ACL tampering (integrity/DoS) on an object the attacker chooses: Users lose read access, TrustedInstaller loses ownership. It does not give the attacker access, because the new DACL is admin-only.
- **Remediation:** keep the object by handle. Open the untrusted directory once with `DELETE|READ_CONTROL|WRITE_DAC|WRITE_OWNER`, plus `SYNCHRONIZE` and `FILE_FLAG_BACKUP_SEMANTICS|OPEN_REPARSE_POINT`, under the privileges if needed. Rename it with `SetFileInformationByHandle(FileRenameInfo)` and apply the descriptor **on that same handle**. At minimum, after re-opening, require `FILE_ATTRIBUTE_DIRECTORY`, no reparse attribute, and the same `keyOf` as the directory inspected in `adoptDir`.
- **Evidence:** code reading of `adoptDir` → `replaceUntrustedDir` → `protectQuarantine` → `withPrivileges`. Default `%ProgramData%` ACL semantics (Users: add file / add subdirectory).

### S-3 — Uninstall advises deleting attacker-plantable "quarantine" paths (Low)

- **Component:** `cmd/aurasplit/commands.go:186-194` (`quarantineDirs`) and `:170-177`.
- **Root cause:** `filepath.Glob(DataDir()+".quarantine-*")` lists every matching name in `%ProgramData%`, a folder where any user can create entries. Nothing checks owner, ACL or reparse attribute. The admin is then told these "may contain an old profile; delete them manually".
- **Exploitability:** a standard user creates `C:\ProgramData\AuraSplitTR.quarantine-x` as a junction to a valuable directory. An admin who removes it with PowerShell 5.1 `Remove-Item -Recurse -Force` (which follows junctions in 5.1) deletes the target's contents. This needs the admin's cooperation (social engineering), so the severity is Low.
- **Remediation:** list only entries that are real directories (not reparse points) owned by SYSTEM/Administrators with a trusted DACL, using the same `objectTrusted` as the sweep. Better still, offer to delete them from the tool with a no-follow delete (`os.RemoveAll` in Go 1.26 is handle-relative and safe). Print the junction warning for anything else.
- **Evidence:** code reading. Junction behaviour of PS 5.1 `Remove-Item` is known platform behaviour; I did not reproduce it here.

### S-4 — Read-exposed secret silently adopted (Low)

- **Component:** `secure_windows.go:308-330` (`daclTrusted` only rejects write-type rights) and `:618-619` (trusted → `resetSecurity` in place).
- **Root cause:** for `kindSecret` (`profile.json`), an ACE that lets Users/Everyone **read** the file counts as "trusted". The ACL is reset and the same private key is used from then on. Anyone who read the file, or still holds a read handle, keeps the key.
- **Exploitability:** needs an earlier misconfiguration, a restore from backup, or an older tool version that wrote the file with a weaker ACL. A standard user cannot cause it.
- **Remediation:** for `kindSecret`, also treat `FILE_READ_DATA|GENERIC_READ|GENERIC_ALL` granted to an untrusted SID as untrusted, or at least as "exposed". Quarantine the file and tell the user to run `setup` again; for WARP, register a new key.
- **Evidence:** code reading of `writeMask` (`:43-46`) and `handleOnce`.

### S-5 — Pre-install DoS by junction or file (Low)

- **Component:** `secure_windows.go:394-401` (`checkDirInfo`) and `:357-370` (`adoptDir`).
- **Root cause:** an untrusted *directory* is quarantined, but a reparse point or a non-directory at the data path makes `adoptDir` fail with "delete it and retry". This happens on every setup attempt and every service (re)start (every 10 s).
- **Exploitability:** a standard user can create `C:\ProgramData\AuraSplitTR` before the first install or after an uninstall. Once the directory is installed and admin-owned, users cannot replace it, since they lack DELETE_CHILD on `%ProgramData%`.
- **Impact:** setup is blocked until an admin intervenes; there is no confidentiality or integrity impact.
- **Remediation:** move a reparse point or file at that name aside with `MoveFileEx`, which renames the link itself, into a quarantine name, the same way as an untrusted directory. Then recreate the directory. Keep failing closed on errors.
- **Evidence:** code reading.

### S-6 — Uninstall continues when the service has not stopped (Low)

- **Component:** `commands.go:131-136`, `service_windows.go:160-161`.
- **Root cause:** both `service.Stop()` and the `stopService` inside `Uninstall` ignore errors, including the 20 s timeout. `DeleteService` only marks the service for deletion; a running service keeps running. The user is told "Hizmet kaldırıldı" ("service removed"). `removeAppDir(DataDir())` then fails partway on `service.log`, which the service holds open with share-read only, after it has already deleted `profile.json`.
- **Impact:** the tunnel keeps running after the reported uninstall, and the cleanup is inconsistent. No privilege impact.
- **Remediation:** after Stop, query until `Stopped` (or the PID is gone) and abort the uninstall with a clear message if it is still running. Report `ERROR_SERVICE_MARKED_FOR_DELETE` as "removed after reboot or after stop".
- **Evidence:** code reading.

### S-7 — Synchronous disk I/O and lock in the engine's state callback (Low)

- **Component:** `cmd/aurasplit/state_windows.go:88-124` (`set` → `flushLocked` → `logDegraded()`, `WriteSecureFileInDir`, `logf` direct to `logw`); `engine.go:261-265, 273-332` (`report` is called inline).
- **Root cause:** sing-box output goes through the non-blocking pump, but `OnState` runs synchronously on the engine goroutine. It writes and fsyncs a file, and it takes `logfile.Writer.mu` (through `Degraded()` and `logf`). That mutex is held by the pump writer during a stalled disk write (`logfile.go:157-190`).
- **Impact:** on a stalled disk, state transitions and shutdown wait for the disk. I checked the lock order (stateWriter.mu → logfile.mu, never the reverse), so **this is not a deadlock**, and every `report` call comes *after* the corresponding start or close. It therefore does not widen the fail-open gap; it only delays the retry loop and stop. ARCHITECTURE.md's claim that engine messages use "the same non-blocking path" is accurate for `logf` but not for `OnState`.
- **Remediation:** have `stateWriter.set` update memory and signal a dedicated writer goroutine (coalescing). Route its log lines through the pump, or make `Degraded()` an atomic flag.
- **Evidence:** code reading of all three files; lock-order review.

### S-8 — Rollback does not restore the old binary (Low, correctness)

- **Component:** `cmd/aurasplit/setup.go:140-149, 151-178`.
- **Root cause:** `installExe` has already replaced `aurasplit.exe` (`MoveFileEx` REPLACE_EXISTING) when `service.Install` or the profile commit fails. `rollback()` then starts the service, which is now the *new* binary with the old profile, and prints "önceki hizmet … yeniden başlatıldı" ("the previous service was restarted").
- **Impact:** an untested binary/profile combination runs, and the message misleads. No security boundary is involved.
- **Remediation:** before replacing, keep the previous exe (rename it to a staging name in the install directory). On failure, move it back, or say plainly that the new binary is in place.
- **Evidence:** code reading.

### S-9 — Secret material lifetime (Informational)

- `profile.WireGuard.PrivateKey`/`PresharedKey` are Go `string`s, and copies exist in `profile.Marshal` output, the sing-box JSON (`engine.buildConfig`), `option.Options` and the hex IPC string (`sing-box/transport/wireguard/endpoint.go:53-54`). Zeroing `data` in `setup.go:116-118` and `:310-312` does not remove these copies. A memory dump of the LocalSystem service or the elevated setup needs admin rights anyway.
- If setup is killed (console closed) between `StageSecureFile` (`setup.go:115`) and the commit, the deferred `os.Remove` does not run. `.profile.json.<hex>.tmp`, which holds the key under the SY/BA ACL, remains until a sweep older than 10 minutes deletes it (`secure_windows.go:611-615`). Sweeps run only at setup or service start, and the delete is a plain unlink.
- Quarantine directories keep old profiles indefinitely, by design. Uninstall lists them but does not delete them (S-3).
- **Recommendation:** document this. Optionally keep the key as `[]byte` and drop references after `box.New`. Have `uninstall` offer to delete our own trusted quarantine directories and stale `.tmp` files.

### S-10 — Service hardening (Informational)

`service.Install` (`service_windows.go:75-138`) registers a full-privilege LocalSystem service. It sets no `SERVICE_SID_TYPE_UNRESTRICTED`, calls no `SetServiceRequiredPrivileges`, and leaves the SCM default DACL in place. The SCM default DACL is acceptable: interactive users can query and send user-defined controls, which `Execute` ignores. Because the service parses traffic from every local user (sniff, DNS hijack), trimming privileges to what wintun and routing need (for example dropping SeDebug, SeTakeOwnership, SeBackup and SeRestore after startup) would limit the damage from any sing-box bug. `paths.withPrivileges` temporarily enables Restore/TakeOwnership process-wide at startup; that is acceptable, but note it.

### S-11 — Unscrubbed diagnostics (Informational)

- `reportRunError` (`service_windows.go:361-371`) writes the raw error to the **Application event log, which interactive users can read**. The error is redacted for keys but not passed through `scrubDetail`, so it can contain the endpoint host and any user path. `state_windows.go` scrubs only the state detail.
- Lines from sing-box and wireguard-go reach `service.log` through the pump without `redact()` (`logpump.go:470-493`). Today the only key-bearing error is the `IpcSet` failure, which embeds the full hex IPC config including `private_key=<hex>` (`sing-box/transport/wireguard/endpoint.go:255`). It is **returned** from `box.Start` and therefore redacted by `instance.Start` (`engine.go:119-121`), which handles hex. wireguard-go's own `device.log.Errorf` (`device/uapi.go:146`) logs only the short parse error. Safe today, but it depends on upstream wording.
- **Recommendation:** apply `scrubDetail` to the event-log text, and pass pump lines through a cheap `redact` (the secret forms are known).

### S-12 — UAC relaunch target (Informational)

`relaunchElevated` (`elevate_windows.go:16-43`) ShellExecutes `runas` on the path from `os.Executable()`, usually in Downloads. Malware running as the same user could swap that file between launch and consent. The swap gains nothing the malware could not get by showing its own UAC prompt, and the prompt shows the swapped file's publisher. The elevated process pins its own image (`selfimage_windows.go`) and copies exactly what is running. **Recommendation:** Authenticode-sign releases (already in SECURITY.md) so the UAC prompt identifies the publisher.

## 3. Checked and OK

- **Directory trust (`objectTrusted`/`daclTrusted`):** an owner other than SYSTEM, BA or TrustedInstaller is rejected. A NULL or missing DACL is rejected. Object and callback ACE types are rejected. Inherit-only ACEs are counted. `writeMask` covers add-file/add-subdir (WD/AD), DELETE_CHILD, WRITE_DAC/OWNER and the GENERIC bits. Inspection errors fail closed without changing anything (`:353-370`, `:595-601`).
- **Ancestor check (`checkAncestors`)** uses `GetFileAttributes`, which reports the link itself, on every parent. The bases come from `KnownFolderPath`, not environment variables (`base_windows.go`).
- **Adopt vs. act:** in `adoptDir`, the second open is compared to the first by `keyOf` (`:378-381`). `resetSecurity` and `replaceWithCopy` compare `keyOf` on their own handles (`:673-675`, `:702-704`). In a trusted directory only SY/BA can create or rename entries; users lack DELETE_CHILD on `%ProgramData%`/`%ProgramFiles%` and the directory DACL is protected. So the remaining path-based moves (`quarantine`, stale temp `os.Remove`, `ReplaceFile`) act only on admin-controlled names.
- **Sharing semantics:** the sweep opens existing files with only `READ_CONTROL|FILE_READ_ATTRIBUTES` (or WRITE_DAC/OWNER), which skips the sharing check. A concurrent service with `service.log` open (share-read) or a `createNew` temp file (share 0) therefore does not make setup fail.
- **Untrusted log replacement:** a new file is created with `CREATE_NEW` and its descriptor applied at creation and again afterwards; the copy is capped at 8 MiB (`maxCopiedLog`); `MoveFileEx` replace means old handles keep the unlinked object. Untrusted profile, state and exe are never reused.
- **`OpenSecureAppend`:** `OPEN_ALWAYS` with the secure SD, `OPEN_REPARSE_POINT`, then it requires a regular file with link count 1 and a trusted owner and DACL, otherwise sweep and reopen. The handle shares read only.
- **Log size cap and rotation (`logfile`):** the cap is hard; rotation failure turns into counted drops with a 30 s retry; rotation is path-based in the trusted directory; `Lstat` does not follow links; user-path scrubbing covers dependency lines.
- **Log pump:** memory is bounded (1024 lines × ≤ 8 KiB + 1 ≈ 8 MiB). Long lines are split through `bufio.ErrBufferFull`. `offer` never blocks, so sing-box never blocks on the sink. Sink errors are counted. Close is bounded by 2 s. There is no lock cycle (pump.mu is only held around map and pipe bookkeeping). **There is no pipe or goroutine leak across retries:** sing-box opens the log "file" in `defaultFactory.Start` and closes it in `Close` (`sing-box/log/observable.go:76-110`, `box.go:539-544`), so prepared-but-unstarted boxes never call `Pipe()`.
- **Retry with `prepareBox`:** a failed `Start` closes the instance; a failed `prepareBox` leaves `next=nil`; cancellation paths close the fallback. All errors pass through `redact` (base64 plus lower- and upper-case hex of the private key and PSK), including the `IpcSet` error that contains the IPC config.
- **Config injection (profile → sing-box JSON):** the config is built from typed structs with `encoding/json`, so no string concatenation is involved. Parsing uses sing-box's strict option parser. `AllowedIPs` is fixed. `ExtraProcessNames` is validated. Addresses and DNS are parsed with `netip`. No `services`, `experimental`, file outputs or rule-sets are emitted, so the API, debug, gRPC and HTTP servers stay unreachable. `profile.json` itself is writable only by admins.
- **`.conf` parser (`provider/wgconf.go`):** input is capped at 64 KiB (and read with the same cap in `setup.go:328-342`). Exactly one interface and one peer are accepted. Keys must be base64 of 32 bytes. The endpoint must be host:port without separators or whitespace. MTU must be 1280–1500. Errors never echo input. `AllowedIPs` is ignored.
- **WARP:** HTTPS only, default TLS verification, redirects refused, response capped at 1 MiB, token not kept, the key is generated locally and only the public key is sent.
- **No DLL planting:** no non-system `NewLazyDLL` is used in the dependency set. `golang.zx2c4.com/wintun` (which loads with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`) is imported only by `sagernet/wireguard-go/tun`, whose `CreateTUN` the WireGuard system/stack devices do not use. sing-tun loads its embedded wintun through memmod, resolving imports from System32 only.
- **Service binary integrity:** the install directory is created or adopted with `O:BA`, a protected DACL and BU read/execute only. The exe is staged with `CREATE_NEW` and moved into place. The source is the pinned `selfImage` handle, opened share-read only and checked against the mapped image by file ID (`selfimage_windows.go:29-61`). "Already installed" is decided by file identity, never by path text, and links or multiple names never count as the same file. `BinaryPathName` is quoted and read back to verify it (`service_windows.go:107-121`), and the account is checked to be LocalSystem.
- **Tombstone uninstall:** tombstone names have 48 random bits and live in the protected `%ProgramFiles%`. Only the tombstone exe and directory are marked `MOVEFILE_DELAY_UNTIL_REBOOT`, never the stable paths. `os.RemoveAll` on Go 1.26 Windows is handle-relative and does not follow links (`src/os/removeall_at.go` build tag includes windows; `internal/syscall/windows/at_windows.go` uses `FILE_OPEN_REPARSE_POINT`). `removeAppDir` refuses names other than `AuraSplitTR`.
- **State file / `stateValid`:** the file is admin-only. It is believed only when the SCM PID matches, the creation time is within ±1 s and the heartbeat is under 90 s old. Detail text is scrubbed and truncated.
- **SCM control surface:** only Stop and Shutdown are handled; user-defined controls are ignored.

## 4. Not verified or out of scope

- I did not run the ACL integration tests, because they need elevation and trigger AV.
- I did not test whether this Windows build allows hard links to unwritable files (S-2). I did not test the S-1 textproto DoS in practice.
- WFP or persistent kill-switch design. The known fail-open windows are documented in SECURITY.md and not repeated here.
