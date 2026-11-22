# Phase 3 — Reliability & Testing audit (Agent C)

Date: 2026-11-21/22. Scope: test coverage, intermittent test failures, `-race`
feasibility, concurrency/shutdown review, new unelevated tests, admin test
design, AV-sensitive test gating. Only `*_test.go` files and the new test
helper package `internal/testutil` were changed. No production code was
edited. Nothing was run elevated, and no service, TUN, firewall or route was
touched.

Environment: Windows 11 Pro 10.0.26200, go1.26.5 windows/amd64, unelevated
shell, CGO_ENABLED=0, no C compiler on PATH. Security products from
SecurityCenter2: Kaspersky (two entries) and Windows Defender. Defender
`AMRunningMode: Not running`, `RealTimeProtectionEnabled: False`, so Kaspersky
is the active on-access scanner.

## 1. Coverage

Command: `go test -count=1 -cover -tags with_gvisor,with_wireguard ./...`

| Package | Before | After | Notes |
|---|---|---|---|
| cmd/aurasplit | 19.6% | 22.2% | setup, uninstall, cmdService and status printing are untested (no seams) |
| internal/engine | 79.2% | 85.2% | only real sing-box Start/Close paths are left (need TUN) |
| internal/logfile | 88.0% (FAIL, flaky) | 96.0% | |
| internal/paths | 53.4% | 6.4% default / 53.4% with `-tags acltests` | ACL tests are now gated (F-3) |
| internal/profile | 0.0% (no tests) | 0.0% | covered indirectly by the engine/provider tests; no direct Validate tests |
| internal/provider | 95.7% | 95.7% | |
| internal/service | 0.6% | 14.9% | Execute/supervise are now tested; SCM calls are not (no seam) |
| internal/testutil | — | 79.5% | new |

### Critical paths and their test status

| Path | Status |
|---|---|
| Setup rollback (`setup.go:140-186`: stop old service, then installExe, Install, ReplaceFile profile, rollback/Start) | **UNTESTED.** Calls `service.*` and `paths.*` directly, so it cannot be injected (seam S-1). |
| Setup preflight / installExe (`setup.go:356-399`) | UNTESTED (needs elevated EnsureSecureInstallDir). Only `sameFileAsImage` is tested. |
| Service lifecycle: Install, Start, Stop, Uninstall (`service_windows.go:75-239`) | UNTESTED (real SCM, admin). The design is in §6. |
| Service host: `handler.Execute`, `superviseLoop`, `safeRun` | **TESTED NOW** with a fake SCM channel pair: Stop/Shutdown/Interrogate, panic recovery, cancellation. A run failure before cancellation is still untested because it writes to the Event Log (S-3). |
| Directory adoption / sweep / quarantine (`secure_windows.go:350-736`) | TESTED unelevated by testPolicy (behind `acltests`). The production-policy and hard-link tests are elevated only and were SKIPPED here. |
| Uninstall: `removeInstallDirInUse` (tombstone), `removeAppDir` safety net | TESTED. `cmdUninstall` flow itself UNTESTED (interactive plus SCM). |
| Engine retry/fallback ordering | TESTED: first-attempt success, tunnel+fallback both fail leads to StateError, cancel while blocking, cancel during first attempt, prepared tunnel fails (fallback restarted), prepare failure keeps blocking, IP endpoint skips lookup, no goroutine leak. |
| Engine real box Start/Close (TUN) | UNTESTED (admin plus TUN). |
| State validity (`stateValid`) | TESTED (existing tests plus new boundary cases). |
| State writer / heartbeat | TESTED (failure logging, heartbeat stops on cancel, no write before the first state). |
| Log rotation / degraded mode / Close | TESTED (96%), including handle-leak assertions. |

## 2. Intermittent failures

### F-1 (Medium, test-side): `TempDir RemoveAll cleanup: unlinkat …: Dizin boş değil` is not a handle leak in our process

Observed in `logfile.TestRotation` and `cmd/aurasplit.TestSameFileAsImage`.

Baseline evidence. Command: `go test -count=20 -json` over all packages,
tallied by `count.ps1` (runs every test N times and counts PASS/FAIL/SKIP per
test).
- Run 1, `go test -count=1 -cover ./...`: TestRotation FAIL (`unlinkat …\TestRotation2044705732\001: Dizin boş değil`).
- Run 2, `-count=20 ./cmd/aurasplit/`: TestSameFileAsImage 1 FAIL. `-count=20 ./internal/logfile/`: TestRotation 1 FAIL.
- Run 3, `-count=20 ./...`: 1639 PASS, **1 FAIL** (TestSameFileAsImage), 60 SKIP (elevated-only).

Diagnostic: a temporary `zz_diag_test.go`, deleted after the analysis. It
repeated the TestRotation workload 200 times in a manual temp dir. After each
`w.Close()` it opened every remaining file with **share mode 0**, which fails
while *any* handle exists, in any process. It then called `os.RemoveAll`.
Results:

| Workload (200 iterations each) | RemoveAll failures |
|---|---|
| TestRotation body (write + rotate via Remove/Rename) | 28/200 and 66/200 (two runs) |
| write 3 files, no rename | 0/200 |
| create 3 empty files | 0/200 |
| write + one rename | 18/200 |
| write 2, remove 1, rename over it | 19/200 |

- Exclusive-open failures before RemoveAll: **0** in every iteration. No handle was open in our process or any other at that moment.
- After every failure the directory listing was **already empty**, and an immediate second `RemoveAll` **always succeeded** (retry 0).

Root cause: the failure depends on renaming a file, or on writing a PE file
(TestSameFileAsImage wrote a full copy of the test .exe into %TEMP%). Go
1.26's `os.RemoveAll` deletes each file with POSIX semantics and reports
success. The final `rmdir` still hits a delete-pending entry that a file-system
filter driver (the active on-access scanner, Kaspersky) briefly holds open
after it was notified about the rename or the new executable.
`testing.removeAll` (`$GOROOT/src/testing/testing_windows.go`
`isWindowsRetryable`) retries only `ERROR_ACCESS_DENIED` and
`ERROR_SHARING_VIOLATION`, not `ERROR_DIR_NOT_EMPTY`, so the test is marked
failed. The production code is not involved: `logfile.Writer.rotate` closes
`w.f` before moving it (`logfile.go:122-125`), and `Close` releases the last
handle (`logfile.go:201-210`). The new `AssertNoOpenHandles` checks confirm
this deterministically.

Fix (test-side, done):
- `internal/testutil/testutil.go`: `TempDir(t)` with a bounded retrying cleanup (5 s). A real leak keeps the directory busy past the bound, so it still fails the test.
- `internal/testutil/handles_windows.go`: `AssertNoOpenHandles(t, dir)` (exclusive open, 1 s tolerance for scanners). It has a self-test that proves it detects a leaked handle.
- logfile and cmd tests use `testutil.TempDir`. TestRotation and the new lifecycle tests assert no handle is left open.
- `TestSameFileAsImage` no longer writes a copy of the PE image. Identity is by volume serial and file index, so the content is irrelevant.

After the fix:
- `count.ps1 -N 20` over `./...`: **2060 PASS / 0 FAIL / 0 SKIP**, 103 tests.
- `-N 100 ./internal/logfile/`: 900/0/0.
- `-N 100 ./cmd/aurasplit/`: 1300/0/0.

### F-2 (Info): "Erişim engellendi" when starting `paths.test.exe`

This is not a leak. Kaspersky flagged `paths.test.exe` as
`VHO:Trojan.Win64.Convagent.gen` (heuristic) and blocked or quarantined it, so
`go test` could not execute it. The binary was the one that spawns
`cmd.exe /c mklink /J`, creates Everyone-writable DACLs and links
`SetSecurityInfo` / `AdjustTokenPrivileges`. This is addressed by F-3.

### F-3 (Low, test-side, done): ACL/junction/privilege tests gated behind `acltests`

The tests that touch the filesystem were moved from
`internal/paths/secure_windows_test.go` to
`internal/paths/secure_acl_windows_test.go` (`//go:build windows &&
acltests`): junctions, ACL'd files, quarantine, adoption, elevated tests and
the relative-path test that links `ensureDir`. The default file keeps only the
pure-logic `TestDACLTrust` and `TestClassify`.

Evidence, from `go tool nm` on `go test -c` output:

| binary | withPrivileges | AdjustTokenPrivileges | SetSecurityInfo | paths.ensureDir | os/exec syms |
|---|---|---|---|---|---|
| paths, default | 0 | 0 | 0 | 0 | 0 |
| paths, `-tags acltests` | 3 | 2 | 2 | 1 | 46 |
| cmd/aurasplit, default | 0 | 0 | 0 | — | 69 (stdlib, no mklink) |
| logfile, default | 0 | 0 | 2 (OpenSecureAppend linked via var) | — | 0 |

Run them with:
`go test -tags with_gvisor,with_wireguard,acltests ./internal/paths/`.
Result: 10 tests, 140 PASS / 0 FAIL / 60 SKIP over `-count=20` (3 elevated-only
tests skip). CI or release checks must pass `acltests`, from an elevated shell
for full coverage. Otherwise paths coverage drops to 6.4%.

## 3. `go test -race`

**Not feasible on this machine.**
- `go test -race …` gives `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1`.
- With `CGO_ENABLED=1` it gives `cgo: C compiler "gcc" not found: exec: "gcc": executable file not found in %PATH%`.

To enable it, install a mingw-w64 gcc (for example the WinLibs or MSYS2
ucrt64 toolchain), put it on PATH, set `CGO_ENABLED=1` only for the race run,
and run
`go test -race -count=5 -tags with_gvisor,with_wireguard ./internal/... ./cmd/...`.
Production builds can stay `CGO_ENABLED=0`. The new concurrency tests are
written to be race-detector meaningful: concurrent Writer writes, pump
use-after-close, the Execute/status channels and the goroutine-leak check.

## 4. Concurrency / shutdown / resource-cleanup review

| ID | Sev | Location | Finding |
|---|---|---|---|
| C-1 | Medium | `internal/service/service_windows.go:320-327` | On Stop/Shutdown, Execute waits at most `stopTimeout-2s` (18 s) for `done`, then returns. `svc.Run` returns, `cmdService` returns 0 and `os.Exit` runs (`main.go:83`). The run closure's defers (`commands.go:255` `logw.Close`, `:259` stopHeartbeat) and `engine.Run`'s `inst.Close()` never run, so sing-box/TUN is torn down only by process death, and queued log lines are lost. On timeout this exit is also reported as a clean stop (exit 0), so the SCM recovery actions do not fire and nothing is logged. Recommend: log a warning, report a non-zero exit, and keep sing-box Close bounded inside engine (Close with its own timeout). Relevant for WFP fail-closed: filters must not depend on the defers having run. |
| C-2 | Low | `cmd/aurasplit/commands.go:258-260` | The heartbeat goroutine is cancelled but not joined. A heartbeat in flight can write after `logw.Close()`. This is harmless today because Writer discards writes after Close (`logfile.go:162`) and the state writer has its own mutex. It can also write `tunnel-state.json` after `engine.Run` reported `stopped`, which only refreshes the same state. Recommend a WaitGroup join before returning. |
| C-3 | Low | `internal/service/service_windows.go:308-315` | `case err := <-done` is unreachable in practice: superviseLoop returns only after ctx is cancelled, and ctx is cancelled only in the Stop branch. Harmless. If kept, it should send a final StopPending/Stopped consistently. |
| C-4 | Info | `internal/engine/engine.go:271-281, 305-311` | ctx handling is correct. Cancellation during the block wait closes the fallback without waiting for the delay (tested). Cancellation while the first `startBox` is in progress is honoured once Start returns, but `box.Start` itself is not cancellable, so shutdown time is bounded only by sing-box. No double Close: `instance.Start` closes on failure and its runner is discarded (`engine.go:118-124, 201-203, 328`). |
| C-5 | Info | `internal/engine/logpump.go:166-199` | Close is idempotent, bounded by a single deadline, and closes the handed-out write ends. If the sink blocks forever, the writer goroutine is leaked for the process lifetime (by design, documented). `offer` after Close never blocks (tested). No goroutine leak across 5 Run cycles with pipes (tested). |
| C-6 | Info | `internal/paths/secure_windows.go:696,730` | `replaceWithCopy` closes `src` twice (explicit plus defer). The second `os.File.Close` returns ErrClosed and is ignored, so there is no handle bug. Every other CreateFile in paths is closed on all paths. No leak was found in production code. |
| C-7 | Info | `internal/paths/secure_windows.go:898-901` | The service log is opened with `FILE_SHARE_READ` only (no delete or write share). That is intentional: rotation closes it first. While the service runs, any external rename or delete of `service.log` fails, which is the documented degraded-mode trigger. |
| C-8 | Low | `internal/service/service_windows.go:345` and `engine.go:310` | `time.After` in loops. Since Go 1.23 these timers are collected, so this is not a leak. |

## 5. New tests (all unelevated)

| File | Tests |
|---|---|
| `internal/testutil/testutil.go`, `handles_windows.go`, `handles_other.go`, `testutil_test.go` | `TempDir` with retrying cleanup; `AssertNoOpenHandles`; self-tests |
| `internal/logfile/lifecycle_test.go` | Close idempotent/discard, 8-goroutine writes respect cap with no torn lines, full plus unrotatable log at Open starts degraded holding no handle, reopen failure after rotation degrades |
| `internal/logfile/logfile_test.go` | uses testutil; TestRotation asserts no open handles |
| `internal/engine/fallback_test.go` | 7 Run ordering/fallback/cancel tests, goroutine-leak test, pump use-after-close |
| `internal/service/handler_windows_test.go` | fake-SCM Execute Stop/Shutdown/Interrogate, safeRun panic, superviseLoop cancel |
| `cmd/aurasplit/lifecycle_test.go` | heartbeat stops on cancel, no write before the first state, stateValid boundaries, removeAppDir safety net, isNotInstalled, splitArgs |
| `cmd/aurasplit/state_test.go` | TestSameFileAsImage without a PE copy; testutil TempDir |
| `internal/paths/secure_acl_windows_test.go` | moved, gated tests (F-3) |

### Seams still needed in production code (for the implementer; not done here)

- **S-1 setup rollback.** `runSetup` calls `service.Status/Stop/Install/Start`, `installExe`, `paths.ReplaceFile/StageSecureFile` directly. Introduce a small interface, for example `type serviceControl interface{ Status() (string, error); Stop() error; Install(string) error; Start() error }`, plus package vars for `installExe` and `replaceFile`, and split `runSetup` into an interactive part and a non-interactive `applySetup(pre, data)`. Then test the following, asserting that the old profile is never touched before ReplaceFile, that the staged temp file is removed on failure, and the Start/rollback ordering:
  - install fails, so the old service is restarted
  - Install fails, so it is restarted again
  - ReplaceFile fails, so the old profile is kept
  - Start fails after commit, so there is no rollback
- **S-2 SCM.** Wrap `mgr.Mgr`/`mgr.Service` in an interface (`OpenService`, `CreateService`, `UpdateConfig`, `Config`, `Control`, `Query`, `Delete`, `SetRecoveryActions…`) so these can be faked:
  - Install idempotence and command-line verification
  - the stopService timeout
  - the "already running" and "marked for delete" cases
- **S-3 event log.** `reportRunError` (`service_windows.go:361`) is called directly. Make it a package var so superviseLoop retry-after-failure can be tested without writing to the Application log. `stopTimeout` and `retryDelay` should also be overridable vars so the C-1 timeout path can be tested in under a second.
- **S-4 cmdService closure.** Extract the run func (`commands.go:242-269`) into `serviceRun(ctx, deps)` with injectable `ensureSecureDir`, `logOpen`, `profileLoad`, `engineRun` and state-writer factory. Then test log open failure, profile load failure, the state sequence, and the C-2 heartbeat join.
- **S-5 WFP (upcoming).** The new `internal/wfp` package should expose an interface (`Install(filters) error`, `Remove() error`) with a fake, so that engine/service tests can assert the ordering "filters before tunnel close" and "filters removed only on clean uninstall".

## 6. Admin-only service lifecycle tests (design only, not executed)

Put them in a separate package `test/acceptance` with `//go:build windows &&
acceptance`. They skip unless the process is elevated and
`AURASPLIT_ACCEPTANCE=1` is set. Run them only on a disposable VM or Windows
Sandbox snapshot, never on a workstation. Use a test service name such as
`AuraSplitTR-Test` and test paths (this needs a seam for
`paths.ServiceName`/DataDir/InstallDir, or a build-tag override).

Harness:
1. Build `aurasplit.exe` with the release tags into a temp dir.
2. Snapshot the starting state: `sc qc`, routes (`Get-NetRoute`), adapters, WFP filters (`netsh wfp show filters` once WFP lands), and the ACLs of ProgramData and Program Files.
3. Run each case below.
4. Diff the state against the snapshot at the end. The teardown always runs `uninstall` plus a forced cleanup and fails the test if anything remains (service, adapter, route, WFP filter, directories, quarantine dirs).

Cases:
- **L-1 install.** Run `setup` non-interactively; this needs a scripted-input seam or a `--profile <conf>` flag. Assert:
  - the service exists with `"…\aurasplit.exe" service`, LocalSystem, auto start and recovery actions
  - the data dir DACL is SYSTEM+BA only and the install dir adds BU:RX
  - `tunnel-state.json` reaches tunnel-started or blocking within 30 s
- **L-2 reinstall over running.** Setup runs again while the service is running. Assert the old process stops, the exe is replaced (new file ID), the profile is replaced atomically, and the service runs again.
- **L-3 rollback.** Inject a failure (a locked install exe opened without FILE_SHARE_DELETE, or an invalid profile write). Assert the old service is restarted with the old profile and that no staged `.profile.json.*.tmp` remains.
- **L-4 stop/start/restart.** Assert the SCM state transitions, that `status` output uses stateValid, and that stop completes in under 20 s. Kill -9 the service process, then assert the SCM restarts it within 5 s plus margin (recovery) and that the stale state is reported unknown.
- **L-5 stop timeout (C-1).** Use a test build whose engine blocks in Close. Assert the exit is non-zero or a warning is logged, and that TUN/WFP state is left fail-safe.
- **L-6 boot without network.** Disable the NIC, then start. Assert StateBlocking, Discord blocked (probe connection to a Discord IP is rejected) and other traffic unaffected. Re-enable the NIC and assert tunnel-started within `maxRetryDelay` plus margin.
- **L-7 adoption.** Pre-create the ProgramData dir with an Everyone-writable ACL and a planted profile. Assert quarantine plus a fresh dir, and that the service refuses to start without setup.
- **L-8 uninstall.** Run from the installed copy and from an external copy. Assert the service is gone, the tombstone is scheduled (`PendingFileRenameOperations` contains only tombstone paths), the data dir is removed on yes, and no adapters, routes or WFP filters remain.
- **L-9 log rotation under load.** Run `--debug` traffic. Assert the service.log size cap holds and that degraded mode appears when `service.log.1` is held open.

Report the harness as JUnit through `go test -json` plus `gotestsum` and
attach the before/after state diffs.

## 7. Commands and results (summary)

| Command | Result |
|---|---|
| `go test -count=1 -cover -tags with_gvisor,with_wireguard ./...` (before) | FAIL: logfile TestRotation (F-1) |
| `count.ps1 -N 20` (before) | 1639 PASS / 1 FAIL / 60 SKIP |
| `go test -race …` | build error: cgo disabled / gcc not found |
| `go vet -tags with_gvisor,with_wireguard ./...` and `…,acltests ./...` | clean |
| `gofmt -l ./internal ./cmd` | clean |
| `go test -count=1 -cover -tags with_gvisor,with_wireguard ./...` (after) | all ok |
| `count.ps1 -N 20` (after) | **2060 PASS / 0 FAIL / 0 SKIP** (103 tests) |
| `count.ps1 -N 100 -Pkgs ./internal/logfile/` | 900 / 0 / 0 |
| `count.ps1 -N 100 -Pkgs ./cmd/aurasplit/` | 1300 / 0 / 0 |
| `go test -count=50 ./internal/service/` | ok |
| `count.ps1 -N 20 -Tags with_gvisor,with_wireguard,acltests -Pkgs ./internal/paths/` | 140 PASS / 0 FAIL / 60 SKIP (elevated-only) |

`count.ps1` runs `go test -count=N -json -tags <tags> <pkgs>` and tallies the
pass/fail/skip actions per test. It lived in the session scratchpad and is not
part of the repository.

Not verified:
- the elevated tests (TestWriteSecureFile, TestEnsureSecureDirSweepsChildren, TestOpenSecureAppend)
- the real SCM and TUN paths
- `-race`
- whether the new default test binaries still trigger Kaspersky heuristics (no detection was observed during this session's runs)
