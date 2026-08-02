# Bastion architecture (v15.9.4)

## Purpose

Bastion Hardening Framework is a **menu-driven**, **state-aware** Windows workstation hardener. It runs elevated, records preferences and optional Apply undo data under a local data directory, and never invents Apply history on first launch.

This document maps the **code layout** after the v15.9.x modular restructure (including script-scope module load, post-load command probe, self-elevating bat, and v15.9.4 launch hardening: whoami-SID admin check instead of `net session`, `tools-elevate-self.ps1`, Mark-of-the-Web Unblock + ExecutionPolicy Process Bypass). Product behavior is unchanged from the prior monolith unless noted in release notes.

## Design principles

| Principle | Practice |
|-----------|----------|
| Auditability | All product PowerShell is **plain text** under `src\`. Source is **never encrypted** (GPLv3 + peer review). |
| Single entry | Users **always** launch `Bastion-Hardening.bat` (UAC). Never double-click `Bastion-Hardening.ps1` alone under Restricted ExecutionPolicy. |
| Shared state | Modules are **dot-sourced** into the bootstrap runspace so `$script:` variables and functions are shared. |
| Fail closed | Startup **hard-fails** if `src\` modules or `src\MANIFEST.sha256` are missing or hashes mismatch. |
| Encrypt data, not code | DNS undo snapshots and RDP host prior use **DPAPI** (CurrentUser + fixed entropy). Preferences JSON is not secret but gets a tight ACL. |

## Runtime layout

```
bastion-hardening-v15.9.4\
  Bastion-Hardening.bat      # UAC launcher; whoami SID elev check (not net session); Unblock + Bypass; invoke &
  tools-elevate-self.ps1     # Product-root UAC helper (-File; avoids nested ) in cmd one-liners)
  Bastion-Hardening.ps1      # Thin bootstrap: early Process Bypass; integrity; script-scope .
  Bastion-Banner.utf8.txt
  LICENSE, NOTICE, README.md, SECURITY.md
  src\
    MANIFEST.sha256          # SHA256 of each module (paths relative to src\)
    Bastion.Init.ps1         # $script: catalogs, sections, providers, flags
    Bastion.Core.ps1         # UI, log, prompts, console
    Bastion.Config.ps1       # paths, config/undo, DPAPI, ACL, session store
    Bastion.Programs.ps1     # winget catalog install / uninstall helpers
    Bastion.Services.ps1     # high-risk / Xbox service helpers
    Bastion.Browsers.ps1     # Firefox / Chromium policies + ECH packs
    Bastion.Dns.ps1          # adapter DNS, DoH, snapshots, restore
    Bastion.Harden.ps1       # OneDrive, bloat, CFA, StrictHandle, registry, RDP host
    Bastion.Apply.ps1        # DryRun, SelfTest/Audit, Apply, QuickHarden, restore points
    Bastion.Recovery.ps1     # Recovery hubs (network, services, mitigations, ...)
    Bastion.Menus.ps1        # Main menu, section/program/DNS/browser/help/uninstall
  docs\                      # Handbook, data-directory, known issues, architecture
```

**Not shipped in the release zip:** `tools\` (pack/wiki scripts, optional monolith archive under `tools\archive\` for git history only).

## Load order

**Launcher (`Bastion-Hardening.bat`)** (preferred entry):

1. **Elevation check without `net session`.** Bastion can disable **LanmanServer** (Server service) under HighRiskServices. After that, `net session` fails even in an already-elevated admin console, so older bats kept re-UAC-looping and flash-closed. v15.9.4 uses **whoami** group SIDs (High Mandatory Level `S-1-16-12288`, with Administrators / `openfiles` fallback) instead.
2. **Re-UAC via `tools-elevate-self.ps1`** at product root (`powershell -File`), not a cmd one-liner with nested parentheses (those produced `. was unexpected at this time.` / exit 255).
3. In the elevated console: Process-scope ExecutionPolicy Bypass, recursive `Unblock-File` on the product tree (Mark-of-the-Web), then invoke `Bastion-Hardening.ps1` with the call operator (`&`).

Bootstrap (`Bastion-Hardening.ps1`) always:

1. Sets Process-scope ExecutionPolicy Bypass early (helps when someone still starts the `.ps1` with Bypass flags; double-click alone still fails under Restricted before code runs)
2. Sets `$script:BastionRoot = $PSScriptRoot`
3. `Test-BastionSourcesReady` then **dot-sources modules at script scope** (not inside a function):
   - Requires `src\` and every listed module file
   - `Test-BastionSourceIntegrity` against `src\MANIFEST.sha256` (**hard-fail** on missing/mismatch)
   - Dot-sources modules in order (must be `.` at script scope so functions survive after load; required for menus after import):

| Order | Module | Responsibility |
|------:|--------|----------------|
| 1 | `Bastion.Init.ps1` | `$script:Config` (version), section docs, program catalog, DNS providers, lists/flags |
| 2 | `Bastion.Core.ps1` | Logging, banners, menus UX, Read-*/Write-* helpers |
| 3 | `Bastion.Config.ps1` | Data-dir resolve/bind, config save/load, DPAPI, ACL, undo, session |
| 4 | `Bastion.Programs.ps1` | Winget preflight, catalog install, paths, uninstall |
| 5 | `Bastion.Services.ps1` | Service disable/enable and catalog rows |
| 6 | `Bastion.Browsers.ps1` | Per-browser policy modes and optional ECH |
| 7 | `Bastion.Dns.ps1` | Live DNS, DoH interface keys, snapshot apply/restore |
| 8 | `Bastion.Harden.ps1` | Hardening section helpers (OneDrive, bloat, CFA, StrictHandle, RDP host, ...) |
| 9 | `Bastion.Apply.ps1` | Dry Run, Audit, Apply, Quick Harden, restore points |
| 10 | `Bastion.Recovery.ps1` | Recovery menus and targeted undo helpers |
| 11 | `Bastion.Menus.ps1` | Interactive menus including `Show-MainMenu` |

4. Optional smoke: `-BastionSmokeLoadOnly` prints version and exits 0 after a successful import (requires elevation; friendly admin gate if not elevated).
5. Resolves/binds the data directory, `Ensure-BastionPaths`, `Initialize-BastionDataStore`, then `Show-MainMenu`.

## Integrity

- Developers regenerate hashes with:

  ```text
  pwsh -File tools/New-BastionSourceManifest.ps1
  ```

- `tools/pack-release.ps1` regenerates the MANIFEST before packing (unless `-SkipManifestRegen`).
- Format of each data line: `HASH  RelativeFileName` (hex SHA256, two spaces, path relative to `src\`).
- Intentional source edits require a regenerated MANIFEST or startup will refuse to run.

## Data security (threat model summary)

| Asset | Protection | Residual risk |
|-------|------------|---------------|
| Product source (`src\*.ps1`) | Plain text + SHA256 MANIFEST + GitHub | Compromised download without verifying release/hash; local admin can edit sources and MANIFEST together |
| DNS undo snapshot / RDP host prior | DPAPI CurrentUser + Bastion entropy string; ACL SYSTEM+Administrators on undo file | Same elevating user (or malware as that user) can decrypt; full account compromise wins |
| `Bastion-Config.json` (preferences, custom paths) | Not secret; **ACL SYSTEM+Administrators** on save to reduce casual local reads | Admin/same elevated identity can read; not a credential store |
| Session / browser-state JSON | Live detection snapshots; not secrets | Local readers if ACLs not applied |
| Browser enterprise policies | Written outside Bastion data dir when you use menu 6 | Standard Windows policy visibility |

**Out of scope for Bastion crypto:** protecting against a hostile Administrator on the same box, kernel malware, or offline disk theft without full-disk encryption (BitLocker is the right control there).

DPAPI entropy string and DoH interface flags (`DohFlags=17`) are intentional compatibility constants; do not change them casually or prior undo blobs / Settings Encrypted badges break.

## Smoke load (developers)

Elevated:

```text
powershell -NoProfile -ExecutionPolicy Bypass -File .\Bastion-Hardening.ps1 -BastionSmokeLoadOnly
```

Expected: `Bastion smoke load OK v15.9.4 (commands verified)` and exit 0. After load, commands such as `Show-MainMenu` must exist in the runspace (script-scope dot-source + explicit command probe).

## Version

Product-facing version is **15.9.4** (`$script:Config.ScriptVersion` in `Bastion.Init.ps1`, bootstrap header, README, SECURITY supported table, pack-release default). Prefer **15.9.4** if:

- After Apply, the bat flash-closed or looped UAC on an already-admin console (**Server / LanmanServer disabled** — fixed by whoami SID check), or
- Zip extracts fail with *running scripts is disabled* (Mark-of-the-Web / Restricted).

Always start with the `.bat`, never the `.ps1` alone.

## Related docs

- [DATA-DIRECTORY.md](DATA-DIRECTORY.md) - files Bastion creates at runtime
- [SECURITY.md](../SECURITY.md) - reporting and safe usage
- [BROWSER-POLICIES-AND-ECH.md](BROWSER-POLICIES-AND-ECH.md) - browser modes and ECH
- [KNOWN-ISSUES.md](KNOWN-ISSUES.md) - StrictHandle, Game Bar overlay, etc.
