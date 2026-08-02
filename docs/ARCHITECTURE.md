# Bastion architecture

## Purpose

Bastion Hardening Framework is a **menu-driven**, **state-aware** Windows workstation hardener. It runs elevated, records preferences and optional Apply undo data under a local data directory, and never invents Apply history on first launch.

This document maps the **code layout** after the v15.9.x modular restructure (script-scope module load, post-load command probe, self-elevating bat, Mark-of-the-Web / ExecutionPolicy launch hardening, LanmanServer-safe bat parse, forced black console theme, and color-coded Help docs). Product behavior remains guided, selective hardening; the restructure is about **how the source is organized for review and maintenance**, not a secret rewrite of the safety model.

## Why the source is modular

Through the v15.8.x releases, Bastion shipped mainly as a **single large PowerShell script** (monolith). That was convenient to package, but it made independent review expensive: DNS, Recovery, Apply, browsers, and menus all lived in one multi-thousand-line file.

The modular layout exists so that:

1. **Reviewers and end users** can open a named module that matches their concern instead of searching one giant script.  
2. **GPLv3 auditability** stays honest — every product module is **plain text**, never encrypted.  
3. **Maintainers** can change one domain (for example Recovery) with a smaller, reviewable diff.  
4. **Integrity** can be checked **per file** via `src\MANIFEST.sha256` (SHA256 hashes). A mismatch hard-fails startup.

**User launch path is unchanged in spirit:** download the official zip, keep the tree together, run **`Bastion-Hardening.bat` as administrator**.

Handbook-style overview for non-developers: [wiki Modular source](wiki/Modular-source.md) (also published on the GitHub Wiki).

## Design principles

| Principle | Practice |
|-----------|----------|
| Auditability | All product PowerShell is **plain text** under `src\`. Source is **never encrypted** (GPLv3 + peer review). |
| Single entry | Users **always** launch `Bastion-Hardening.bat` (UAC). Never double-click `Bastion-Hardening.ps1` alone under Restricted ExecutionPolicy. |
| Shared state | Modules are **dot-sourced** into the bootstrap runspace so `$script:` variables and functions are shared. |
| Fail closed | Startup **hard-fails** if `src\` modules or `src\MANIFEST.sha256` are missing or hashes mismatch. |
| Encrypt data, not code | DNS undo snapshots and RDP host prior use **DPAPI** (CurrentUser + fixed entropy). Preferences JSON is not secret but gets a tight ACL. Modular load is always plain text. |

## Encryption vs modular load (read this)

| What | Encrypted? | Mechanism |
|------|------------|-----------|
| `src\Bastion.*.ps1` modules | **No** | Plain text, loaded by script-scope dot-source |
| `Bastion-Hardening.ps1` bootstrap | **No** | Plain text |
| `tools-elevate-self.ps1` / `tools-run-bootstrap.ps1` | **No** | Plain text helpers for the `.bat` |
| `src\MANIFEST.sha256` | **No** (not encryption) | SHA256 **integrity** hashes; tamper detection only |
| DNS prior / RDP host prior in undo store | **Yes** | Windows **DPAPI** after a real Apply that recorded them |

If a launch fails after hardening, the cause is almost always **launcher / elevation / ExecutionPolicy / cmd parse** — not “encrypted modules.” Modules are intentionally readable.

## Runtime layout

```
bastion-hardening-v15.9.7\   (folder name matches the release tag)
  Bastion-Hardening.bat      # UAC launcher; High-IL whoami check; goto-safe; calls helpers
  tools-elevate-self.ps1     # UAC re-launch helper (avoids nested parentheses in cmd)
  tools-run-bootstrap.ps1    # Unblock-File + Process Bypass + & Bastion-Hardening.ps1
  Bastion-Hardening.ps1      # Thin bootstrap: early Process Bypass; integrity; script-scope .
  Bastion-Banner.utf8.txt
  LICENSE, NOTICE, README.md, SECURITY.md
  src\
    MANIFEST.sha256          # SHA256 of each module (paths relative to src\)
    Bastion.Init.ps1         # $script: catalogs, sections, providers, flags
    Bastion.Core.ps1         # UI, log, prompts, console theme (black/gray); Write-Banner uses BastionRoot
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

### Monolith vs modular (summary)

| Concern | Monolith era (through v15.8.x) | Modular era (v15.9.x+) |
|---------|-------------------------------|-------------------------|
| Where logic lives | One large script | Domain modules under `src\` + thin bootstrap |
| Review cost | High (scroll/search entire file) | Lower (open named module) |
| Integrity | Whole-file presence | Per-module `MANIFEST.sha256` hard-fail |
| Source form | Plain text | Plain text (never encrypted) |
| Runtime entry | Elevated `.bat` | Same elevated `.bat` path |

**Not shipped in the release zip:** `tools\` (pack/wiki scripts, optional monolith archive under `tools\archive\` for git history / comparison only — not the supported runtime layout).

## Load order

**Launcher (`Bastion-Hardening.bat`)** (preferred entry):

1. Detects **true elevation** with **whoami High Mandatory Level** SID `S-1-16-12288` (not `net session`, which fails after Bastion disables LanmanServer; not Administrators group SID alone, which appears as deny-only on non-elevated UAC tokens).
2. If not elevated: re-launches via `tools-elevate-self.ps1` (or inline `Start-Process -Verb RunAs` fallback) and exits.
3. If elevated: calls `tools-run-bootstrap.ps1`, which sets Process-scope ExecutionPolicy Bypass, recursively `Unblock-File`s the product tree (Mark-of-the-Web from zip downloads), and invokes `Bastion-Hardening.ps1` with `&`.
4. Uses **goto labels** instead of large parenthesized `if (...)` blocks with `echo` text containing `(` / `)` — those caused `. was unexpected at this time.` after Server was disabled and the bat was re-run elevated.

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

### Write-Banner path

`Write-Banner` prefers `$script:BastionRoot` (product root next to the banner file). If that is empty and Core’s `$PSScriptRoot` is `...\src`, it uses the **parent** of `src` so `Bastion-Banner.utf8.txt` is found after modular split.

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

Expected: `Bastion smoke load OK v15.9.7 (commands verified)` (version string follows `ScriptVersion`) and exit 0. After load, commands such as `Show-MainMenu` must exist in the runspace (script-scope dot-source + explicit command probe).

Bat path smoke (elevated host, LanmanServer may be stopped/disabled):

```text
cmd /c Bastion-Hardening.bat
```

Expected: “Elevated console ready”, then main menu (or use `tools-run-bootstrap.ps1` with bootstrap args in automated tests).

## Version

Product-facing version is **15.9.7** (`$script:Config.ScriptVersion` in `Bastion.Init.ps1`, bootstrap header, README, SECURITY supported table, pack-release default). Prefer **15.9.7** for Help color-coded docs on the dark console, forced black theme (**15.9.6**), and **15.9.5** launch fixes on Bastion-hardened machines where Server/LanmanServer is disabled. Always start with the `.bat`, never the `.ps1` alone.

**Public site note:** Official site download and GitHub **Latest** recommend modular **15.9.7** (plain-text `src\`, MANIFEST integrity; source never encrypted).

## Related docs

- [DATA-DIRECTORY.md](DATA-DIRECTORY.md) - files Bastion creates at runtime
- [SECURITY.md](../SECURITY.md) - reporting and safe usage
- [BROWSER-POLICIES-AND-ECH.md](BROWSER-POLICIES-AND-ECH.md) - browser modes and ECH
- [KNOWN-ISSUES.md](KNOWN-ISSUES.md) - StrictHandle, Game Bar overlay, etc.
