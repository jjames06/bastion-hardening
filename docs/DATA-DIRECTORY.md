# Bastion data directory

Bastion is **not** a silent installer that scatters files across Windows without documentation. On every elevated launch it uses a single **data directory** for logs, menu preferences, and Apply undo data. The path is shown on the **main menu** and again when you exit.

This document explains **what** is created, **why**, and what is **not** invented.

---

## Why a data directory exists

| Need | Why files exist |
|------|-----------------|
| Session logs | Support, review, and honest post-run inspection |
| Menu preferences | Remember section toggles, DNS choice, program queue, browser *wanted* modes between runs |
| Live posture snapshot | Prove the store is real; record live vs wanted browser state each launch |
| Apply undo | Track services / firewall groups from the **last real Apply** only |
| Browser policy safety | Backups before Bastion overwrites browser enterprise policies |

**State-aware Apply and Dry Run do not depend on these files to invent "already hardened."** They read **live Windows state** (services, firewall, registry, features, browser policy files/keys). JSON files are memory for *your choices* and *Bastion's own Apply undo* - not a fake claim that Windows was hardened if you never Applied. Bastion **does not invent** Apply history on first run.

---

## Where the directory lives

Bastion picks the first **writable** location that works. If Bastion state files already exist somewhere on the list, that location is reused (preferring the newest `Bastion-Config.json`).

### Prefer existing Bastion state (if present and writable)

1. `C:\Temp\Bastion`
2. `C:\Temp` (legacy flat layout from older builds)
3. `%ProgramData%\Bastion`
4. `%LOCALAPPDATA%\Bastion`
5. `%TEMP%\Bastion` (last; can be wiped by Disk Cleanup)

### New install (no prior Bastion state)

1. `C:\Temp\Bastion` (preferred durable machine-local path)
2. `%ProgramData%\Bastion`
3. `%LOCALAPPDATA%\Bastion`
4. `C:\Temp` (legacy flat fallback)
5. `%TEMP%\Bastion` (last resort only)

Each candidate is **write-probed** (create folder if needed, write a short temporary file, delete it). If nothing is writable, Bastion warns and will not pretend a store exists.

---

## What is created (and when)

| Path under the data directory | When | Purpose |
|-------------------------------|------|---------|
| *(the directory itself)* | First elevated launch that can write | Root for all Bastion runtime files |
| `BastionInstallers/` | First launch (path ensure) | Staging area for optional winget-related install work |
| `browser-policy-backups/` | First launch (path ensure); files added when menu **6** changes policies | Snapshots of browser policy material before Bastion overwrites it |
| `Bastion-Config.json` | **Seeded on first run** (or after a full wipe of the store) | Section toggles, selected catalog apps, install roots, per-browser **wanted** modes, ECH Yes/No flags, DNS provider; optional **`WowInstallRoots`** (folders) and **`StrictHandleExceptionPaths`** (full `.exe` paths) for custom game layouts / extra StrictHandle exceptions |
| `Bastion-Session.json` | **Rewritten every launch** | Live browser posture vs wanted modes, whether prior config/Apply files existed, data directory path. Proves the store is real; **not** Apply history |
| `Bastion-BrowserPolicies-State.json` | Created/updated when browser policy state is saved (every launch after init, and after menu **6** changes) | Wanted modes, live detection, last policy change summary |
| `Bastion-Log-yyyyMMdd-HHmmss.txt` | Each session | Transcript lines for that run |
| `Bastion-LastApply.json` | **Only after a real Apply** (Quick Harden / Apply that completes undo tracking) | Timestamp, sections run, tracked undo for services and firewall groups |
| `Bastion-Report-*.html` | Only if you export from Help and Reports | Optional HTML snapshot |

### What is **not** created on first run

| Item | Why |
|------|-----|
| `Bastion-LastApply.json` | There is no Bastion Apply undo until you Apply. Missing file = no Bastion Apply history, **not** "Windows is stock" |
| System-wide product registration | Bastion is not an MSI; it does not add itself to Programs and Features |
| Encrypted Client Hello (ECH) policy | ECH is never written unless you opt in under Strict in menu **6** (see [BROWSER-POLICIES-AND-ECH.md](BROWSER-POLICIES-AND-ECH.md)) |

---

## First run vs later runs

### First elevated launch (or after you delete the whole data folder)

1. Resolve or create a writable data directory.
2. Seed `Bastion-Config.json` with **safe defaults** (menu preferences only).
3. Write `Bastion-Session.json` and browser policy state from **live** detection.
4. Main menu shows the data directory path and a **first run / wiped store** style message when appropriate.
5. Dry Run still reports **Would change** / **Already OK** from Windows itself.

### Later launches (files still present)

1. Load `Bastion-Config.json` (your last menu choices).
2. Load last browser-policy change metadata if present.
3. Rewrite session + browser state from live detection again.
4. Show **Last Bastion Apply** only if `Bastion-LastApply.json` exists.

### If you delete only some files

| Deleted | Next launch behavior |
|---------|----------------------|
| Whole data directory | Clean seed again; no invented Apply history |
| `Bastion-Config.json` only | Defaults re-seeded; Apply file kept if still present |
| `Bastion-LastApply.json` only | Menu shows no Bastion Apply recorded; Undo has nothing from Bastion; Dry Run still uses live OS |
| `Bastion-Session.json` only | Rewritten automatically on next launch |

Deleting Bastion's data directory **does not** undo Windows hardening, browser enterprise policies, or winget installs. Use Recovery, per-browser **Default**, Uninstall, or **System Restore** for those.

---

## Files Bastion may change *outside* the data directory

These are intentional system changes when you choose the related feature - not secret sidecars.

| Area | Typical locations (examples) | When |
|------|------------------------------|------|
| Firefox policies | `C:\Program Files\Mozilla Firefox\distribution\policies.json` | Menu **6** / browser policy Apply |
| Chrome / Brave policies | `HKLM\SOFTWARE\Policies\Google\Chrome`, `HKLM\SOFTWARE\Policies\BraveSoftware\Brave` (and related) | Menu **6** / browser policy Apply |
| Hardening sections | Services, firewall, registry, optional features, Defender, DNS adapters, AppX, etc. | **Apply** / **Quick Harden** for enabled sections |
| Windows Event Log | Application log, source `BastionHardening` | Logging (best-effort) |
| System Restore points | Windows restore catalog | Menu **13** / **R** when you create a point |

Full section behavior is documented in the in-app Help (menu **11**) and the main [README](../README.md).

---

## Privacy and support

- Bastion does **not** upload your logs or config to a network service as part of normal operation.
- Logs may include paths, hostnames of local adapters, and status lines useful for debugging.
- When filing an Issue or Discussion, you may attach **redacted** log lines; avoid pasting secrets if you ever put them in custom paths.

---

## Related documentation

- [README - How to install](../README.md#how-to-install-properly)
- [Browser policies and Encrypted Client Hello (ECH)](BROWSER-POLICIES-AND-ECH.md)
- [SECURITY.md](../SECURITY.md)
- In-app **Help → page 12 (Files and logs)** shows the **live path for this session**
