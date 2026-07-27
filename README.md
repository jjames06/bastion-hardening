# Bastion Hardening Framework

**Selective · State-aware · Safety-first Windows hardening for a personal workstation**

Version **15.0**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Critical warnings

Read these before you run anything:

- **Requires Administrator privileges**
- Makes real system changes (services, firewall, registry, AppX packages, DNS, Defender, and more)
- **Create a System Restore Point** before Apply or Quick Harden
- Can break printing (Print Spooler), network discovery, OneDrive sync, Xbox features, Widgets, and related functionality
- Intended **only** for a single personal PC you fully control
- **Not** for work, school, domain-joined, or MDM-managed devices
- This is **not** an antivirus and does **not** make a system unhackable

If you are not comfortable creating a restore point and recovering from broken features, **do not run this tool**.

---

## What Bastion is

A guided, selective hardening assistant for Windows 10/11 that lets you:

- Measure current posture (Dry Run and Security Audit)
- Choose exactly which areas to harden
- Apply changes with logging and limited undo
- Install a curated catalog of common applications via winget
- Recover common side effects (Print Spooler, browser policies, Widgets, and more)

## What Bastion is not

- Not an antivirus or complete security product
- Not an enterprise MDM / Group Policy replacement
- Not a reckless “one-click debloat everything” script
- Not a claim of zero-day protection

---

## Design principles

| Principle | Meaning |
|-----------|---------|
| **Selective** | Almost every section is optional |
| **State-aware** | Detects what is already configured before changing it |
| **Safety-first** | Restore-point gate, soft failures, honest documentation |
| **Catalog-only installs** | No free-typed package IDs; never uses `--ignore-security-hash` |
| **Reversible where practical** | Tracked Undo for services and firewall groups |

System Restore remains the strongest rollback path.

---

## Requirements

- Windows 10 or Windows 11
- Administrator rights
- System Protection / System Restore enabled on the system drive (strongly recommended)
- [winget](https://learn.microsoft.com/windows/package-manager/winget/) (App Installer) recommended for the Programs section

---

## Quick start

### Option A — Download release

1. Download the latest release (or clone this repository)
2. Extract the files to a folder you control
3. Right-click `Bastion-Hardening.bat` → **Run as administrator**
4. Create a System Restore Point (menu **13** or **R**)
5. Run **Dry Run** first
6. Review sections, then Apply or use Quick Harden

### Option B — Clone with Git

```powershell
git clone https://github.com/jjames06/bastion-hardening.git
cd bastion-hardening
# Right-click Bastion-Hardening.bat → Run as administrator
```

---

## Recommended first-time workflow

1. Menu **13 / R** → create a named System Restore Point  
2. Option **1** → Dry Run (see what would change)  
3. Option **2** → Security Audit  
4. Option **4** → enable only the sections you understand  
5. Option **5** → select programs only if you want them installed  
6. Option **7** (Quick Harden) or **8** (Apply)  
7. Reboot if LSA Protection or optional features were changed  
8. Run Dry Run again to verify  

---

## Main sections

| Section              | Default | Notes                                           |
|----------------------|---------|-------------------------------------------------|
| Firewall             | On      | Inbound block, outbound allow + group hardening |
| HighRiskServices     | On      | Includes Spooler (PrintNightmare surface)       |
| SMBv1                | On      | Disables legacy SMB1                            |
| OneDrive             | On      | Removes desktop client only                     |
| DeliveryOptimization | On      | HTTP-only updates                               |
| DNS                  | On      | Quad9 (`9.9.9.9`)                               |
| Defender             | On      | Network Protection + Controlled Folder Access   |
| PowerShellAuditing   | On      | Script Block Logging                            |
| ExploitProtection    | On      | Mild, compatibility-safe mitigations            |
| LSAProtection        | On      | RunAsPPL (reboot required)                      |
| ScheduledTasks       | On      | Selected telemetry tasks                        |
| XboxGaming           | Off     | Optional                                        |
| Programs             | On      | Catalog-only winget installs (none pre-selected)|
| BrowserPolicies      | Off     | Firefox / Chrome privacy modes                  |
| BloatApps            | Off     | Curated AppX removal                            |
| Suggestions          | Off     | Widgets / Start suggestions                     |
| CopilotM365          | Off     | Optional                                        |

Quick Harden uses a safer subset and asks explicitly whether to keep the Print Spooler enabled.

---

## Important notes

- **Print Spooler** — Disabled by default for security. Quick Harden gives a clear choice to keep it.
- **OneDrive & BloatApps** — Hard to reverse. System Restore is the reliable recovery path.
- **Undo** — Restores tracked services and firewall groups from the last Apply only. It does **not** reinstall AppX packages or OneDrive.
- **VPN DNS** — A connected VPN may override Quad9. That is normal.
- **Custom install paths** — Only allowed on fixed local volumes outside system directories.
- **Logs and config** — Prefer `C:\Temp`; fall back to `%TEMP%\Bastion` or `%LOCALAPPDATA%\Bastion` if needed.

---

## Repository layout

| File                      | Purpose                         |
|---------------------------|---------------------------------|
| `Bastion-Hardening.ps1`   | Main script                     |
| `Bastion-Hardening.bat`   | Elevated launcher               |
| `Bastion-Banner.utf8.txt` | Optional Unicode banner         |
| `LICENSE`                 | MIT License + additional notice |
| `README.md`               | This documentation              |

---

## Feedback and contributions

- **Bugs and feature requests:** open a [GitHub Issue](https://github.com/jjames06/bastion-hardening/issues)
- **Pull requests:** welcome for clear fixes and documentation improvements
- Maintained on a best-effort basis

When reporting a bug, include Windows version, what you ran (Dry Run / Apply / Quick Harden), and relevant lines from the Bastion log under the log directory shown at exit.

---

## Security

- Review the script before running it. Trust is earned by reading the code.
- Prefer official releases or clones of this repository only.
- Do not run untrusted copies of Bastion from random downloads or chat attachments.
- For vulnerability reports, open a private security advisory on GitHub if available, or an Issue without exploit detail until maintainers respond.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for the full text and the additional disclaimer about system changes and risk.

**Use at your own risk.**
