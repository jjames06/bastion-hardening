# Bastion Hardening Framework

**Selective · State-aware · Safety-first Windows hardening for a personal workstation**

Version **15.0**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?logo=windows&logoColor=white)](#tested-on)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](#how-to-install-properly)

<p align="center">
  <img src="docs/images/hero-banner.png" alt="Bastion — menu-driven Windows hardening for personal machines" width="720">
</p>

<p align="center">
  <a href="#how-to-install-properly"><strong>Install guide</strong></a> ·
  <a href="https://github.com/jjames06/bastion-hardening/releases/latest"><strong>Latest release</strong></a> ·
  <a href="https://github.com/jjames06/bastion-hardening/discussions"><strong>Discussions</strong></a> ·
  <a href="SECURITY.md"><strong>Security</strong></a>
</p>

---

## Screenshots

Main menu (review, configure, apply, safety):

![Bastion main menu](docs/images/main-menu.png)

Dry Run — state-aware preview, no changes applied:

![Bastion Dry Run](docs/images/dry-run.png)

Built-in help (scope, safety model, section docs):

![Bastion help overview](docs/images/help-overview.png)

---

## Tested on

Verified by the maintainer on a personal daily-driver PC (not a lab matrix of every SKU):

| OS | Build | Arch | Bastion | Notes |
|----|-------|------|---------|--------|
| **Windows 11 Pro** | **10.0.26200** (build **26200**) | 64-bit | **v15.0** | Dry Run, menus, config load, DNS/firewall posture as of 2026-07-27 |

Also intended for **Windows 10** (same script surface). If you run Bastion on a build not listed here, please report success or issues in [Discussions → Testing feedback](https://github.com/jjames06/bastion-hardening/discussions) or [Issues](https://github.com/jjames06/bastion-hardening/issues).

**Not tested / not supported:** domain-joined, Intune/MDM-managed, Windows Server, ARM-specific edge cases (may still run; report results).

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

## How to install (properly)

Bastion is **not** an MSI installer. You download the files, keep them together, and launch the elevated batch file. Nothing is registered as a Windows program until *you* choose optional winget installs inside the tool.

### Before you start

1. Use a **personal** PC you fully control (not work, school, domain-joined, or MDM-managed).
2. Prefer the **official** release or this GitHub repository only — not random re-uploads.
3. Skim [LICENSE](LICENSE) and the warnings at the top of this README.
4. Optionally read the script (`Bastion-Hardening.ps1`) before the first Apply.

### Method A — Release zip (recommended)

Best for most people.

1. Open the latest release:  
   **https://github.com/jjames06/bastion-hardening/releases/latest**  
   (or [v15.0](https://github.com/jjames06/bastion-hardening/releases/tag/v15.0) if you want a pinned version)
2. Download **`bastion-hardening-v15.0.zip`** (or the current release asset with a similar name).
3. Right-click the zip → **Properties** → if you see **Unblock**, check it → **OK**  
   (reduces SmartScreen / “downloaded from the internet” friction on the extracted scripts)
4. Extract the zip to a folder **you** control, for example:  
   `C:\Tools\Bastion`  
   Avoid system folders such as `C:\Windows` or Program Files.
5. Confirm these files sit **in the same folder**:

   | File | Required? |
   |------|-----------|
   | `Bastion-Hardening.bat` | Yes — launcher |
   | `Bastion-Hardening.ps1` | Yes — main script |
   | `Bastion-Banner.utf8.txt` | Optional (banner only) |
   | `LICENSE`, `README.md`, `SECURITY.md` | Optional at runtime |

6. **Do not** double-click the `.ps1` file. Use the batch launcher:
   - Right-click **`Bastion-Hardening.bat`**
   - Choose **Run as administrator**
   - Accept the UAC prompt
7. When the Bastion menu appears, go to **How to run Bastion the first time** below.

### Method B — Git clone

For people who already use Git and want easy updates.

```powershell
git clone https://github.com/jjames06/bastion-hardening.git
cd bastion-hardening
```

Then right-click **`Bastion-Hardening.bat`** → **Run as administrator** (same as Method A, step 6).

To update later:

```powershell
cd bastion-hardening
git pull
```

### Method C — Download ZIP from the Code button

GitHub **Code → Download ZIP** works, but the **Releases** zip is preferred (known version tag, release notes, checksums if you add them later).

If you use Code ZIP: extract, keep files together, launch `Bastion-Hardening.bat` as administrator — same rules as Method A.

### How to run Bastion the first time

After the elevated menu opens:

1. **13** or **R** — create a named System Restore Point  
2. **1** — Dry Run (preview only; no hardening applied)  
3. **2** — Security Audit (optional posture sample)  
4. **4** — enable only sections you understand  
5. **5** — select programs only if you want installs (none are pre-selected)  
6. **D** — DNS resolver, or leave DNS unchanged  
7. **7** Quick Harden or **8** Apply — type **YES** when asked  
8. Reboot if prompted (e.g. LSA Protection / some optional features)  
9. Run **Dry Run** again to verify  

### Common install / launch problems

| Symptom | What to try |
|---------|-------------|
| Nothing happens / window flashes | Run `Bastion-Hardening.bat` **as administrator**, not the `.ps1` alone |
| “scripts is disabled” / execution policy | The launcher uses `-ExecutionPolicy Bypass` for this script only. Use the `.bat`, not a locked-down host policy that blocks even elevated Bypass |
| SmartScreen / “Windows protected your PC” | Prefer Unblock on the zip (Method A step 3). More info → Run anyway **only** if you trust this official source |
| winget / Programs installs fail | Install **App Installer** from the Microsoft Store, open a new elevated window, retry |
| Files “not found” after extract | Keep `.bat` and `.ps1` in the **same** directory; do not run a shortcut that points elsewhere |
| Controlled Folder Access / AV blocks | Allow the script path temporarily, or run Dry Run first and apply in smaller steps |

### What Bastion does **not** install for you

- It does **not** add itself to Programs and Features as a permanent product installer  
- It does **not** flash BIOS or auto-install GPU drivers  
- Optional apps install **only** if you select them under Programs and run Apply  
- Logs/config default under `C:\Temp` (or `%TEMP%\Bastion` / `%LOCALAPPDATA%\Bastion` fallbacks)

---

## Quick start (short)

1. Download the [latest release](https://github.com/jjames06/bastion-hardening/releases/latest) zip and extract it  
2. Right-click `Bastion-Hardening.bat` → **Run as administrator**  
3. Create a System Restore Point (**13** / **R**)  
4. **Dry Run** first, then Apply or Quick Harden  

For full detail, use **[How to install (properly)](#how-to-install-properly)** above.

---

## Main sections

| Section              | Default | Notes                                           |
|----------------------|---------|-------------------------------------------------|
| Firewall             | On      | Inbound block, outbound allow + group hardening |
| HighRiskServices     | On      | Includes Spooler (PrintNightmare surface)       |
| SMBv1                | On      | Disables legacy SMB1                            |
| OneDrive             | On      | Removes desktop client only                     |
| DeliveryOptimization | On      | HTTP-only updates                               |
| DNS                  | On*     | User-chosen public resolver (default Quad9)     |
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

\* DNS is enabled by default with **Quad9**, but you can pick another resolver or leave DNS alone (main menu **D**). Quick Harden asks whether to change DNS and which provider to use.

Quick Harden uses a safer subset and asks explicitly whether to keep the Print Spooler enabled and whether to change DNS.

---

## DNS resolvers

From main menu **D** (or Sections → **D**), choose one of:

| Option | Primary / secondary | Notes |
|--------|---------------------|--------|
| **Quad9 (malware blocking)** | `9.9.9.9` / `149.112.112.112` | Default. Blocks known malicious domains |
| **Cloudflare (1.1.1.1)** | `1.1.1.1` / `1.0.0.1` | Privacy-focused public DNS |
| **Cloudflare security** | `1.1.1.2` / `1.0.0.2` | Cloudflare with malware blocking |
| **Google Public DNS** | `8.8.8.8` / `8.8.4.4` | Highly available public DNS |
| **Cisco OpenDNS** | `208.67.222.222` / `208.67.220.220` | Public OpenDNS resolvers |
| **Do not change DNS** | — | Leaves adapters on DHCP/manual settings |

A connected VPN may override these settings while the tunnel is up. That is expected.

---

## Important notes

- **Print Spooler** — Disabled by default for security. Quick Harden gives a clear choice to keep it.
- **OneDrive & BloatApps** — Hard to reverse. System Restore is the reliable recovery path.
- **Undo** — Restores tracked services and firewall groups from the last Apply only. It does **not** reinstall AppX packages or OneDrive, and does **not** restore previous DNS servers.
- **DNS** — Optional. Choose a provider or leave DNS unchanged; VPN software may still override while connected.
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
| `SECURITY.md`             | Vulnerability reporting policy  |
| `README.md`               | This documentation              |

---

## Feedback and contributions

- **Testing feedback / “I ran this on …”:** [GitHub Discussions](https://github.com/jjames06/bastion-hardening/discussions) (see the pinned **Testing feedback** thread)
- **Bugs and feature requests:** open a [GitHub Issue](https://github.com/jjames06/bastion-hardening/issues)
- **Pull requests:** welcome for clear fixes and documentation improvements
- Maintained on a best-effort basis

When reporting a bug, include Windows version (**Settings → System → About** or `winver`), what you ran (Dry Run / Apply / Quick Harden), and relevant lines from the Bastion log under the log directory shown at exit.

---

## Security

- Review the script before running it. Trust is earned by reading the code.
- Prefer official releases or clones of this repository only.
- Do not run untrusted copies of Bastion from random downloads or chat attachments.
- Vulnerability reporting and supported versions: see [SECURITY.md](SECURITY.md).

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for the full text and the additional disclaimer about system changes and risk.

**Use at your own risk.**
