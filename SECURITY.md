# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 15.8.3  | Yes (current) |
| 15.8.2  | Best-effort until you upgrade |
| 15.8.1  | Best-effort until you upgrade |
| 15.8    | Best-effort until you upgrade |
| 15.7    | Best-effort until you upgrade |
| 15.3    | Best-effort until you upgrade (older MIT-era tag; prefer 15.8) |
| 15.2    | Best-effort until you upgrade |
| 15.1    | Best-effort until you upgrade |
| 15.0    | Best-effort until you upgrade |
| 15.6    | Unpublished (removed; use 15.8) |
| 15.5 / 15.4 | Never published as release tags |
| < 15.0  | No        |

Prefer the **latest published release** of Bastion Hardening Framework for security fixes and product updates.

## License (distribution)

Current tree: **GNU GPLv3** (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Treat every distributed copy as privileged software **and** as free software under GPLv3 (source must travel with modified redistributions). Older release zips that still contain an MIT `LICENSE` file remain under the terms shipped in those artifacts.

## What this project does

Bastion makes deliberate system changes on Windows (services, firewall, registry, DNS, Defender settings, AppX packages, browser enterprise policies when you opt in, and related areas). Treat every copy of the script as **privileged software**:

- Run only from the [official site](https://www.operationlockedin.com/bastion/download), this official GitHub repository, or a release you verified yourself
- Review `Bastion-Hardening.ps1` before first use
- Prefer a System Restore Point before Apply or Quick Harden

## Runtime files (transparency)

On elevated launch, Bastion creates a **writable data directory** (path shown on the main menu) for logs, menu preferences, session snapshots, and optional Apply undo data. It does **not** invent Apply history on first run.

Full inventory: [docs/DATA-DIRECTORY.md](docs/DATA-DIRECTORY.md).

| Expectation | Reality |
|-------------|---------|
| First run | Seeds config defaults; rewrites session/browser-state snapshots from **live** detection |
| Apply history file | `Bastion-LastApply.json` only after a **real** Apply |
| DNS / RDP undo secrets | DNS snapshot and RDP host prior are **DPAPI-encrypted** in that file; ACL SYSTEM + Administrators. Same elevating account can decrypt; full account compromise still can. See [docs/DATA-DIRECTORY.md](docs/DATA-DIRECTORY.md) |
| Display privacy | Winget preflight / Audit do not echo the full winget executable path (often under a user profile). Data-directory path still appears on the main menu by design. |
| Encrypted Client Hello (ECH) | Never written unless you opt in under Strict in menu **6** - see [docs/BROWSER-POLICIES-AND-ECH.md](docs/BROWSER-POLICIES-AND-ECH.md) |
| Telemetry to Bastion authors | Bastion does not upload logs or config to a Bastion cloud service as part of normal operation |

Browser policy files/keys (Firefox `policies.json`, Chrome/Brave policy registry) are written only when you use browser policy features. They live **outside** the data directory and are not removed merely by deleting Bastion's JSON folder.

## Reporting a vulnerability

**Do not** open a public Issue with full exploit details for a newly discovered vulnerability.

Prefer one of:

1. **GitHub Security Advisory** (private) on this repository, if available  
2. A **private** report path configured on the repository  
3. An Issue that states only that a security concern exists, without weaponizable detail, and asks maintainers to open a private channel

Include when possible:

- Bastion version (`ScriptVersion` in the script header)
- Windows 10/11 build
- Steps to reproduce
- Expected vs actual impact (privilege escalation, unexpected network exposure, data loss risk, etc.)

We will aim to acknowledge reports and prioritize fixes on a best-effort basis.

## Non-vulnerabilities (please do not report as product bugs)

- Disabling Print Spooler, network discovery, OneDrive client, or similar **documented** hardening side effects
- VPN software overriding Bastion DNS settings while a tunnel is connected
- Windows denying optional policy keys even when elevated (documented Soft skips)
- Need for Administrator rights (required by design)
- Site or network breakage after **Strict** browser mode or an optional **Encrypted Client Hello (ECH)** pack you explicitly enabled (documented compatibility trade-offs; revert with menu **6** → Default or System Restore)
- Presence of Bastion log/config files under the documented data directory (expected; see [docs/DATA-DIRECTORY.md](docs/DATA-DIRECTORY.md))
- Missing `Bastion-LastApply.json` after first launch without Apply (expected; no Apply undo until Apply runs)
- Program/game launch failures after **ExploitProtection** / system **StrictHandle** (World of Warcraft was one documented example; others may break until reported) - known issue [#18](https://github.com/jjames06/bastion-hardening/issues/18), reverse via Recovery → 6 → StrictHandle, and [docs/KNOWN-ISSUES.md](docs/KNOWN-ISSUES.md); not a remote code-execution vulnerability

## Safe usage checklist

1. Create a System Restore Point  
2. Run **Dry Run** and review "Would change" items  
3. Leave high-impact sections (BloatApps, OneDrive) off until you understand them  
4. Treat browser **Strict** and Encrypted Client Hello (ECH) as optional; ECH is never default  
5. Choose DNS under menu **D**, or leave DNS unchanged  
6. Apply, then re-run Dry Run / Audit to verify  
7. Know your data directory path (main menu) if you need logs or want to clear Bastion prefs  

## Supply-chain notes

- Program installs use **winget catalog IDs only** and never pass `--ignore-security-hash`
- Custom package IDs typed by the user are not accepted
- GPU/BIOS guidance is informational only; Bastion does not flash firmware or auto-install vendor driver suites
- Prefer the [official product site](https://www.operationlockedin.com) download, official GitHub releases, or clones of this repository; do not run untrusted re-uploads
- The site download (`/api/bastion/download`) resolves to the same GitHub Latest release zip; it is not a third-party mirror

## Scope

This policy covers the Bastion scripts and packaging in this repository. It does not cover third-party resolvers (Quad9, Cloudflare, Google, OpenDNS), Microsoft Windows, browser vendors' ECH implementations, or winget package publishers.
