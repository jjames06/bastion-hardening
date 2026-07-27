# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 15.x    | Yes       |
| < 15.0  | No        |

Only the latest published release of Bastion Hardening Framework is supported for security fixes.

## What this project does

Bastion makes deliberate system changes on Windows (services, firewall, registry, DNS, Defender settings, AppX packages, and related areas). Treat every copy of the script as **privileged software**:

- Run only from this official repository or a release you verified yourself
- Review `Bastion-Hardening.ps1` before first use
- Prefer a System Restore Point before Apply or Quick Harden

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

## Safe usage checklist

1. Create a System Restore Point  
2. Run **Dry Run** and review “Would change” items  
3. Leave high-impact sections (BloatApps, OneDrive) off until you understand them  
4. Choose DNS under menu **D**, or leave DNS unchanged  
5. Apply, then re-run Dry Run / Audit to verify  

## Supply-chain notes

- Program installs use **winget catalog IDs only** and never pass `--ignore-security-hash`
- Custom package IDs typed by the user are not accepted
- GPU/BIOS guidance is informational only; Bastion does not flash firmware or auto-install vendor driver suites

## Scope

This policy covers the Bastion scripts and packaging in this repository. It does not cover third-party resolvers (Quad9, Cloudflare, Google, OpenDNS), Microsoft Windows, or winget package publishers.
