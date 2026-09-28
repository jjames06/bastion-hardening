# Bastion code map

Selective Windows 10/11 hardening for a PC you administer. GNU GPLv3. Version **16.0**.

Not Rampart (hostname checker) and not the practice website. This program never points at a URL.

Every `src\Bastion.*.ps1`, the bootstrap, the `.bat`, and `tools\*.ps1` starts with a `CODEMAP FILE:` header. Domain modules already had function-level comment-based help (`Purpose` / `When called` / `Side effects` / `Undo`); those remain under the file header.

## Entry

`Bastion-Hardening.bat` elevates, then `Bastion-Hardening.ps1` dot-sources `src\*.ps1` in a fixed order into **this** runspace so `$script:` state is shared. Integrity: `src\MANIFEST.sha256` (rebuild with `tools\New-BastionSourceManifest.ps1` after editing source).

## Load order (`src`)

1. `Bastion.Init.ps1` — paths, stats, catalogs. No functions.
2. `Bastion.Core.ps1` — log, menu primitives, `Open-UrlSafe`.
3. `Bastion.Config.ps1` — JSON config, DPAPI undo secrets.
4. `Bastion.Programs.ps1` — catalog-only winget.
5. `Bastion.Services.ps1` — services, firewall groups, tasks.
6. `Bastion.Browsers.ps1` — policy modes, optional ECH (never default).
7. `Bastion.Dns.ps1` — preferred DNS + DoH.
8. `Bastion.Network.ps1` — optional LAN hygiene.
9. `Bastion.Harden.ps1` — Game DVR, OneDrive, CFA, Defender health, WoW StrictHandle exceptions, RDP host.
10. `Bastion.Cve.ps1` — detect/compensating controls on this PC.
11. `Bastion.Apply.ps1` — the only module that should persist most system changes (after Dry Run).
12. `Bastion.Recovery.ps1` — undo using Config snapshots. System Restore is still the strongest rollback.
13. `Bastion.Menus.ps1` — main loop.

## What encryption is (and is not)

- Modular source: **never** encrypted (GPLv3 + independent audit).
- `MANIFEST.sha256`: integrity only.
- DPAPI: undo payloads only (DNS snapshot, RDP prior, CVE undo) in `Bastion.Config.ps1`.

## Do not

- Run domain modules standalone.
- Treat this as a pentest tool.
- Skip Dry Run on a machine you have not snapshotted.
- Point Bastion at a hostname; that is Rampart's job.
- Rely on `net session` for elevation after Apply (LanmanServer may be disabled).
- Claim Bastion patches Microsoft kernel / ALPC / Update Stack CVEs.

## File index

| File | Role |
|------|------|
| `Bastion-Hardening.bat` | Official end-user launcher. Self-elevates, Unblock-File / MOTW, starts Bastion-Hardening.ps1 with Process Bypass. |
| `Bastion-Hardening.ps1` | Thin elevated bootstrap. Dot-sources src\Bastion.*.ps1 in fixed order into THIS runspace so $script: state is shared. Then enters menus (or smoke-load). |
| `src/Bastion.Apply.ps1` | ONLY module that should persist most system changes after Dry Run: Security Audit, Apply, Quick Harden, System Restore Point create/check. |
| `src/Bastion.Browsers.ps1` | Per-browser policy modes and optional ECH locks. Writes on confirm (NOW), not only at Apply. |
| `src/Bastion.Config.ps1` | Bastion-Config.json load/save, ACL on the config file, DPAPI Protect/Unprotect for undo blobs (DNS snapshot, RDP prior, CVE undo). |
| `src/Bastion.Core.ps1` | Log, menu primitives, Open-UrlSafe, write helpers, pause/header. Shared by every later module. |
| `src/Bastion.Cve.ps1` | Workstation CVE catalog Bastion can DETECT on this PC, and reversible remediations where they exist. Main menu C. Optional Apply section off by default. |
| `src/Bastion.Dns.ps1` | Preferred DNS provider catalog, per-interface DoH (DohFlags=17 + template), apply/restore of DNS. Snapshot is DPAPI-protected in undo. |
| `src/Bastion.Harden.ps1` | Section helpers: Game DVR, OneDrive, bloat Appx, Defender CFA paths, Defender update health, WoW StrictHandle exceptions, registry soft-set, RDP host allow/deny. |
| `src/Bastion.Init.ps1` | First module. Declares $script: paths, stats, catalogs, DPAPI entropy salt. No functions. |
| `src/Bastion.Menus.ps1` | Interactive UI. Most menus save preferences only. Windows changes when Apply (8) or the documented NOW paths run (browsers, uninstall, DNS A, Recovery). |
| `src/Bastion.Network.ps1` | Optional workstation LAN hygiene (outbound leak-ish settings). Recovery fingerprints the live gateway; it does not assume a Bell GigaHub. |
| `src/Bastion.Programs.ps1` | Catalog-only winget installs (no free-typed package IDs) and uninstall-on-confirm. |
| `src/Bastion.Recovery.ps1` | Undo using Config snapshots: services, firewall, DNS/DoH, RDP, StrictHandle exceptions, CVE remediations, browser policies. |
| `src/Bastion.Services.ps1` | High-risk and Xbox service lists, firewall groups, scheduled-task paths. Disable/restore with undo. |
| `tools-elevate-self.ps1` | Relaunch the current script elevated via UAC (used if someone starts the .ps1 directly). |
| `tools-run-bootstrap.ps1` | Unblock-File on the extracted tree (Mark of the Web) then launch Bastion-Hardening.ps1 with Process Bypass. |
| `tools/New-BastionSourceManifest.ps1` | Rebuild src/MANIFEST.sha256 after editing any Bastion.*.ps1. |
| `tools/Split-BastionMonolith.ps1` | Historical one-time splitter that created the modular src\ layout from v15.8.4 monolith. Do not run against current tree. |
| `tools/archive/Bastion-Hardening-v15.8.4-monolith.ps1` | Frozen pre-modular Bastion (v15.8.4) kept so reviewers can diff the split. Not shipped in the user zip. |
| `tools/pack-release.ps1` | Build dist/bastion-hardening-v16.0.zip with src, bat, licence, docs/wiki. Smoke-load the ps1. |
| `tools/publish-wiki.ps1` | Sync docs/wiki to the GitHub wiki remote. |
