# Modular source layout

Bastion is free software under **GPLv3**. People who run elevated hardening tools should be able to **read, review, and reason about** the code before they trust it. That requirement shaped how the product is packaged today.

## What changed

Through the **v15.8.x** line, Bastion shipped primarily as a **single large PowerShell script** (a *monolith*). All menus, Dry Run, Apply, Recovery, DNS, browsers, and helpers lived in one file. That layout was simple to download, but it made serious review harder: a reviewer had to scroll a multi-thousand-line script to find a single concern (for example DNS, Recovery, or browser policy).

Starting with the **v15.9.x** line, Bastion uses a **modular plain-text layout**:

| Piece | Role |
|-------|------|
| `Bastion-Hardening.bat` | Only supported launcher (UAC elevation, Mark-of-the-Web unblock helpers) |
| `Bastion-Hardening.ps1` | **Thin bootstrap**: integrity checks, then loads modules |
| `src\Bastion.*.ps1` | **Implementation** split by concern (core UI, config, DNS, browsers, Apply, Recovery, menus, and more) |
| `src\MANIFEST.sha256` | Per-module **SHA256 integrity** list (tamper detection, not encryption) |

You still install and run Bastion the same way: Unblock the zip, extract, run **`Bastion-Hardening.bat` as administrator**. You do **not** need to assemble modules by hand; official release zips already contain the full tree.

## Why we modularized

1. **Easier independent review.** Security-conscious users, auditors, and contributors can open only the files that match their question (`Bastion.Dns.ps1`, `Bastion.Recovery.ps1`, `Bastion.Apply.ps1`, and so on) instead of searching one giant script.
2. **Clearer ownership of behavior.** Menus, Apply pipelines, Recovery hubs, and network/browser helpers sit in named modules with explicit load order.
3. **Safer maintenance.** Smaller files reduce the cost of reviewing a pull request that touches one area without re-reading the entire product.
4. **Honest open-source posture.** Modules remain **readable plain text**. Bastion does **not** encrypt source to "protect" the product. GPLv3 and peer review both require that readers can study the code.
5. **Integrity without secrecy.** `MANIFEST.sha256` proves each module matches the release (or your intentional edit). That is **hash integrity**, not encryption. Encrypting the scripts would fight auditability.

## What stayed the same

- **Purpose and menus.** Dry Run, selective Apply, Recovery hubs, browser modes, DNS preference, and safety gates remain the product you already know.
- **Launcher rule.** Always start with **`Bastion-Hardening.bat`**. Do not double-click the `.ps1` alone under Restricted ExecutionPolicy.
- **Data vs code.** **DPAPI** may protect **Apply undo data** (DNS snapshot / RDP host prior). That is unrelated to how modules load. **Code is never encrypted.**
- **License.** GPLv3 still applies: run, study, share; distributed modified versions must stay GPLv3 with complete corresponding source.

## Monolith vs modular (side by side)

| | Earlier monolith (e.g. v15.8.x) | Current modular (v15.9.x+) |
|--|--------------------------------|----------------------------|
| Primary code shape | One large `Bastion-Hardening.ps1` (or equivalent single script) | Thin bootstrap + `src\Bastion.*.ps1` modules |
| Review a single topic | Search/scroll a huge file | Open the matching module |
| Startup integrity | File present / version string | **Per-module SHA256** via `MANIFEST.sha256` (hard-fail on mismatch) |
| How it runs for users | Elevated `.bat` -> PowerShell | Elevated `.bat` -> bootstrap **dot-sources** modules at **script scope** |
| Source readability | Plain text | Plain text (unchanged principle) |
| Archive | Still useful for history | Optional monolith snapshot may exist under repo `tools/archive\` for comparison only; **not** the recommended runtime path |

## How loading works (short)

1. You run **`Bastion-Hardening.bat`** elevated.
2. Helpers unblock Mark-of-the-Web and start the bootstrap with Process-scope Bypass.
3. `Bastion-Hardening.ps1` verifies `src\` and **`MANIFEST.sha256`**.
4. Modules are **dot-sourced in a fixed order** into the same runspace so menus and `$script:` state work after load.
5. The main menu appears. Smoke developers can use `-BastionSmokeLoadOnly` after elevation to verify import without opening the UI for long.

Full load order, layout tree, and threat notes: [docs/ARCHITECTURE.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/ARCHITECTURE.md) (also in the release zip).

## How to review the product

Suggested path for a careful first read:

1. **`Bastion-Hardening.bat`** and **`tools-run-bootstrap.ps1`** / **`tools-elevate-self.ps1`**: how elevation and Unblock work.
2. **`Bastion-Hardening.ps1`**: integrity gate and load order only.
3. **`src\Bastion.Init.ps1`**: version, section catalog, defaults.
4. The domain you care about, for example:
   - Apply / Dry Run / Audit -> `Bastion.Apply.ps1`
   - Recovery -> `Bastion.Recovery.ps1`
   - DNS / DoH -> `Bastion.Dns.ps1`
   - Browsers / ECH -> `Bastion.Browsers.ps1`
   - Menus / Help -> `Bastion.Menus.ps1`
5. Confirm **`src\MANIFEST.sha256`** matches the files you inspected (or regenerate only if you intentionally edited sources).

## Related links

- [Architecture (technical)](https://github.com/jjames06/bastion-hardening/blob/main/docs/ARCHITECTURE.md)
- [Repository README](https://github.com/jjames06/bastion-hardening#readme)
- [FAQ](FAQ)
- [Security policy](https://github.com/jjames06/bastion-hardening/blob/main/SECURITY.md)
- [Latest release](https://github.com/jjames06/bastion-hardening/releases/latest)
