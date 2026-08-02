# Bastion Hardening Framework wiki

**Selective, state-aware, safety-first Windows hardening for a personal PC you administer.**

This wiki is a short **user handbook** for **Bastion v15.9.7** (modular plain-text `src\` builds; source never encrypted; DPAPI only for Apply undo data; forced black console theme; Help docs color-coded for dark UI). Deeper technical detail ships **in the release zip** under `docs/` and in **in-app Help** (main menu **11**). **v15.9.7** is the public recommended build on the [official site](https://www.operationlockedin.com/bastion/download) and [GitHub Latest](https://github.com/jjames06/bastion-hardening/releases/latest). Always start with **`Bastion-Hardening.bat`** (Unblock the zip first; never double-click the `.ps1` alone).

**Source structure:** Current releases are **modular** (thin bootstrap + `src\Bastion.*.ps1` modules) so the product is easier to **read and review** than the older single large script. See [Modular source layout](Modular-source). Implementation remains plain text under GPLv3; `MANIFEST.sha256` is integrity only.

## Start here

1. [Quick start](Quick-start) - install, restore point, Dry Run, Apply  
2. [Recovery cookbook](Recovery-cookbook) - fix printing, network, games, Defender side effects  
3. [Games and StrictHandle](Games-and-StrictHandle) - what breaks, how to reverse, how to report  
4. [FAQ](FAQ) - common questions, honest limits  
5. [Modular source layout](Modular-source) - why Bastion is no longer one giant script, and how to review it

## Official links

| Link | Purpose |
|------|---------|
| [Official site](https://www.operationlockedin.com) | Product home (Operation Locked In) - Bastion pages, support, donate |
| [Download Bastion](https://www.operationlockedin.com/bastion/download) | **Recommended download** - resolves the same GitHub Latest zip |
| [Latest release](https://github.com/jjames06/bastion-hardening/releases/latest) | GitHub release assets (`bastion-hardening-v*.zip`) |
| [Repository README](https://github.com/jjames06/bastion-hardening#readme) | Install detail, screenshots, critical warnings |
| [Discussions](https://github.com/jjames06/bastion-hardening/discussions) | Testing feedback, download guide, game reports |
| [Issue #18](https://github.com/jjames06/bastion-hardening/issues/18) | StrictHandle / game exception tracking |
| [Discussions #23](https://github.com/jjames06/bastion-hardening/discussions/23) | Game compatibility reports |
| [SECURITY.md](https://github.com/jjames06/bastion-hardening/blob/main/SECURITY.md) | Vulnerability reporting |
| [LICENSE](https://github.com/jjames06/bastion-hardening/blob/main/LICENSE) / [NOTICE](https://github.com/jjames06/bastion-hardening/blob/main/NOTICE) | **GPLv3** free software terms + project disclaimer |

## What Bastion is (and is not)

| Is | Is not |
|----|--------|
| A guided toolkit for a **single personal** Windows 10/11 PC | Antivirus or a malware guarantee |
| Dry Run, selective Apply, Recovery hubs, catalog winget installs | Enterprise MDM / domain / Intune tooling |
| Honest about side effects (print, RDP, games, DNS) | Automatic GPU driver or BIOS flasher |

## Documentation map

| Need | Where |
|------|--------|
| Running Bastion right now | In-app **Help** (menu **11**) |
| Handbook / FAQ / Recovery recipes | **This wiki** |
| Data directory, ECH, known-issue detail | Release zip `docs/` ([DATA-DIRECTORY](https://github.com/jjames06/bastion-hardening/blob/main/docs/DATA-DIRECTORY.md), [BROWSER-POLICIES-AND-ECH](https://github.com/jjames06/bastion-hardening/blob/main/docs/BROWSER-POLICIES-AND-ECH.md), [KNOWN-ISSUES](https://github.com/jjames06/bastion-hardening/blob/main/docs/KNOWN-ISSUES.md)) |
| Product site / download | [operationlockedin.com](https://www.operationlockedin.com) and [Bastion download](https://www.operationlockedin.com/bastion/download) |
| What changed in a version | [Releases](https://github.com/jjames06/bastion-hardening/releases) |
| Modular vs monolith (handbook) | [Modular source layout](Modular-source) |
| Modular source map / integrity (technical) | [docs/ARCHITECTURE.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/ARCHITECTURE.md) |
| Community talk | [Discussions](https://github.com/jjames06/bastion-hardening/discussions) |

## Safety first

- Run only as **Administrator** from an official source you trust (site download or GitHub release).  
- Create a **System Restore Point** (main menu **13** / **R**) before Apply or Quick Harden.  
- When you know what broke, use **Recovery hubs** (menu **9**) before a full Undo.  
- System Restore remains the strongest full rollback.

*This handbook aims to match product behavior around **v15.8+**. Always use the [official download](https://www.operationlockedin.com/bastion/download) or [Latest release](https://github.com/jjames06/bastion-hardening/releases/latest).*

**License:** GNU **GPLv3**. Free to use and modify; distributed modified versions must stay GPLv3 with source (see FAQ).

**Source of truth:** this handbook lives in the release zip under `docs/wiki/` and is mirrored to the [GitHub Wiki](https://github.com/jjames06/bastion-hardening/wiki) when published.
