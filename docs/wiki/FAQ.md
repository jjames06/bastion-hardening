# FAQ

## Is Bastion antivirus?

**No.** It reduces exposure and improves visibility (firewall posture, services, optional Defender settings, logging). It does **not** claim complete malware prevention.

## Can I use this on a work or school PC?

**No.** Intended only for a **personal** PC you fully control. Not for domain-joined, Intune/MDM-managed, work, or school devices.

## What Windows versions are supported?

**Windows 10/11**, 64-bit, run as Administrator. Maintainer-tested on a personal Windows 11 Pro daily driver; other builds may work — report results in [Discussions](https://github.com/jjames06/bastion-hardening/discussions).

## Which file do I download?

Always: **https://github.com/jjames06/bastion-hardening/releases/latest**  
See [Discussions #17](https://github.com/jjames06/bastion-hardening/discussions/17). Prefer the release zip over random re-uploads.

## Where does Bastion store files?

A **data directory** shown on the main menu (prefer durable paths such as `C:\Temp\Bastion`; not wipe-prone `%TEMP%` when possible). Logs, config, session snapshots, and Apply undo data live there.  
Full inventory: [docs/DATA-DIRECTORY.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/DATA-DIRECTORY.md).

Deleting that folder does **not** un-harden Windows or remove browser enterprise policies.

## Does Bastion enable Encrypted Client Hello (ECH) by default?

**Never.** ECH is a separate Yes/No under browser **Strict** for installed Firefox/Chrome/Brave only. Detail: [docs/BROWSER-POLICIES-AND-ECH.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/BROWSER-POLICIES-AND-ECH.md).

## How do I undo changes?

| Goal | Path |
|------|------|
| Targeted fix | Main menu **9** Recovery hubs — [Recovery cookbook](Recovery-cookbook) |
| Last Apply tracked services/firewall | Recovery **→ 1** Undo (partial by design) |
| Browser policies | Menu **6** or Recovery **→ 4** → that browser → **Default** |
| Full rollback | System Restore (menu **13** / **R**, or Safe Mode) |

## My game broke after Apply. Is Bastion broken?

Not necessarily. **StrictHandle** can break some programs that do not yet have an exception. **World of Warcraft** is a documented example (now auto-excepted). **Other titles may still break.**  
Follow [Games and StrictHandle](Games-and-StrictHandle): reverse → reboot → report full `.exe` path → wait for a shipped exception.

## Printing stopped

Recovery **→ 2 Services →** Print Spooler (or High-risk services). Spooler is disabled by design when HighRiskServices runs unless you opted to keep it in Quick Harden.

## Cannot RDP or use remote tools

Firewall Apply locks remote groups on purpose. Recovery **→ 3 Network →** Remote access. Opening remote paths increases attack surface — lock again when idle.

## Will Undo put everything back?

**No.** Undo only restores tracked services and firewall groups from `Bastion-LastApply.json` when present. It does not reinstall Appx/OneDrive, does not restore prior DNS, and does not clear browser enterprise policies.

## Where do I get help?

- In-app Help: menu **11**  
- This wiki  
- [Discussions](https://github.com/jjames06/bastion-hardening/discussions)  
- Bugs: [Issues](https://github.com/jjames06/bastion-hardening/issues)  
- Security: [SECURITY.md](https://github.com/jjames06/bastion-hardening/blob/main/SECURITY.md) (do not post full exploit details publicly for new vulns)

## What license is Bastion under?

**GNU GPLv3** (see [LICENSE](https://github.com/jjames06/bastion-hardening/blob/main/LICENSE) and [NOTICE](https://github.com/jjames06/bastion-hardening/blob/main/NOTICE)).

| Allowed | Required if you distribute a modified Bastion |
|---------|-----------------------------------------------|
| Use, study, modify | Keep the distribution under **GPLv3** |
| Share and even sell **GPL-compliant** copies that include source | Provide the **complete corresponding source code** for what you ship |

**Honest limit:** GPLv3 does **not** ban selling software. It bans taking Bastion, making closed proprietary changes, and selling that **without** releasing source under GPLv3. Closed proprietary forks of Bastion are not allowed for distributed modified works.

Older release zips that still contain an MIT `LICENSE` file remain under the terms in those artifacts. Current `main` and **v15.7+** use GPLv3.

## Can I contribute?

Yes - clear bug reports, game exception reports (name + full `.exe` path), documentation fixes, and pull requests are welcome on a best-effort basis. Contributions are accepted under the same GPLv3 terms.

Back to [Home](Home).
