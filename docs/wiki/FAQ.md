# FAQ

## Is Bastion antivirus?

**No.** It reduces exposure and improves visibility (firewall posture, services, optional Defender settings, logging). It does **not** claim complete malware prevention.

## Can I use this on a work or school PC?

**No.** Intended only for a **personal** PC you fully control. Not for domain-joined, Intune/MDM-managed, work, or school devices.

## What Windows versions are supported?

**Windows 10/11**, 64-bit, run as Administrator. Maintainer-tested on a personal Windows 11 Pro daily driver; other builds may work - report results in [Discussions](https://github.com/jjames06/bastion-hardening/discussions).

## Which file do I download?

Use either official channel (both resolve the same GitHub Latest zip). Prefer **v15.9.2** (current modular release with launch hardening; do not use older 15.9.0/15.9.1 zips if the elevated window flash-closed after UAC):

- **Official site:** https://www.operationlockedin.com/bastion/download  
- **GitHub Releases:** https://github.com/jjames06/bastion-hardening/releases/latest  

See [Discussions #17](https://github.com/jjames06/bastion-hardening/discussions/17). Avoid re-uploads from chat or third parties.

## Where is the product website?

**https://www.operationlockedin.com** - Operation Locked In studio site (Bastion product pages, download, support, donate). Bastion source and releases remain on this GitHub repository.

## Where is the code?

Implementation is plain-text PowerShell under **`src\`** (for example `Bastion.Core.ps1`, `Bastion.Apply.ps1`). `Bastion-Hardening.ps1` is a thin elevated bootstrap that dot-sources those modules and verifies **`src\MANIFEST.sha256`**. Source is **never encrypted** (GPLv3 + auditability). See [docs/ARCHITECTURE.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/ARCHITECTURE.md).

## How do I verify the download?

1. Prefer the official site or GitHub **Releases** zip for a known tag.  
2. Keep `Bastion-Hardening.ps1` next to the full **`src\`** folder from that zip.  
3. On launch, Bastion **hard-fails** if a module is missing or a SHA256 in `MANIFEST.sha256` does not match.  
4. For extra confidence, compare against the GitHub tree for that tag and/or re-hash with `Get-FileHash`.

## Where does Bastion store files?

A **data directory** shown on the main menu (prefer durable paths such as `C:\Temp\Bastion`; not wipe-prone `%TEMP%` when possible). Logs, config, session snapshots, and Apply undo data live there.  
Full inventory: [docs/DATA-DIRECTORY.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/DATA-DIRECTORY.md).

Deleting that folder does **not** un-harden Windows or remove browser enterprise policies.

## Do logs or Audit print my full user-profile paths?

**Mostly limited by design.** The main menu shows the Bastion **data directory** path (needed so you can find logs). Winget preflight and Security Audit report trusted sources **without** printing the full winget executable path under your profile. Custom install roots you choose still appear in config when you set them. When sharing logs, redact anything you do not want public.

## Why does Windows Settings still show Quad9 after I picked Cloudflare in Bastion?

**Menu D only saves a preference.** It does **not** change Windows adapters until you:

- press **A** on the DNS menu (**Apply preferred DNS to adapters now**), or  
- run main menu **8 Apply** with the DNS section enabled.

The DNS menu shows **Preferred** vs **Live Windows adapters** so you can see the difference. Recovery option **4** restores the **last Apply snapshot**, not “whatever is selected in menu D.”

## Recovery 9 → 3 → 4 restored the wrong DNS / snapshot felt stuck

**Option 4 restores the snapshot taken before the last DNS Apply**, and shows a preview of those servers before you confirm.

From **v15.8.3**, later Applies that do **not** re-capture DNS **preserve** the existing snapshot (older builds could overwrite `Bastion-LastApply.json` and drop the DNS blob when adapters already matched the provider). After upgrading, run one real DNS Apply that changes adapters (for example Quad9 → Cloudflare) so a fresh snapshot is stored, then test option **4**.

Path: main menu **9** → **3 Network** → **4** (not **3** then **4**; **3** is DHCP reset only and is not required before restore).

## Why does Windows Settings say DNS is “Unencrypted” after Bastion?

**Two different meanings of “encrypted”:**

1. **Bastion snapshot DPAPI** - prior DNS is stored encrypted **on disk** in `Bastion-LastApply.json`.  
2. **Windows Settings “Encrypted”** - **DNS-over-HTTPS (DoH)** on the wire.

All Bastion public resolvers (Quad9, Cloudflare, Cloudflare security, Google, OpenDNS) are **DoH-capable**. From **v15.8.4**, Apply writes the **same per-interface DoH keys** Settings Edit DNS uses (`DohTemplate` + `QWord DohFlags=17`, AutoUpgrade, no UDP fallback), so the **Encrypted** badge should appear **without** opening Edit DNS. **Do not change DNS** leaves Windows as-is.

**Verified path (v15.8.4):**

1. Main menu **D** → pick a DoH-capable provider (for example Cloudflare) → **A** (or main menu **8** with DNS on).  
2. Open Windows **Settings > Network > Ethernet (or Wi-Fi) > DNS**. Preferred/Alternate should show **Encrypted** (re-open the page if it was already open).  
3. Change provider again (or apply a different one), then Recovery **9 → 3 Network → 4** to restore the prior snapshot.  
4. Re-check Settings: servers match the snapshot and **Encrypted** remains for known resolvers.

Menu **D** alone still does not change Windows until Apply (**A** or main **8**).

If you are on **v15.8.1–15.8.3** and Settings still says **Unencrypted**, upgrade to **v15.8.4+** and re-Apply DNS (or Network → restore snapshot / Apply preferred). Manual fallback (old builds only): adapter → DNS → **Edit** → DNS over HTTPS → **On (automatic template)** → Fallback off → Save.

## Does Bastion enable Encrypted Client Hello (ECH) by default?

**Never.** ECH is a separate Yes/No choice under browser **Strict**, and only for installed Firefox, Chrome, or Brave. For full detail, see [docs/BROWSER-POLICIES-AND-ECH.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/BROWSER-POLICIES-AND-ECH.md).

## How do I undo changes?

| Goal | Path |
|------|------|
| Targeted fix | Main menu **9** Recovery hubs - [Recovery cookbook](Recovery-cookbook) |
| Last Apply tracked services/firewall/DNS snapshot/RDP prior | Recovery **→ 1** Undo (partial by design) |
| Prior DNS after Bastion public resolvers | Recovery **→ 3 Network → 4** Restore snapshot, or **3** DHCP reset |
| Browser policies | Menu **6** or Recovery **→ 4** → that browser → **Default** |
| Full rollback | System Restore (menu **13** / **R**, or Safe Mode) |

## My game broke after Apply. Is Bastion broken?

Not necessarily. **StrictHandle** can break some programs that do not yet have an exception. **World of Warcraft** is a documented example (now auto-excepted). **Other titles may still break.**  
Follow [Games and StrictHandle](Games-and-StrictHandle): reverse → reboot → report full `.exe` path → wait for a shipped exception.

## Printing stopped

Open Recovery **→ 2 Services →** Print Spooler (or High-risk services). The spooler is disabled by design when HighRiskServices runs, unless you chose to keep it during Quick Harden.

## Cannot RDP or use remote tools

Firewall Apply locks remote groups on purpose. Open Recovery **→ 3 Network →** Remote access. Opening remote paths increases attack surface; lock them again when you are idle.

## Will Undo put everything back?

**No.** Undo restores tracked services, firewall groups, an encrypted DNS snapshot (when a DNS Apply stored one), and RDP host prior (when RdpHostLock ran). It does not reinstall Appx/OneDrive and does not clear browser enterprise policies (use Recovery browser **Default**). DNS restore is best-effort if adapters changed.

## Where do I get help?

Use the path that matches your situation:

| Situation | Where to go |
|-----------|-------------|
| Something broke after Apply (printing, network, games, browsers) | Site [Bastion Help](https://www.operationlockedin.com/bastion/help) (works from a phone) and [Recovery cookbook](Recovery-cookbook); in-app Recovery menu **9** when Bastion still starts |
| First install path | Site [Quick start](https://www.operationlockedin.com/bastion/docs/quick-start) and [Download](https://www.operationlockedin.com/bastion/download) |
| Live paths on your machine | In-app Help (main menu **11**) |
| Reproducible bug or crash | [GitHub Issues](https://github.com/jjames06/bastion-hardening/issues) (include Windows version, Bastion version, menu path, log lines) |
| Game / StrictHandle report | [Issue #18](https://github.com/jjames06/bastion-hardening/issues/18) or [Discussions #23](https://github.com/jjames06/bastion-hardening/discussions/23) |
| General questions | [Discussions](https://github.com/jjames06/bastion-hardening/discussions) or site [Support](https://www.operationlockedin.com/support) (tagged email) |
| Security vulnerability | [SECURITY.md](https://github.com/jjames06/bastion-hardening/blob/main/SECURITY.md) (prefer private reporting; do not post full exploit details publicly for new issues) |

Handbook pages also live in this wiki and on the product site under `/bastion/docs/*`.

## What license is Bastion under?

**GNU GPLv3** (see [LICENSE](https://github.com/jjames06/bastion-hardening/blob/main/LICENSE) and [NOTICE](https://github.com/jjames06/bastion-hardening/blob/main/NOTICE)).

| Allowed | Required if you distribute a modified Bastion |
|---------|-----------------------------------------------|
| Use, study, modify | Keep the distribution under **GPLv3** |
| Share and even sell **GPL-compliant** copies that include source | Provide the **complete corresponding source code** for what you ship |

**Honest limit:** GPLv3 does **not** ban selling software. It bans taking Bastion, making closed proprietary changes, and selling that **without** releasing source under GPLv3. Closed proprietary forks of Bastion are not allowed for distributed modified works.

Older release zips that still contain an MIT `LICENSE` file remain under the terms in those artifacts. Current `main` and **v15.7+** (including **v15.8**) use GPLv3.

## Can I contribute?

Yes - clear bug reports, game exception reports (name + full `.exe` path), documentation fixes, and pull requests are welcome on a best-effort basis. Contributions are accepted under the same GPLv3 terms.

Back to [Home](Home).
