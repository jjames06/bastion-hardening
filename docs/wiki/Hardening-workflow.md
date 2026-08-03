# Hardening workflow

Ordered path from a clean download to a careful first Apply, then verify and recover if needed. This is the full checklist. For a shorter path, see [Quick start](Quick-start).

**Official:** [Download](https://www.operationlockedin.com/bastion/download) · [Help](https://www.operationlockedin.com/bastion/help) · [This guide on the site](https://www.operationlockedin.com/bastion/docs/hardening-workflow)

## 1. What this guide is / is not

| This guide is | This guide is not |
|---------------|-------------------|
| A **user handbook** for **Bastion v15.9.7** modular builds on a **personal** Windows 10/11 PC you administer | A substitute for reading Dry Run lines and in-app Help (menu **11**) on *your* machine |
| An ordered workflow: right build, safety gates, first Apply, verify, fix side effects | A promise that every app, game, printer, or network setup will keep working after hardening |
| Honest about section defaults, side effects, and partial Undo | Antivirus, enterprise MDM/Intune guidance, or a "debloat everything" script |
| Links into Recovery, StrictHandle, FAQ, and modular source review | A place to invent features that are not in the product |

Bastion measures posture, lets you choose sections, applies with logging and limited undo, and offers Recovery hubs. It does **not** make a PC unhackable.

## 2. Prerequisites checklist

Confirm all of these before you download or Apply:

- [ ] **Personal PC only** - not work, school, domain-joined, or Intune/MDM-managed
- [ ] **Windows 10 or 11**, 64-bit, with an account that can run elevated
- [ ] You can create a **System Restore Point** and are willing to use it if something goes wrong
- [ ] You understand Apply makes **real** changes (firewall, services, registry, Defender, optional AppX/DNS, and more)
- [ ] Official download only (site or GitHub Latest) - not random re-uploads from chat or third parties
- [ ] You will use **`Bastion-Hardening.bat` as administrator**, never double-click the `.ps1` alone under Restricted ExecutionPolicy
- [ ] Optional but smart: a second device (phone/tablet) open on [Bastion Help](https://www.operationlockedin.com/bastion/help) while you work

If you are not comfortable with restore points and Recovery, **do not run Apply**.

## 3. Get the right build (v15.9.7 modular, Unblock, bat only)

1. Open **https://www.operationlockedin.com/bastion/download** (resolves the same GitHub Latest zip) **or** **https://github.com/jjames06/bastion-hardening/releases/latest**.
2. Prefer **v15.9.7** modular: plain-text `src\` modules, thin bootstrap, `MANIFEST.sha256` integrity, forced black console theme, Help colors for dark UI. That is the public recommended build.
3. Download **`bastion-hardening-v*.zip`** (Latest should match **v15.9.7** when that tag is current).
4. **Unblock the zip** before extract: right-click zip -> **Properties** -> check **Unblock** if shown -> **OK**. Skipping this often causes *running scripts is disabled on this system*.
5. Extract to a path **you** control (for example `C:\Tools\`). Expect one folder such as `bastion-hardening-v15.9.7\`.
6. Confirm the product tree: `Bastion-Hardening.bat`, `Bastion-Hardening.ps1`, full **`src\`** (and usually docs). Keep them together.
7. Right-click **`Bastion-Hardening.bat`** -> **Run as administrator** -> accept UAC.

You do **not** assemble modules by hand. Official zips already contain bootstrap + `src\`. Source is never encrypted; DPAPI is only for Apply undo data (DNS snapshot / RDP host prior). Optional packaging detail: [Modular source layout](Modular-source).

## 4. Safety gates before Apply

Do these before any path that changes Windows (main menu **7** Quick Harden or **8** Apply):

1. **Read the main menu banner** - note the Bastion **data directory** path (logs, config, undo after Apply live there).
2. **Create a System Restore Point** - main menu **13** or **R**. This is the strongest full rollback.
3. **Dry Run first** - main menu **1**. Shows Would change vs Already OK. Makes **no** system changes.
4. **Optional Security Audit** - main menu **2**. Posture sample only; not a hardening pass.
5. **Review sections** - main menu **4**. Enable only what you understand. Leave risky opt-ins off until you are ready (see section 6).
6. **Gates on Apply / Quick Harden** - Bastion checks restore coverage (or asks you to create / continue with explicit **YES**), then requires you to type **YES** to confirm.

There is no silent bulk harden. If you cancel at the restore gate or skip YES, nothing from that Apply path should run.

## 5. Recommended ordered first workflow

Use this order the first time on a machine:

1. Download **v15.9.7** modular, **Unblock** the zip, extract, run **`Bastion-Hardening.bat` as administrator**.
2. Create a **System Restore Point** (**13** / **R**).
3. Open **Help** (**11**) for live paths and section docs if anything is unclear.
4. Run **Dry Run** (**1**). Read Would change lines; do not Apply yet if surprises appear.
5. Optional: **Security Audit** (**2**).
6. Open **Sections** (**4**). For a careful first pass, leave **BloatApps**, **XboxGaming**, **BrowserPolicies**, **Suggestions**, and **CopilotM365** **off**. Turn **OneDrive** **off** if you still need local OneDrive sync (product default seeds OneDrive **on** for full Apply; see section 6). Leave **RdpHostLock** **off** unless you intend to deny this PC as an RDP host.
7. Optional DNS: menu **D** only saves preference. Windows adapters change only when you press **A** on the DNS menu or run main **8** with DNS enabled. Known public resolvers get Settings-matching **DoH Encrypted** on Apply (behavior since **v15.8.4**; current builds include it).
8. Optional browsers: menu **6** can set Default / Medium / Strict for **installed** Firefox, Chrome, or Brave only. **ECH is never default** (separate Yes under Strict). The **BrowserPolicies** section can stay off for bulk Apply; menu **6** still works when you open it.
9. Choose one apply path:
   - **Quick Harden (7)** - guided safer preset (core sections; BloatApps/Xbox stay off; asks about DNS and Print Spooler), then the same Apply machinery with restore + **YES** gates; or
   - **Apply (8)** - runs whatever you enabled under sections **4** (full control, more room to over-select).
10. After Apply: reboot if LSA Protection or optional features require it, then verify (section 8).
11. If something broke: Recovery (**9**) + [Recovery cookbook](Recovery-cookbook); games: [Games and StrictHandle](Games-and-StrictHandle).

## 6. Section defaults honesty

Defaults live in product code (`DefaultSections` / Quick Harden preset). High-level honesty for a first run:

| Topic | Product honesty | First-run guidance |
|-------|-----------------|--------------------|
| **BloatApps** | **Off** by default | Leave off until you accept Appx removal (not reinstalled by Undo) |
| **XboxGaming** | **Off** by default | Leave off if you use Xbox / Game Pass features |
| **BrowserPolicies** (bulk section) | **Off** by default | Leave off for first Apply; use menu **6** only when ready |
| **Suggestions / CopilotM365** | **Off** by default | Leave off until you want those UI changes |
| **RdpHostLock** | **Off** by default | Firewall already locks the Remote Desktop **group**; host lock is optional and separate |
| **OneDrive** | Seeded **on** for full Apply defaults | Turn **off** under sections **4** if you still need OneDrive sync; Undo does **not** reinstall OneDrive |
| **ExploitProtection** | On in full defaults; **not** in Quick Harden preset | Enables system **StrictHandle**; some programs can fail until excepted - see [Games and StrictHandle](Games-and-StrictHandle) |
| **HighRiskServices / Firewall** | On in defaults and Quick Harden | Printing, discovery, RDP/WinRM paths can break; Recovery re-opens what you need |

**Quick Harden vs full Apply:**

- **Quick Harden (7)** turns on a **core preset** only: Firewall, HighRiskServices, SMBv1, DeliveryOptimization, DNS (if you opt in), Defender, PowerShellAuditing, LSAProtection, ScheduledTasks. It does **not** turn on BloatApps, Xbox, browser policies, OneDrive, ExploitProtection, Programs, Suggestions, Copilot, or RdpHostLock. It asks whether to change DNS and whether to **keep Print Spooler** for that run.
- **Apply (8)** uses **your** section toggles from menu **4** (including anything still at product defaults). That is more powerful and easier to over-select if you never review toggles.
- Neither path applies browser policies or ECH unless you configured browsers (menu **6**) and enabled the browser section for bulk Apply where required. ECH is never automatic.

In-app section docs (Help **11**) remain the live detail for each toggle.

## 7. Side effects + where to recover

Expect real tradeoffs after Apply. Prefer **Recovery hubs** (menu **9**) over random PowerShell so Bastion status and reverse paths stay accurate.

| Area | Common side effect | Where to go |
|------|--------------------|-------------|
| Printing | Print Spooler disabled with HighRiskServices | Recovery **9 → 2** Services → Spooler |
| Firewall / remote | RDP, WinRM, LAN discovery locked | Recovery **9 → 3** Network |
| DNS | Wrong resolver or need prior servers | Recovery **9 → 3** → reset DHCP or restore snapshot (**4**) |
| Games / apps exit early | System StrictHandle | [Games and StrictHandle](Games-and-StrictHandle); Recovery **9 → 6** |
| Browser sites break | Medium/Strict or ECH policies | Menu **6** or Recovery **9 → 4** → that browser → **Default** |
| OneDrive / Appx bloat | Client or packages removed | System Restore or vendor/Store installers (not Undo) |
| Full rollback | Many registry/service/Appx changes | System Restore (**13** / **R**, or Safe Mode `rstrui.exe`) |

Full symptom map: [Recovery cookbook](Recovery-cookbook). Site [Help](https://www.operationlockedin.com/bastion/help) works from a phone while you repair this PC.

## 8. Verify after Apply

1. **Reboot** if LSA Protection or optional feature changes require it (Apply/Help will call this out).
2. **Dry Run (1)** again - prefer calm **Already OK** lines for what you intended.
3. **Security Audit (2)** optional second look at posture.
4. **DNS Encrypted (DoH)** - if you applied a public Bastion resolver: open Windows **Settings > Network > Ethernet or Wi-Fi > DNS**. Preferred/Alternate for known resolvers (Quad9, Cloudflare, Google, OpenDNS) should show **Encrypted**. That Settings badge is **DoH on the wire** (supported since **v15.8.4**). It is **not** the same as Bastion DPAPI encryption of the undo snapshot on disk.
5. **Browser policy pages** (only if you used menu **6**): restart the browser, then check Firefox `about:policies`, Chrome `chrome://policy`, Brave `brave://policy`. Set **Default** for that browser if sites break.
6. Exercise daily tools: print (if you kept Spooler), games you care about, RDP only if you use it, OneDrive only if you left the client installed.

Menu **D** alone never proves DNS changed - only **A** or Apply with DNS on does.

## 9. When something breaks

1. Stay calm - prefer **Recovery** over reinstalling Windows first.
2. Open Bastion elevated with **`Bastion-Hardening.bat`** if it still starts.
3. Match the symptom in the [Recovery cookbook](Recovery-cookbook) and use hub **9**.
4. For games: disable system StrictHandle (or add a path exception), **reboot**, confirm, then report name + full `.exe` path - [Games and StrictHandle](Games-and-StrictHandle).
5. **Undo (9 → 1)** restores tracked services, firewall groups, encrypted DNS snapshot (when present), and RDP host prior (when RdpHostLock ran). It does **not** reinstall Appx/OneDrive or clear browser enterprise policies.
6. **System Restore** remains the strongest full rollback.
7. Report reproducible bugs with Windows version, Bastion version, menu path, and log lines from the data directory - [Issues](https://github.com/jjames06/bastion-hardening/issues) or [Discussions](https://github.com/jjames06/bastion-hardening/discussions). Support paths: [FAQ - Where do I get help?](FAQ#where-do-i-get-help) and [operationlockedin.com/support](https://www.operationlockedin.com/support).

## 10. Optional code review (Modular-source)

If you want to read the product before you trust Apply:

1. Confirm you are on a **v15.9.7** modular tree (bootstrap + `src\Bastion.*.ps1` + `MANIFEST.sha256`).
2. Follow [Modular source layout](Modular-source): bat/helpers -> bootstrap integrity -> `Bastion.Init.ps1` (version, defaults) -> domain modules (`Bastion.Apply.ps1`, `Bastion.Recovery.ps1`, `Bastion.Dns.ps1`, and so on).
3. Technical load order and threat notes: [docs/ARCHITECTURE.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/ARCHITECTURE.md) in the zip or repository.
4. Bastion hard-fails on missing modules or MANIFEST hash mismatch. Source stays plain text under GPLv3.

You do not need a code review to use Bastion safely if you stick to Dry Run, restore points, selective sections, and Recovery - but review is encouraged for elevated tools.

## 11. Related pages

| Page | Why |
|------|-----|
| [Home](Home) | Handbook index and safety summary |
| [Quick start](Quick-start) | Shorter install + first Apply path |
| [Recovery cookbook](Recovery-cookbook) | Symptom -> Recovery hub map |
| [Games and StrictHandle](Games-and-StrictHandle) | Game breaks, reverse, report |
| [FAQ](FAQ) | Limits, DNS Encrypted, Undo, license |
| [Modular source layout](Modular-source) | Why modular, how to review |
| [Download](https://www.operationlockedin.com/bastion/download) | Official zip |
| [Help](https://www.operationlockedin.com/bastion/help) | Phone-friendly help while repairing |
| [This guide (site)](https://www.operationlockedin.com/bastion/docs/hardening-workflow) | Same pillar after site publish |
| [Latest release](https://github.com/jjames06/bastion-hardening/releases/latest) | GitHub assets |
| [Repository README](https://github.com/jjames06/bastion-hardening#readme) | Install detail and warnings |

Back to [Home](Home).
