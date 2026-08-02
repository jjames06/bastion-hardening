# Quick start

This guide walks you from download to a careful first Apply. The product site [Download](https://www.operationlockedin.com/bastion/download) page uses the same path after the zip lands. For full installation detail, see the repository [README](https://github.com/jjames06/bastion-hardening#how-to-install-properly).

If you need help while you work, open the site [Help](https://www.operationlockedin.com/bastion/help) page on this PC or on another device (phone, tablet, or second computer). The [Recovery cookbook](Recovery-cookbook) covers common side effects after Apply. For email or GitHub bugs, use [Support](https://www.operationlockedin.com/support).

## 1. Download the right build

Use an **official** source only:

1. **Recommended:** open **https://www.operationlockedin.com/bastion/download** (the site resolves the same GitHub Latest zip), **or** open **https://github.com/jjames06/bastion-hardening/releases/latest**  
2. Download **`bastion-hardening-v*.zip`** (the current Latest build is also noted in [Discussions #17](https://github.com/jjames06/bastion-hardening/discussions/17))  
3. Extract the zip to a location **you** control (for example `C:\Tools\`). Official zips expand to one folder such as `bastion-hardening-v15.9.2\` with the bootstrap, `src\` modules, and docs already together.  
4. Open that folder and confirm: `Bastion-Hardening.bat`, `Bastion-Hardening.ps1` (optional: `Bastion-Banner.utf8.txt`, `docs\`)

**Do not** double-click the `.ps1` file. Start Bastion with the batch launcher.

## 2. Run elevated

1. Right-click **`Bastion-Hardening.bat`**  
2. Choose **Run as administrator**  
3. Accept the UAC prompt  

On first elevated launch, Bastion creates a **data directory** (the path appears on the main menu) for logs and preferences. It does **not** invent Apply history until you actually Apply. For more detail, see [docs/DATA-DIRECTORY.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/DATA-DIRECTORY.md).

## 3. Safety net

From the main menu, choose **13** or **R** to create a **named System Restore Point**.

A restore point is your strongest full rollback if something goes wrong. If restore points or Recovery are new to you, read **Help** and the **Recovery cookbook** first (including from a phone or second device), then create the restore point before you Apply. You do not have to rush: Dry Run never changes the system.

## 4. Preview, then harden

| Step | Menu | Why |
|------|------|-----|
| Dry Run | **1** | Shows Would change vs Already OK without making system changes |
| Security audit | **2** | Optional posture sample |
| Sections | **4** | Enable only what you understand; leave risky options off until you are ready |
| DNS (optional) | **D** | Saves preference only until **A** (Apply DNS now) or main **8**; Apply snapshots prior DNS (DPAPI) and enables DoH Encrypted for known resolvers |
| RDP host lock (optional) | Section **RdpHostLock** | Off by default; denies this PC as an RDP host (separate from firewall group lock) |
| Browsers (optional) | **6** | Applies only to installed Firefox, Chrome, or Brave; ECH is **never** enabled by default |
| Quick Harden or Apply | **7** or **8** | Restore-point gate, then type **YES** to confirm |

## 5. After Apply

- Reboot if LSA Protection or optional features require it.  
- Run Dry Run again and look for calm **Already OK** lines.  
- If something broke: use Bastion **Recovery** (main menu **9**) when the app still starts, and follow the [Recovery cookbook](Recovery-cookbook). The site [Help](https://www.operationlockedin.com/bastion/help) page works from another device while you repair this machine. Use Recovery hubs rather than one-off PowerShell so Bastion status and reverse paths stay accurate.

## Honest expectations

- Bastion makes **real** system changes (firewall, services, registry, Defender, optional AppX, and more).  
- Print Spooler, discovery, RDP/WinRM, Xbox, Widgets, OneDrive, and some games can be affected.  
- Bastion is **not** for work, school, domain-joined, or MDM-managed devices.  
- Bastion is **not** an antivirus.  
- **License:** GNU **GPLv3** (`LICENSE` and `NOTICE` in the zip). Bastion is free software; if you distribute a modified Bastion, it must remain GPLv3 with source. See the [FAQ](FAQ).

**Continue reading:** [Recovery cookbook](Recovery-cookbook) · [Games and StrictHandle](Games-and-StrictHandle) · [FAQ](FAQ) · site [Help](https://www.operationlockedin.com/bastion/help)
