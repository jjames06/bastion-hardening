# Quick start

Short path from download to a careful first Apply. Full install detail: [README](https://github.com/jjames06/bastion-hardening#how-to-install-properly).

Need help while you work? Use the site [Help](https://www.operationlockedin.com/bastion/help) page from this PC or another device (phone, tablet, second computer). The [Recovery cookbook](Recovery-cookbook) covers common side effects after Apply.

## 1. Download the right build

Prefer an **official** source only:

1. **Recommended:** open **https://www.operationlockedin.com/bastion/download** (the site resolves the same GitHub Latest zip), **or** open **https://github.com/jjames06/bastion-hardening/releases/latest**  
2. Download **`bastion-hardening-v*.zip`** (current Latest is also noted in [Discussions #17](https://github.com/jjames06/bastion-hardening/discussions/17))  
3. Extract to a folder **you** control (for example `C:\Tools\Bastion`)  
4. Confirm these files sit together: `Bastion-Hardening.bat`, `Bastion-Hardening.ps1` (optional: `Bastion-Banner.utf8.txt`, `docs\`)

**Do not** double-click the `.ps1`. Start Bastion with the batch launcher.

## 2. Run elevated

1. Right-click **`Bastion-Hardening.bat`**  
2. **Run as administrator**  
3. Accept UAC  

On first elevated launch Bastion creates a **data directory** (path shown on the main menu) for logs and preferences. It does **not** invent Apply history until you actually Apply. Detail: [docs/DATA-DIRECTORY.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/DATA-DIRECTORY.md).

## 3. Safety net

Main menu **13** or **R** → create a **named System Restore Point**.

A restore point is your strongest full rollback if something goes wrong. If restore points or Recovery are new to you, read **Help** and the **Recovery cookbook** first (including from a phone or second device), then create the restore point before you Apply. You do not have to rush; Dry Run never changes the system.

## 4. Preview, then harden

| Step | Menu | Why |
|------|------|-----|
| Dry Run | **1** | Shows Would change vs Already OK with no system changes |
| Security audit | **2** | Optional posture sample |
| Sections | **4** | Enable only what you understand; leave risky options off until ready |
| DNS (optional) | **D** | Public resolver, or leave DNS unchanged |
| Browsers (optional) | **6** | Only installed Firefox/Chrome/Brave; ECH is **never** default |
| Quick Harden or Apply | **7** or **8** | Restore-point gate, then type **YES** |

## 5. After Apply

- Reboot if LSA Protection or optional features require it.  
- Run Dry Run again to confirm calm **Already OK** lines.  
- If something broke: use Bastion **Recovery** (main menu **9**) when the app still starts, and follow the [Recovery cookbook](Recovery-cookbook). The site [Help](https://www.operationlockedin.com/bastion/help) page works from another device while you repair this machine. Prefer Recovery hubs over one-off PowerShell so Bastion status and reverse paths stay accurate.

## Honest expectations

- Bastion makes **real** system changes (firewall, services, registry, Defender, optional AppX, and more).  
- Print Spooler, discovery, RDP/WinRM, Xbox, Widgets, OneDrive, and some games can be affected.  
- **Not** for work, school, domain-joined, or MDM-managed devices.  
- **Not** an antivirus.  
- **License:** GNU **GPLv3** (`LICENSE` + `NOTICE` in the zip). Free software; if you distribute a modified Bastion, it must stay GPLv3 with source. See [FAQ](FAQ).

Next: [Recovery cookbook](Recovery-cookbook) · [Games and StrictHandle](Games-and-StrictHandle) · [FAQ](FAQ) · site [Help](https://www.operationlockedin.com/bastion/help)
