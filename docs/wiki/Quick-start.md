# Quick start

Short path from download to a careful first Apply. Full install detail: [README](https://github.com/jjames06/bastion-hardening#how-to-install-properly).

## 1. Download the right build

1. Open **https://github.com/jjames06/bastion-hardening/releases/latest**  
2. Download **`bastion-hardening-v*.zip`** (current Latest is documented in [Discussions #17](https://github.com/jjames06/bastion-hardening/discussions/17))  
3. Extract to a folder **you** control (for example `C:\Tools\Bastion`)  
4. Confirm these files sit together: `Bastion-Hardening.bat`, `Bastion-Hardening.ps1` (optional: `Bastion-Banner.utf8.txt`, `docs\`)

**Do not** double-click the `.ps1`. Use the batch launcher.

## 2. Run elevated

1. Right-click **`Bastion-Hardening.bat`**  
2. **Run as administrator**  
3. Accept UAC  

On first elevated launch Bastion creates a **data directory** (path shown on the main menu) for logs and preferences. It does **not** invent Apply history until you actually Apply. Detail: [docs/DATA-DIRECTORY.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/DATA-DIRECTORY.md).

## 3. Safety net

Main menu **13** or **R** → create a **named System Restore Point**.

If you are not comfortable with restore points and Recovery, **stop here** and do not Apply.

## 4. Preview, then harden

| Step | Menu | Why |
|------|------|-----|
| Dry Run | **1** | Would change vs Already OK — no system changes |
| Security audit | **2** | Optional posture sample |
| Sections | **4** | Enable only what you understand; leave risky options off until ready |
| DNS (optional) | **D** | Public resolver or leave DNS unchanged |
| Browsers (optional) | **6** | Only installed Firefox/Chrome/Brave; ECH is **never** default |
| Quick Harden or Apply | **7** or **8** | Restore-point gate, then type **YES** |

## 5. After Apply

- Reboot if LSA Protection or optional features require it.  
- Dry Run again to confirm calm **Already OK** lines.  
- If something broke: [Recovery cookbook](Recovery-cookbook) — do **not** guess random PowerShell first.

## Honest expectations

- Bastion makes **real** system changes (firewall, services, registry, Defender, optional AppX, and more).  
- Print Spooler, discovery, RDP/WinRM, Xbox, Widgets, OneDrive, and some games can be affected.  
- **Not** for work, school, domain-joined, or MDM-managed devices.  
- **Not** an antivirus.  
- **License:** GNU **GPLv3** (`LICENSE` + `NOTICE` in the zip). Free software; if you distribute a modified Bastion, it must stay GPLv3 with source. See [FAQ](FAQ).

Next: [Recovery cookbook](Recovery-cookbook) · [Games and StrictHandle](Games-and-StrictHandle) · [FAQ](FAQ)
