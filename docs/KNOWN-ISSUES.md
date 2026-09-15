# Known issues

Public tracker: [GitHub Issues](https://github.com/jjames06/bastion-hardening/issues) ·  
**Game reports:** [Issue #18](https://github.com/jjames06/bastion-hardening/issues/18) · [Discussions #23 - Game compatibility reports](https://github.com/jjames06/bastion-hardening/discussions/23)

---

## Before you enable ExploitProtection (StrictHandle)

**Setting:** Windows **StrictHandle** (strict handle checks), applied **system-wide** as part of Bastion **ExploitProtection** (on by default / included in Quick Harden).

**What it does:** Makes Windows stricter about invalid process handles. That hardens many programs against a class of memory/handle abuse.

**Why some programs can break:** Under default Windows policy, using a closed or recycled handle is often ignored or handled softly. With **StrictHandle ON**, the same pattern can **terminate the process**. Custom game loaders, multi-process launch (store agent to game), integrity checks, and IPC frequently use handles during early startup. That is a normal **mitigation compatibility** problem across the industry - not evidence of wrongdoing by a publisher.

| Program / client | Status (maintainer-tested) |
|---------------|----------------------------|
| **World of Warcraft** (`Wow.exe`, Classic Era `WowClassic.exe`) | **Documented example** that **was broken** (Eidolon crash reporter / `INVALID_HANDLE` in `Wow_loader.dll` or `WowClassic_loader.dll`) without an exception. Bastion now **auto-excepts** discovered `Wow*.exe`. Installing Classic after Apply does **not** inherit the retail exception - refresh / re-Apply. |
| **Counter-Strike 2** | **Tested - not an issue** under the same system StrictHandle profile. |
| **Other titles** | **Unknown.** No Bastion exception means they **may still break** until reported and we ship one. |

**What Bastion does**

1. Enables system-wide: DEP, SEHOP, BottomUp, HighEntropy, **StrictHandle**.
2. Turns **StrictHandle OFF only** for **known exception EXEs** (discovered `Wow*.exe` including `Wow.exe` and `WowClassic.exe`, plus any EXE next to a `*_loader.dll`, plus any full paths in `StrictHandleExceptionPaths`).
3. Leaves StrictHandle **ON** for everything else.

**If a program fails after Apply**

1. **Revert (preferred):** Recovery -> **6 Security mitigations** -> **StrictHandle** -> **disable system StrictHandle**, then **reboot**.
   Or keep system protection: add the full `.exe` under `StrictHandleExceptionPaths` in `Bastion-Config.json`, then refresh exceptions / re-Apply.

   Manual whole-PC off (elevated PowerShell, then reboot):

   ```powershell
   Set-ProcessMitigation -System -Disable StrictHandle
   ```

2. Confirm the program launches again.

3. **Report it** so we can add an automatic exception (same pattern as WoW):
   - [Issue #18](https://github.com/jjames06/bastion-hardening/issues/18), or
   - [Discussions #23 - Game compatibility reports](https://github.com/jjames06/bastion-hardening/discussions/23)

   Include: **name**, how it fails, **full path to the `.exe`**, and whether the launcher still works.

4. **Until that exception ships in Bastion**, keep system StrictHandle off (or keep your manual path exception). After an update includes it, re-Apply or Recovery -> 6 -> re-enable system StrictHandle + exceptions.

Do **not** assume every crash is StrictHandle, but if the launcher works and only the game dies at start, check crash logs and StrictHandle first. Use Bastion Recovery when you can so status and reverse paths stay accurate.

---

## World of Warcraft detail - [#18](https://github.com/jjames06/bastion-hardening/issues/18)

### Symptoms (without exception)

- Battle.net UI works.  
- **Play** or direct `Wow.exe` / Classic Era `WowClassic.exe` -> Blizzard **Eidolon** (that window is `BlizzardError.exe`, the crash reporter - not the process that needs the exception).  
- Crash.txt:

```text
<BlizzardError.Summary:>
INVALID_HANDLE
```

Stack typically includes **`Wow_loader.dll`** (retail) or **`WowClassic_loader.dll`** (Classic Era) and `ntdll.dll` very early.

### Cause (what we know)

System-wide **StrictHandle** from ExploitProtection, without a per-app exception for that flavor's EXE. Disabling StrictHandle for `Wow.exe` or `WowClassic.exe` (or system-wide) restored launch. That is the verified causal chain.

Retail and Classic are **separate image paths**. An exception on `_retail_\Wow.exe` does **not** cover `_classic_era_\WowClassic.exe`. If you install Classic after Apply, refresh exceptions (Recovery -> **6** -> StrictHandle -> option **2**) or re-Apply.

### How we describe it (and what we do *not* claim)

**Accurate technical framing:**

- StrictHandle changes Windows behavior so certain invalid handle uses are fatal.  
- WoW's **early load path** (`Wow_loader.dll` or Classic Era `WowClassic_loader.dll`) triggers that under a system-wide policy.  
- Battle.net is a separate, lighter process and was unaffected.  
- **Plausible, ordinary explanations** (not mutually exclusive, not proven in reverse-engineering detail) include:
  - custom loader behavior  
  - **Agent -> game** process handoff and inherited/temporary handles  
  - multi-process client architecture  
  - early integrity / anti-cheat / IPC handle use  
  - code that is fine under default Windows defaults  

**We do not claim** that this proves internal GM tooling, misconduct, or any specific Blizzard product feature. Crash dumps and policy changes alone do not support that. Documentation should stay on **mitigation compatibility**, not accusations.

### Path discovery (not only default C:\ folders)

1. Battle.net Agent `product.db` / `aggregate.json`  
2. Uninstall registry  
3. Well-known folders on all fixed drives  
4. Optional `Bastion-Config.json`: `WowInstallRoots`, `StrictHandleExceptionPaths`  

### Custom config example

```json
{
  "WowInstallRoots": [ "D:\\Games\\World of Warcraft" ],
  "StrictHandleExceptionPaths": [
    "D:\\Games\\World of Warcraft\\_retail_\\Wow.exe",
    "D:\\Games\\World of Warcraft\\_classic_era_\\WowClassic.exe",
    "D:\\Games\\World of Warcraft\\_classic_\\WowClassic.exe",
    "E:\\Games\\SomeOtherTitle\\game.exe"
  ]
}
```

Re-run Bastion (load config) and **Apply** with ExploitProtection enabled. Paths must exist on disk when loaded.

### If you install WoW or Classic after Apply

Re-Apply, or Recovery -> **6** -> StrictHandle -> **refresh known exception EXEs**, so discovery runs again (metadata + folders). Classic Era is a new `WowClassic.exe` path; it does not reuse the retail `Wow.exe` exception.

### Emergency (disables StrictHandle for the whole PC)

```powershell
Set-ProcessMitigation -System -Disable StrictHandle
```

Then reboot.

### Reporting other games

Comment on [issue #18](https://github.com/jjames06/bastion-hardening/issues/18) or [Discussions #23](https://github.com/jjames06/bastion-hardening/discussions/23) with game name, fail mode, and full EXE path so we can extend the same exception pattern.

### Related

- Section docs: **ExploitProtection**  
- README: [Known issues](../README.md#known-issues)  

---

## `ms-gamingoverlay` / "Get an app to open this link" when launching games

**Symptom:** A Windows dialog: *Get an app to open this `ms-gamingoverlay` link* (or similar) when starting Steam/Battle.net games.

**Cause (typical after Xbox cleanup):**

| Piece | State |
|-------|--------|
| Games | Still try to open **Xbox Game Bar** via the `ms-gamingoverlay:` protocol |
| **Game DVR** | Still **enabled** in the user profile (`GameDVR_Enabled = 1`) |
| **Xbox Gaming Overlay** package | Missing (removed via BloatApps or never installed) |
| Xbox services | Often disabled if **XboxGaming** was applied |

This is **not** a mysterious service "failing to start." It is a **protocol open with no handler app**.

**What Bastion does now**

- **XboxGaming** Apply: disables Xbox services **and** silences Game DVR / Game Bar capture flags so games stop prompting.  
- **BloatApps** when Xbox Gaming Overlay is removed (or already gone): same Game DVR silence.  
- **Recovery -> 6 Game Bar / ms-gamingoverlay prompt**: silence or re-enable Game DVR flags.

**Manual silence (current user):**

```powershell
Set-ItemProperty "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Value 0 -Type DWord -Force
New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Value 0 -Type DWord -Force
```

(Admin Apply also sets `HKLM\...\Policies\Microsoft\Windows\GameDVR\AllowGameDVR = 0`.)

**If you want Game Bar back:** Recovery -> **5 Apps and UI** -> Game Bar -> re-enable flags, then install **Xbox Game Bar** from Microsoft Store (`Microsoft.XboxGamingOverlay`).

### Related

- Section docs: **XboxGaming**, **BloatApps**

---

## Remote Desktop / Remote Assistance / WinRM / LAN discovery blocked after Firewall Apply

**Symptom:** Cannot RDP, Remote Assistance, WinRM, host file shares, or discover devices after Bastion Firewall Apply.

**Cause (by design):** Firewall Apply disables inbound rule groups for **Remote Desktop**, **Remote Assistance**, **Windows Remote Management**, **File and Printer Sharing**, **Network Discovery**, and **mDNS**. Profile defaults stay **Inbound=Block**.

**What Bastion does *not* do on Firewall Apply:** It does not rewrite `fDenyTSConnections` or force-stop **TermService**. Optional section **RdpHostLock** (off by default) can deny the OS RDP host on Apply; Recovery Network -> Remote access can reverse it without full Undo.

**Recovery (preferred):** Main menu **9 -> 3 Network**

| Need | Action |
|------|--------|
| RDP / Assistance / WinRM | Network -> **Remote access** (firewall groups + optional system allow / TermService) |
| File shares / discovery / mDNS | Network -> **LAN / discovery** |
| DNS back to DHCP | Network -> **Reset DNS to automatic** |
| DNS back to pre-Bastion servers | Network -> **Restore prior DNS from last Apply snapshot** (v15.8+; encrypted snapshot required) |
| Print / SMB service stack | Recovery -> **2 Services** (Spooler, LanmanServer, ...) |
| Return to Bastion posture | Lock groups again from the same hubs |

**Honest limits**

- Opening remote or LAN paths **increases attack surface**. Keep them locked when idle.  
- Windows **Home** often cannot host full RDP the way Pro/Enterprise can.  
- Hosting shares may need both **firewall OPEN** and **LanmanServer** enabled.  
- DNS snapshot restore is best-effort if adapters were renamed or removed after Apply; decrypt requires the same elevating Windows user.  
- System Restore remains the strongest full rollback.

### Related

- Section docs: **Firewall**, **HighRiskServices**  
- In-app Help page 11 (Recovery hubs)  

---

## StrictHandle / game launch failures

**Recovery (preferred):** Main menu **9 > 6 Security mitigations > StrictHandle**

- **Disable system StrictHandle** (reboot recommended) when a program without an exception fails, or
- **Refresh known exception EXEs** only (keeps system ON; helps after installing WoW or adding config paths), or
- **Re-enable** Bastion-style profile + exceptions after you can run your software again

**Honest scope:** World of Warcraft retail and Classic Era are **documented examples** with automatic exceptions (`Wow.exe`, `WowClassic.exe`). **Other programs may break** until you report them and we ship an exception. Until then, leave system StrictHandle off or use a manual `StrictHandleExceptionPaths` entry. Installing Classic after Apply needs option **2** (refresh) even if retail already had an exception.

Also see the [notice above](#before-you-enable-exploitprotection-stricthandle) and GitHub issue #18.

---

## Controlled Folder Access / Network Protection false positives

**Recovery:** Main menu **9 > 6 > Defender**: soften NP and/or CFA, or re-harden with CFA allow-path refresh. Allow a trusted app path before turning protections off permanently when you can.

---

## LanHygiene (opt-in) and home gateways

**LanHygiene is off by default** and is **not** in Quick Harden. When enabled, Apply changes **the Windows PC running Bastion only**: LLMNR off, WPAD override, mDNS off, NetBIOS-over-TCP off, common NIC power-save properties Disabled when present, optional outbound UDP 137/138/5353 rules.

Bastion **does not assume** a named ISP modem, mesh kit, or LAN IP. Apply never logs in to a modem/router and does not lock NIC speed. Gateway handling is live-fingerprint only.

**Side effects:** printers, NAS, Chromecast, and some Apple discovery can break.

**Recovery:** Main menu **9 → 3 Network → 5** removes the Bastion outbound 137/138/5353 rules only. Policies may need System Restore.

**Home gateway probe (Recovery 9 → 3 → 6):** HTTP GET of **the live IPv4 default gateway on the computer running Bastion**. Vendor JSON is offered only if that admin speaks a known JSON gateway protocol. Any other CPE: identify only. Password is never saved. Most homes will not match. See [LAN hygiene](wiki/LAN-hygiene.md).

