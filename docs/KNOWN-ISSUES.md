# Known issues

Public tracker: [GitHub Issues](https://github.com/jjames06/bastion-hardening/issues) ·  
**Game reports:** [Issue #18](https://github.com/jjames06/bastion-hardening/issues/18) · [Discussions #23 — Game compatibility reports](https://github.com/jjames06/bastion-hardening/discussions/23)

---

## Before you enable ExploitProtection (games notice)

**Setting:** Windows **StrictHandle** (strict handle checks), applied **system-wide** as part of Bastion’s **ExploitProtection** section (on by default / included in Quick Harden).

**What it does:** Makes Windows stricter about invalid process handles. That hardens many programs against a class of memory/handle abuse.

**Why some games can break:** Under default Windows policy, using a closed or recycled handle is often ignored or handled softly. With **StrictHandle ON**, the same pattern can **terminate the process**. Custom game loaders, multi-process launch (store agent → game), integrity checks, and IPC frequently use handles during early startup. That is a normal **mitigation compatibility** problem across the industry—not evidence of wrongdoing by a publisher.

| Game / client | Status (maintainer-tested) |
|---------------|----------------------------|
| **World of Warcraft** (`Wow.exe`) | **Was broken** (Eidolon / `INVALID_HANDLE` in `Wow_loader.dll`) without an exception. Bastion now **auto-excepts** discovered `Wow*.exe`. |
| **Counter-Strike 2** | **Tested — not an issue** under the same system StrictHandle profile. |
| **Other titles** | **Unknown** until someone reports them. |

**What Bastion does for you now**

1. Enables system-wide: DEP, SEHOP, BottomUp, HighEntropy, **StrictHandle**.  
2. Turns **StrictHandle OFF only** for discovered World of Warcraft `Wow*.exe` paths (full path overrides).  
3. Leaves StrictHandle **ON** for everything else.

**If a game fails after Apply**

1. **Revert** (whole PC, elevated PowerShell, then **reboot**):

   ```powershell
   Set-ProcessMitigation -System -Disable StrictHandle
   ```

   Or add the game’s full `.exe` path under `StrictHandleExceptionPaths` in `Bastion-Config.json` and re-Apply (keeps system protection).

2. Confirm the game launches again.

3. **Report it** (so we can add an automatic exception like WoW):
   - Comment on [issue #18](https://github.com/jjames06/bastion-hardening/issues/18), or  
   - Post in [Discussions #23 — Game compatibility reports](https://github.com/jjames06/bastion-hardening/discussions/23)  

   Please include: **game name**, how it fails (instant exit / dialog text), **full path to the `.exe`**, and whether the launcher (Steam/Battle.net) still works.

Do **not** assume every crash is StrictHandle—but if Battle.net/Steam works and only the game dies at start, check `_retail_\errors\…\Crash.txt` (or similar) and StrictHandle first.

---

## World of Warcraft detail — [#18](https://github.com/jjames06/bastion-hardening/issues/18)

### Symptoms (without exception)

- Battle.net UI works.  
- **Play** or direct `Wow.exe` → Blizzard **Eidolon**.  
- Crash.txt:

```text
<BlizzardError.Summary:>
INVALID_HANDLE
```

Stack typically includes **`Wow_loader.dll`** and `ntdll.dll` very early.

### Cause (what we know)

System-wide **StrictHandle** from ExploitProtection, without a per-app exception for `Wow.exe`. Disabling StrictHandle for that EXE (or system-wide) restored launch. That is the verified causal chain.

### How we describe it (and what we do *not* claim)

**Accurate technical framing:**

- StrictHandle changes Windows behavior so certain invalid handle uses are fatal.  
- WoW’s **early load path** (`Wow_loader.dll`) triggers that under a system-wide policy.  
- Battle.net is a separate, lighter process and was unaffected.  
- **Plausible, ordinary explanations** (not mutually exclusive, not proven in reverse-engineering detail) include:
  - custom loader behavior  
  - **Agent → game** process handoff and inherited/temporary handles  
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
    "E:\\Games\\SomeOtherTitle\\game.exe"
  ]
}
```

Re-run Bastion (load config) and **Apply** with ExploitProtection enabled. Paths must exist on disk when loaded.

### If you install WoW after Apply

Re-Apply so discovery runs again (metadata + folders).

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

## `ms-gamingoverlay` / “Get an app to open this link” when launching games

**Symptom:** A Windows dialog: *Get an app to open this `ms-gamingoverlay` link* (or similar) when starting Steam/Battle.net games.

**Cause (typical after Xbox cleanup):**

| Piece | State |
|-------|--------|
| Games | Still try to open **Xbox Game Bar** via the `ms-gamingoverlay:` protocol |
| **Game DVR** | Still **enabled** in the user profile (`GameDVR_Enabled = 1`) |
| **Xbox Gaming Overlay** package | Missing (removed via BloatApps or never installed) |
| Xbox services | Often disabled if **XboxGaming** was applied |

This is **not** a mysterious service “failing to start.” It is a **protocol open with no handler app**.

**What Bastion does now**

- **XboxGaming** Apply: disables Xbox services **and** silences Game DVR / Game Bar capture flags so games stop prompting.  
- **BloatApps** when Xbox Gaming Overlay is removed (or already gone): same Game DVR silence.  
- **Recovery → 6 Game Bar / ms-gamingoverlay prompt**: silence or re-enable Game DVR flags.

**Manual silence (current user):**

```powershell
Set-ItemProperty "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Value 0 -Type DWord -Force
New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Value 0 -Type DWord -Force
```

(Admin Apply also sets `HKLM\...\Policies\Microsoft\Windows\GameDVR\AllowGameDVR = 0`.)

**If you want Game Bar back:** Recovery → 6 → re-enable flags, then install **Xbox Game Bar** from Microsoft Store (`Microsoft.XboxGamingOverlay`).

### Related

- Section docs: **XboxGaming**, **BloatApps**

---

## Remote Desktop / Remote Assistance / WinRM blocked after Firewall Apply

**Symptom:** Cannot RDP into the PC, cannot use Remote Assistance, or WinRM / PowerShell remoting fails after Bastion Firewall Apply.

**Cause (by design):** Firewall Apply disables inbound rule groups for **Remote Desktop**, **Remote Assistance**, and **Windows Remote Management** (plus file sharing / discovery / mDNS). Profile defaults stay **Inbound=Block**. That is intentional exposure reduction for a single-user workstation.

**What Bastion does *not* do on Firewall Apply:** It does not rewrite `fDenyTSConnections` or force-stop **TermService**. Those are optional system RDP controls under Recovery.

**Recovery (preferred):** Main menu **9 → 7 Remote access (RDP / Assistance / WinRM)**

| Need | Action |
|------|--------|
| Temporary help session | Open **Remote Assistance** only; lock again when done |
| Host RDP again | Remote Desktop: enable firewall group **and** allow system RDP (`fDenyTSConnections=0` + start TermService). Full host RDP usually needs both. |
| PowerShell remoting / WinRM | Open **Windows Remote Management** only if you truly need it |
| Return to Bastion posture | **Lock all three** firewall groups (option 5). Optionally deny system RDP. |

**Honest limits**

- Opening remote paths **increases attack surface**. Prefer locked when idle.  
- Windows **Home** often cannot host full RDP the way Pro/Enterprise can.  
- File and Printer Sharing / Network Discovery / mDNS are **not** on this submenu (use Undo or `wf.msc`).  
- System Restore remains the strongest full rollback.

### Related

- Section docs: **Firewall**  
- In-app Help page 11 (Recovery)  

