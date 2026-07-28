# Known issues

Public tracker: [GitHub Issues](https://github.com/jjames06/bastion-hardening/issues)

---

## World of Warcraft fails to start (Eidolon / `INVALID_HANDLE`) — [#18](https://github.com/jjames06/bastion-hardening/issues/18)

**Status:** Known issue. **Fix shipping** in current tree: Bastion does **not** enable system-wide **StrictHandle**, and ExploitProtection Apply best-effort **disables** StrictHandle if a prior run left it on.

### Symptoms

- Battle.net launcher works (login, library, updates).
- Clicking **Play** on World of Warcraft fails **instantly** with Blizzard **Eidolon** (*The application encountered an unexpected error*).
- Running `C:\Program Files (x86)\World of Warcraft\_retail_\Wow.exe` directly fails the same way.
- Under `_retail_\errors\<timestamp>\Crash.txt`:

```text
<BlizzardError.Summary:>
INVALID_HANDLE
```

Stack typically shows `ntdll.dll` and **`Wow_loader.dll`** very early (main thread).

### Cause

Older Bastion **ExploitProtection** (enabled by default / Quick Harden) ran:

```text
Set-ProcessMitigation -System -Enable DEP, SEHOP, BottomUp, HighEntropy, StrictHandle
```

**StrictHandle** (strict handle checks) is process-mitigation policy for the **whole system**. Some game loaders (WoW’s included) can trip invalid-handle paths and terminate immediately. That is **not** the same as firewall blocking or a corrupt Battle.net Agent install.

### What usually does *not* fix it

- Deleting only Battle.net / Agent / ProgramData and reinstalling the launcher  
- Controlled Folder Access toggles alone  
- Firewall reset alone  
- Scan and Repair of the game (files can be fine)

### Workaround (machines already affected)

1. Open **elevated** PowerShell:

```powershell
Set-ProcessMitigation -System -Disable StrictHandle
Get-ProcessMitigation -System
```

2. **Reboot** (important).  
3. Start WoW via Battle.net **Play** or direct `Wow.exe`.

Optional: also relax other mild flags if needed:

```powershell
Set-ProcessMitigation -System -Disable SEHOP,BottomUp,HighEntropy
```

(DEP is usually left enabled.)

### After updating Bastion

Re-run Apply with **ExploitProtection** enabled on a fixed build: it will apply DEP/SEHOP/BottomUp/HighEntropy only and attempt to **clear StrictHandle**.

### Related

- Section docs in-app: **ExploitProtection**  
- README: [Known issues](../README.md#known-issues)  
