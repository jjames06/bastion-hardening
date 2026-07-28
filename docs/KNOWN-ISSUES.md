# Known issues

Public tracker: [GitHub Issues](https://github.com/jjames06/bastion-hardening/issues)

---

## World of Warcraft / Eidolon `INVALID_HANDLE` vs StrictHandle — [#18](https://github.com/jjames06/bastion-hardening/issues/18)

**Status:** Understood and **handled in current Bastion**.

| Mode | Behavior |
|------|----------|
| **Current Bastion** | Enables system-wide **StrictHandle** for protection, then sets **per-app StrictHandle OFF** for discovered **`Wow*.exe`** under common World of Warcraft install paths. Rest of the system keeps StrictHandle. |
| **Older Bastion** | Enabled system StrictHandle with **no** game exceptions → WoW Play / `Wow.exe` could crash instantly. |

### Symptoms (when unmitigated)

- Battle.net works; **Play** on WoW (or direct `Wow.exe`) fails with **Eidolon**.
- `_retail_\errors\…\Crash.txt` summary: **`INVALID_HANDLE`**, stack through **`Wow_loader.dll`**.

### Why a system kill-switch is not required anymore

Windows process mitigations support:

1. **System** policy: StrictHandle **ON** (protects most processes).  
2. **Image / full path** policy: StrictHandle **OFF** for that EXE only (WoW exception).

`Wow_loader.dll` is loaded by `Wow.exe`, so the exception on the game EXE is the correct scope.

### If WoW still fails after a new Apply

1. Confirm exception paths were found (Apply log should list `StrictHandle exception (OFF for this app): …\Wow.exe`).  
2. If you installed WoW **after** Apply, **re-Apply** ExploitProtection so Bastion can discover new `Wow*.exe` paths.  
3. Manual one-off:

```powershell
Set-ProcessMitigation -Name "C:\Program Files (x86)\World of Warcraft\_retail_\Wow.exe" -Disable StrictHandle
```

(Use your real full path; reboot if needed.)

4. Emergency only (turns StrictHandle off for **everyone**):

```powershell
Set-ProcessMitigation -System -Disable StrictHandle
```

### What usually does *not* fix INVALID_HANDLE

- Wiping Battle.net / Agent alone while Crash.txt still says `INVALID_HANDLE`  
- CFA / firewall-only changes when the launcher already works  

### Related

- Section docs: **ExploitProtection**  
- README: [Known issues](../README.md#known-issues)  
