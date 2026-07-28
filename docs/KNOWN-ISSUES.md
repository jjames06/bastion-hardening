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
