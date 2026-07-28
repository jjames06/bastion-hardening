# Known issues

Public tracker: [GitHub Issues](https://github.com/jjames06/bastion-hardening/issues) ·  
**Game reports:** [Issue #18](https://github.com/jjames06/bastion-hardening/issues/18) · [Discussions #23 — Game compatibility reports](https://github.com/jjames06/bastion-hardening/discussions/23)

---

## Before you enable ExploitProtection (games notice)

**Setting:** Windows **StrictHandle** (strict handle checks), applied **system-wide** as part of Bastion’s **ExploitProtection** section (on by default / included in Quick Harden).

**What it does:** Makes Windows stricter about invalid process handles. That hardens many programs against a class of memory/handle abuse.

**Why some games can break:** A few game loaders still touch invalid handles during startup. With system StrictHandle **ON** and **no** per-app exception, the process can die immediately.

**Why World of Warcraft was hit hard:** WoW’s launch path is not a thin “double-click and go” process. The client/loader behaves like software that needs **deeper system access**—including multi-process patterns and admin/GM-style **application / game-window viewing** features that share or open handles early. Under normal Windows defaults that still works. Under **system-wide StrictHandle**, the same path can surface as **`INVALID_HANDLE`** in **`Wow_loader.dll`** and Blizzard’s **Eidolon** dialog. Battle.net (the storefront) stays fine because it is a lighter process.

This is a **compatibility trade-off**, not anti-cheat “detection” of Bastion. The fix is a **per-app exception** for `Wow.exe` (and related `Wow*.exe`), not turning StrictHandle off for the whole PC.

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

### Cause

System-wide **StrictHandle** from ExploitProtection, without a per-app exception for `Wow.exe`.

### Why that setting collided with WoW

StrictHandle treats certain invalid or recycled handle uses as fatal. WoW’s early loader (`Wow_loader.dll`) runs in a context that needs **broader handle / multi-process OS access** than many games—consistent with admin/GM-oriented **view the user’s game window** style tooling and related client services. That deeper access is legitimate for the game, but it is a poor match for a **blanket system StrictHandle** policy.

Bastion’s response: keep StrictHandle for the machine; exempt only the game EXE(s) that need it.

### Path discovery (not only default C:\ folders)

1. Battle.net Agent `product.db` / `aggregate.json`  
2. Uninstall registry  
3. Well-known folders on all fixed drives  
4. Optional `Bastion-Config.json`: `WowInstallRoots`, `StrictHandleExceptionPaths`  

### Custom config example

```json
{
  "WowInstallRoots": [ "D:\\Blizzard\\MyWoW" ],
  "StrictHandleExceptionPaths": [
    "D:\\Blizzard\\MyWoW\\_retail_\\Wow.exe",
    "E:\\Games\\SomeGame\\game.exe"
  ]
}
```

---

## Related

- README: [Known issues](../README.md#known-issues)  
- In-app: Dry Run / Apply preview notice when ExploitProtection is enabled; Help page 13  
