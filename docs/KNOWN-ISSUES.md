# Known issues

Public tracker: [GitHub Issues](https://github.com/jjames06/bastion-hardening/issues)

---

## World of Warcraft / Eidolon `INVALID_HANDLE` vs StrictHandle — [#18](https://github.com/jjames06/bastion-hardening/issues/18)

**Status:** Handled in current Bastion with **broad path discovery**.

| Layer | Behavior |
|-------|----------|
| **System** | StrictHandle **ON** (protect most processes) |
| **Exceptions** | StrictHandle **OFF** for discovered `Wow*.exe` under resolved WoW install roots |

### How Bastion finds WoW on different PCs

Discovery is a **union** of:

1. **Battle.net Agent metadata** — `%ProgramData%\Battle.net\Agent\product.db`, `.product.db`, `aggregate.json` (and nested copies). These store real install paths Battle.net knows about, including custom drives/folders.  
2. **Windows uninstall registry** — InstallLocation / DisplayIcon for Blizzard / World of Warcraft entries.  
3. **Well-known folders** on every **fixed** drive letter, e.g. `X:\World of Warcraft`, `X:\Games\World of Warcraft`, Program Files variants.  
4. **Optional config overrides** in `Bastion-Config.json` (under the Bastion data directory):
   - `WowInstallRoots`: array of install **folders**  
   - `StrictHandleExceptionPaths`: array of full **`.exe` paths** (any game you want excepted)

Under each root, Bastion scans product subfolders only (`_retail_`, classic/PTR variants, `UTILS`, etc.) — not the huge `Data\` tree.

### Custom layout example (`Bastion-Config.json` fragment)

```json
{
  "WowInstallRoots": [
    "D:\\Blizzard\\MyWoW"
  ],
  "StrictHandleExceptionPaths": [
    "D:\\Blizzard\\MyWoW\\_retail_\\Wow.exe",
    "E:\\Games\\SomeOtherTitle\\game.exe"
  ]
}
```

Re-run Bastion (load config) and **Apply** with ExploitProtection enabled. Paths must exist on disk when loaded.

### If you install WoW after Apply

Re-Apply so discovery runs again (metadata + folders).

### Symptoms when unmitigated (older Applies / missed path)

- Battle.net works; **Play** / direct `Wow.exe` → **Eidolon**.  
- Crash.txt: **`INVALID_HANDLE`**, stack through **`Wow_loader.dll`**.

### Emergency (disables StrictHandle for the whole PC)

```powershell
Set-ProcessMitigation -System -Disable StrictHandle
```

Then reboot.

### Reporting other games

Comment on [issue #18](https://github.com/jjames06/bastion-hardening/issues/18) with game name, fail mode, and full EXE path so we can extend the same exception pattern.

### Related

- Section docs: **ExploitProtection**  
- README: [Known issues](../README.md#known-issues)  
