# Games and StrictHandle

## Short version

**ExploitProtection** turns **system-wide StrictHandle** ON (stricter process handle checks). That hardens most software. **Some programs can fail to start** until they have a per-app exception.

| Program | Status |
|---------|--------|
| **World of Warcraft** | Documented **example** that broke under system StrictHandle. Bastion **auto-excepts** discovered `Wow*.exe` when found. |
| **Counter-Strike 2** | Maintainer-tested - **not** an issue under the same profile. |
| **Other titles** | **Unknown.** No Bastion exception means they **may still break** until reported and we ship one. |

WoW is **not** the only possible break. It is the case we fully documented and automated.

## If a program breaks after Apply

1. **Recovery (preferred):** main menu **9 → 6 Security mitigations → StrictHandle → disable system StrictHandle**, then **reboot**.  
   Or keep system protection: add the full `.exe` path under `StrictHandleExceptionPaths` in `Bastion-Config.json`, then refresh exceptions / re-Apply.  
2. **Confirm** the program works again.  
3. **Report** so we can add an automatic exception:  
   - [Issue #18](https://github.com/jjames06/bastion-hardening/issues/18)  
   - [Discussions #23 - Game compatibility reports](https://github.com/jjames06/bastion-hardening/discussions/23)  
   Include: **name**, how it fails, **full path to the `.exe`**, whether the launcher still works.  
4. **Until that exception ships in Bastion**, keep system StrictHandle **off** (or keep your manual path exception).  
5. After a Bastion update includes your exception: **re-Apply** or Recovery **→ 6 →** re-enable system StrictHandle + refresh exceptions.

Prefer Recovery over guessing PowerShell so Bastion status stays honest. Manual whole-PC off (elevated, then reboot):

```powershell
Set-ProcessMitigation -System -Disable StrictHandle
```

## What Bastion does on Apply

1. Enables system-wide mild mitigations including **StrictHandle**.  
2. Turns StrictHandle **OFF only** for **known exception EXEs** (discovered `Wow*.exe` plus any full paths in `StrictHandleExceptionPaths`).  
3. Leaves StrictHandle **ON** for everything else.

## Where you see this guidance in-product

- **Dry Run** and **Apply** (shared clear reverse steps)  
- **Recovery → 6 → StrictHandle** (live status + disable / refresh / re-enable)  
- In-app Help pages **11** and **13**  
- [docs/KNOWN-ISSUES.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/KNOWN-ISSUES.md)  

## Technical framing (honest)

StrictHandle can make certain invalid or short-lived handle uses **fatal**. Some game loaders and multi-process clients do that during early startup and are fine under default Windows policy. That is a **mitigation compatibility** class of issue across the industry - not an accusation about any publisher's product intent.

Next: [Recovery cookbook](Recovery-cookbook) · [FAQ](FAQ) · [Home](Home)
