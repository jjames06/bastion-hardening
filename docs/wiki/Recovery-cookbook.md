# Recovery cookbook

Main menu **9 Recovery / fix** is one entry with **modular hubs**. Prefer a hub over full **Undo** when you know what broke.

## Hub map

| Menu | Hub | Use when |
|------|-----|----------|
| **1** | Undo last hardening | You want best-effort restore of **tracked** services/firewall groups from the last Apply only |
| **2** | Services | Printing stopped; need file share host, discovery helpers, or Xbox services again |
| **3** | Network | RDP / Assistance / WinRM; LAN sharing/discovery/mDNS; DNS reset to automatic |
| **4** | Browser policies | Sites broken after Strict/ECH — set that browser to **Default** |
| **5** | Apps and UI | Copilot/M365, Widgets/Suggestions, Game Bar / ms-gamingoverlay prompt |
| **6** | Security mitigations | StrictHandle / games, Defender NP/CFA, Delivery Optimization, PowerShell logging, LSA, CEIP tasks |

**Note:** Appx bloat and OneDrive removal are **not** reinstalled from Recovery — use System Restore or vendor/Store installers.

## Symptom → action

| Symptom | Go to | What to do |
|---------|-------|------------|
| Cannot print | **9 → 2 →** Print Spooler | Re-enable Spooler as Automatic and start it |
| Cannot host or reach Windows shares | **9 → 3 →** LAN/discovery **and** **9 → 2** Services | Open File and Printer Sharing if needed; re-enable `LanmanServer` if disabled |
| Cannot RDP / Remote Assistance / WinRM | **9 → 3 →** Remote access | Enable the firewall group you need; for full RDP host also allow system RDP + TermService. Prefer lock when idle |
| Name resolution wrong after Bastion DNS | **9 → 3 →** Reset DNS | Resets eligible adapters to automatic (DHCP). Menu **D** intent is unchanged; next DNS Apply may set public DNS again. VPN may override while connected |
| Browser sites broken after policies | **9 → 4** or main **6** | That browser → **Default** (best-effort). System Restore is bulletproof |
| ms-gamingoverlay “get an app” dialog | **9 → 5 →** Game Bar | Silence Game DVR (or re-enable flags and install Xbox Game Bar from Store) |
| Game / program fails after Apply (instant exit) | **9 → 6 →** StrictHandle | See [Games and StrictHandle](Games-and-StrictHandle) |
| Controlled Folder Access blocks a trusted app | **9 → 6 →** Defender | Prefer allow-list/re-harden carefully; soften only if needed |
| Need Widgets / suggestions back | **9 → 5** | Restore Widgets/Suggestions defaults |
| Need Copilot UI tools | **9 → 5 →** Copilot / M365 | Status + policy/Appx helpers |

## Honesty rules

- **OPEN** firewall groups and **enabled** high-risk services **increase** attack surface. Prefer **LOCKED** / disabled when you do not need them.  
- Firewall hubs toggle **named groups**; they do not flip overall profile Inbound=Block by themselves.  
- Full host RDP usually needs: OPEN Remote Desktop group **+** system allow (`fDenyTSConnections`) **+** TermService. Windows **Home** may not host RDP like Pro.  
- **Undo** does not restore prior DNS servers, does not reinstall Appx/OneDrive, and does not clear browser enterprise policies (use browser **Default**).  
- System Restore (menu **13** / **R**, or Safe Mode → `rstrui.exe`) remains the strongest full rollback.

In-app detail: Help page **11**. Repo detail: [KNOWN-ISSUES.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/KNOWN-ISSUES.md).
