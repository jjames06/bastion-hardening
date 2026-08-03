# Recovery cookbook

Main menu **9 Recovery / fix** opens a set of **modular hubs**. When you know what broke, use the matching hub instead of a full **Undo**. For the recommended pre-Apply path (right build, restore point, Dry Run, section defaults), see [Hardening workflow](Hardening-workflow).

## Hub map

| Menu | Hub | When to use it |
|------|-----|----------------|
| **1** | Undo last hardening | Best-effort restore of **tracked** services, firewall groups, **encrypted DNS snapshot** (when present), and **RDP host prior** (when RdpHostLock was applied) |
| **2** | Services | Printing stopped; you need file-share host, discovery helpers, or Xbox services again |
| **3** | Network | RDP, Remote Assistance, or WinRM; LAN sharing, discovery, or mDNS; DNS reset to DHCP; **restore prior DNS** from last Apply snapshot when available |
| **4** | Browser policies | Sites break after Strict or ECH settings; set that browser back to **Default** |
| **5** | Apps and UI | Copilot or M365, Widgets or Suggestions, Game Bar or the ms-gamingoverlay prompt |
| **6** | Security mitigations | StrictHandle and games, Defender NP/CFA, Delivery Optimization, PowerShell logging, LSA, CEIP tasks |

**Note:** Appx bloat and OneDrive removal are **not** reinstalled from Recovery. Use System Restore or the vendor/Store installers.

## Symptom to action

| Symptom | Go to | What to do |
|---------|-------|------------|
| Cannot print | **9 → 2 →** Print Spooler | Re-enable Spooler as Automatic and start it |
| Cannot host or reach Windows shares | **9 → 3 →** LAN/discovery **and** **9 → 2** Services | Open File and Printer Sharing if needed; re-enable `LanmanServer` if it is disabled |
| Cannot RDP / Remote Assistance / WinRM | **9 → 3 →** Remote access | Enable the firewall group you need; for a full RDP host also allow system RDP and TermService. Lock remote access again when you are idle |
| Name resolution wrong after Bastion DNS | **9 → 3 →** Reset DNS **or** Restore prior DNS | Option **3** resets eligible adapters to automatic (DHCP). Option **4** restores the encrypted pre-Apply snapshot when present (best-effort). Menu **D** intent is unchanged; the next DNS Apply may set public DNS again. A VPN may override DNS while connected |
| Browser sites broken after policies | **9 → 4** or main **6** | Set that browser to **Default** (best-effort). System Restore remains the surest rollback |
| ms-gamingoverlay "get an app" dialog | **9 → 5 →** Game Bar | Silence Game DVR (or re-enable flags and install Xbox Game Bar from the Store) |
| Game or program fails after Apply (instant exit) | **9 → 6 →** StrictHandle | See [Games and StrictHandle](Games-and-StrictHandle) |
| Controlled Folder Access blocks a trusted app | **9 → 6 →** Defender | Prefer allow-listing the app or re-hardening carefully; soften protection only if needed |
| Need Widgets or suggestions back | **9 → 5** | Restore Widgets/Suggestions defaults |
| Need Copilot UI tools | **9 → 5 →** Copilot / M365 | Status plus policy and Appx helpers |

## Honesty rules

- **OPEN** firewall groups and **enabled** high-risk services **increase** attack surface. Prefer **LOCKED** or disabled when you do not need them.  
- Firewall hubs toggle **named groups**; they do not flip overall profile Inbound=Block by themselves.  
- Full host RDP usually needs: OPEN Remote Desktop group **plus** system allow (`fDenyTSConnections`) **plus** TermService. Windows **Home** may not host RDP the way Pro does.  
- **Undo** restores tracked services, firewall groups, encrypted DNS snapshot (when saved), and RDP host prior (when RdpHostLock ran). It does not reinstall Appx or OneDrive, and does not clear browser enterprise policies (use browser **Default** for policies).  
- DNS snapshot and RDP host prior are stored with **Windows DPAPI** (CurrentUser of the elevating account) plus a tight file ACL. A full compromise of that account can still decrypt. Missing or foreign-user blobs cannot be restored.  
- **Two different "encrypted" ideas:** (1) Bastion **DPAPI** protects the snapshot file on disk. (2) Windows Settings **Encrypted** on DNS servers means **DNS-over-HTTPS (DoH)** on the network. From **v15.8.4**, Apply/restore writes the same per-interface DoH path Settings Edit DNS uses so known resolvers (Quad9, Cloudflare, Google, OpenDNS) should show **Encrypted** without a manual Settings click. **Verified path:** Apply a DoH provider (menu **D** then **A**, or main **8**) -> Settings shows Encrypted -> Network option **4** restores the prior snapshot and keeps Encrypted for known resolvers. Older snapshots that only stored IP addresses still restore IPs; DoH is re-applied from known templates when possible.  
- Optional **RdpHostLock** (off by default) denies the OS RDP host switch on Apply; Recovery Remote access can reverse it.  
- System Restore (menu **13** / **R**, or Safe Mode then `rstrui.exe`) remains the strongest full rollback.

For live paths on your machine, open in-app Help (main menu **11**). For more detail in the repository, see [KNOWN-ISSUES.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/KNOWN-ISSUES.md). You can also use the site [Help](https://www.operationlockedin.com/bastion/help) page from another device.
