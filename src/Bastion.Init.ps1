# =============================================================================
# Bastion.Init.ps1 - script-scoped state, catalogs, and section documentation
# =============================================================================
#
# PURPOSE
#   Declares all $script: state and static catalogs used by the rest of Bastion.
#   This is the first module loaded by Bastion-Hardening.ps1 so later modules
#   can read and mutate the same runspace-wide variables.
#
# LOAD ORDER / ROLE
#   Loaded first among src\Bastion.*.ps1 (see $script:BastionSourceModules).
#   Dot-sourced into the bootstrap runspace. Everything here is $script: scoped
#   so Config, Core, Apply, Recovery, Menus, etc. share one coherent state bag.
#   No functions are defined here; only assignments and catalog tables.
#
# DO NOT
#   - Run this file standalone (it will define state with no UI or Apply path).
#   - Encrypt or obfuscate this source (GPLv3; open for audit).
#   - Treat MANIFEST.sha256 as encryption; it is integrity only.
#   - Assume $script:Config.LogDirectory is final; Config module re-resolves
#     the data directory after load.
#
# SECURITY NOTES
#   - Source is plain text. Reviewers should read it freely.
#   - DPAPI (Protect-BastionBlob / Unprotect-BastionBlob in Bastion.Config.ps1)
#     protects only sensitive undo payloads (DNS snapshot, RDP host prior),
#     never this module and never the winget catalog or section docs.
#   - $script:BastionDpapiEntropy is a fixed salt for CurrentUser DPAPI; it is
#     not a secret key and does not replace OS credential isolation.
#   - Sensitive paths and install roots are validated later (Programs module);
#     blocked path fragments below are deny-list hints for custom install roots.
#
# Version string below must stay in sync with the product release version.
# =============================================================================

# -----------------------------------------------------------------------------
# Core product identity and preferred data root
# -----------------------------------------------------------------------------
# LogDirectory is the preferred NEW store root only. After modules load,
# Resolve-BastionLogDirectory may reuse a writable legacy path (flat C:\Temp)
# or fall back to ProgramData / LOCALAPPDATA / TEMP when C:\Temp is unusable.
$script:Config = @{
    ScriptVersion = "15.9.7"
    # Preferred new-store root; Resolve-BastionLogDirectory may reuse legacy C:\Temp or fall back.
    LogDirectory  = "C:\Temp\Bastion"
    # Windows Event Log source name used by Write-Log (Application log).
    EventSource   = "BastionHardening"
}

# Per-launch stamp for log file names (Bastion-Log-yyyyMMdd-HHmmss.txt).
$script:timestamp   = Get-Date -Format "yyyyMMdd-HHmmss"

# -----------------------------------------------------------------------------
# Data-store and first-run flags (bound/filled by Bastion.Config.ps1)
# -----------------------------------------------------------------------------
# Full path to Bastion-Session.json after Bind-BastionDataPaths; null until bound.
$script:sessionFile = $null

# True if Bastion-Config.json already existed when Initialize-BastionDataStore ran.
$script:HadPriorConfig  = $false

# True if Bastion-LastApply.json already existed (real Apply history, never invented).
$script:HadPriorApply   = $false

# True when this launch wrote a fresh default Bastion-Config.json (first run or wiped store).
$script:FirstRunSeeded  = $false

# True after Initialize-BastionDataStore succeeds (dirs ready, config load/seed done).
$script:DataStoreReady  = $false

# When true, Apply skips Spooler disable for this run (user chose to keep printing).
$script:SkipSpoolerThisApply = $false

# -----------------------------------------------------------------------------
# Program install queue and optional custom roots
# -----------------------------------------------------------------------------
# Catalog display names the user checked for install (must exist in ProgramDefs).
# Sync-ProgramInstallQueue drops names already present on disk.
$script:SelectedApps = [System.Collections.Generic.List[string]]::new()

# Optional shared --location root for winget installs (fixed local volume only).
$script:GlobalInstallRoot   = $null

# Per-app override install roots (key = ProgramDefs display name, value = path).
$script:ProgramInstallRoots = @{}

# -----------------------------------------------------------------------------
# Browser policy wanted state (menu 6 / Bastion-Config.json)
# Values: Default | Medium | Strict. Live OS posture is detected separately.
# -----------------------------------------------------------------------------
$script:BrowserPolicyModes  = [ordered]@{
    Firefox = "Default"
    Chrome  = "Default"
    Brave   = "Default"
}

# Encrypted Client Hello opt-in per browser. Only meaningful under Strict;
# Load-BastionConfig never infers ECH from Strict alone.
$script:BrowserEchLocks = [ordered]@{
    Firefox = $false
    Chrome  = $false
    Brave   = $false
}

# Legacy single-mode field kept for older config files; per-browser Modes win.
$script:BrowserPolicyMode   = "Default"

# Preferred public DNS catalog id (see DnsProviders). "None" turns DNS section off.
$script:DnsProviderId       = "Quad9"

# Registry value names Bastion writes under Chromium-family policy hives so
# Recovery can identify and clear only Bastion-owned policy values.
$script:ChromiumBastionValueNames = @(
    "BastionManaged",
    "BastionEchLock",
    "MetricsReportingEnabled",
    "SafeBrowsingEnabled",
    "BlockThirdPartyCookies",
    "DefaultCookiesSetting",
    "HttpsOnlyMode",
    "DnsOverHttpsMode",
    "EncryptedClientHelloEnabled"
)

# Set true by Load-BastionConfig when a file was parsed successfully.
$script:ConfigLoaded        = $false

# Human-readable failure lines accumulated during Apply for the summary screen.
$script:ApplyFailures       = [System.Collections.Generic.List[string]]::new()

# Hashtable of last browser policy menu change (timestamp, browser, modes, backup path).
# Restored from Bastion-BrowserPolicies-State.json metadata only (not wanted modes).
$script:BrowserPolicyLastChange = $null

# Extra directories searched for WoW*.exe when building StrictHandle exceptions.
$script:WowInstallRoots = [System.Collections.Generic.List[string]]::new()

# Full paths to .exe files that must have system StrictHandle turned OFF via
# Set-ProcessMitigation (user-trusted list from Bastion-Config.json).
$script:StrictHandleExceptionPaths = [System.Collections.Generic.List[string]]::new()

# -----------------------------------------------------------------------------
# DNS provider catalog (IPv4 + DoH template metadata)
# -----------------------------------------------------------------------------
# WireDoH true means Bastion will also configure Windows DoH for that resolver
# when the DNS section is applied. "None" leaves adapter DNS untouched.
$script:DnsProviders = [ordered]@{
    "Quad9" = @{
        DisplayName = "Quad9 (malware blocking)"
        Primary     = "9.9.9.9"
        Secondary   = "149.112.112.112"
        DohTemplate = "https://dns.quad9.net/dns-query"
        WireDoH     = $true
        Notes       = "Blocks known malicious domains."
    }
    "Cloudflare" = @{
        DisplayName = "Cloudflare (1.1.1.1)"
        Primary     = "1.1.1.1"
        Secondary   = "1.0.0.1"
        DohTemplate = "https://cloudflare-dns.com/dns-query"
        WireDoH     = $true
        Notes       = "Fast, privacy-focused public DNS."
    }
    "CloudflareSecurity" = @{
        DisplayName = "Cloudflare security (malware block)"
        Primary     = "1.1.1.2"
        Secondary   = "1.0.0.2"
        DohTemplate = "https://security.cloudflare-dns.com/dns-query"
        WireDoH     = $true
        Notes       = "Cloudflare malware-blocking DNS."
    }
    "Google" = @{
        DisplayName = "Google Public DNS"
        Primary     = "8.8.8.8"
        Secondary   = "8.8.4.4"
        DohTemplate = "https://dns.google/dns-query"
        WireDoH     = $true
        Notes       = "Highly available public DNS."
    }
    "OpenDNS" = @{
        DisplayName = "Cisco OpenDNS"
        Primary     = "208.67.222.222"
        Secondary   = "208.67.220.220"
        DohTemplate = "https://doh.opendns.com/dns-query"
        WireDoH     = $true
        Notes       = "Cisco OpenDNS public resolvers."
    }
    "None" = @{
        DisplayName = "Do not change DNS"
        Primary     = $null
        Secondary   = $null
        DohTemplate = $null
        WireDoH     = $false
        Notes       = "Leave adapter DNS as-is (DHCP/manual). Disables the DNS hardening section."
    }
}

# Maps well-known resolver IPs to DoH templates so live adapter DNS can be
# labeled Encrypted / matched even when the user did not pick a Bastion provider id.
$script:DnsKnownDohTemplates = [ordered]@{
    "9.9.9.9"           = "https://dns.quad9.net/dns-query"
    "149.112.112.112"   = "https://dns.quad9.net/dns-query"
    "1.1.1.1"           = "https://cloudflare-dns.com/dns-query"
    "1.0.0.1"           = "https://cloudflare-dns.com/dns-query"
    "1.1.1.2"           = "https://security.cloudflare-dns.com/dns-query"
    "1.0.0.2"           = "https://security.cloudflare-dns.com/dns-query"
    "8.8.8.8"           = "https://dns.google/dns-query"
    "8.8.4.4"           = "https://dns.google/dns-query"
    "208.67.222.222"    = "https://doh.opendns.com/dns-query"
    "208.67.220.220"    = "https://doh.opendns.com/dns-query"
}

# Per-interface DoH registry QWord (DohFlags) matching Settings "Encrypted" path.
# Value 17 aligns with Windows UI automatic DoH for known templates (v15.8.4+).
$script:BastionDnsDohInterfaceFlags = 17

# -----------------------------------------------------------------------------
# Apply session counters (reset at start of Dry Run / Apply)
# -----------------------------------------------------------------------------
$script:Stats = @{
    AlreadyConfigured = 0
    Applied           = 0
    Failed            = 0
    ProgramsInstalled = 0
    ServicesDisabled  = 0
}

# -----------------------------------------------------------------------------
# Hardening section defaults and working copy
# -----------------------------------------------------------------------------
# DefaultSections is the product baseline for a first-run seed. Sections is the
# mutable working ordered dictionary copied from defaults then overlaid by config.
# Opt-in sections (Xbox, BrowserPolicies, BloatApps, Suggestions, Copilot, RdpHostLock)
# stay false until the user enables them so Quick Harden stays conservative.
$script:DefaultSections = [ordered]@{
    "Firewall"             = $true
    "HighRiskServices"     = $true
    "SMBv1"                = $true
    "OneDrive"             = $true
    "DeliveryOptimization" = $true
    "DNS"                  = $true
    "Defender"             = $true
    "PowerShellAuditing"   = $true
    "ExploitProtection"    = $true
    "LSAProtection"        = $true
    "ScheduledTasks"       = $true
    "XboxGaming"           = $false
    "Programs"             = $true
    "BrowserPolicies"      = $false
    "BloatApps"            = $false
    "Suggestions"          = $false
    "CopilotM365"          = $false
    # Opt-in: deny system RDP host (fDenyTSConnections + TermService). Firewall still locks the RD group by default.
    "RdpHostLock"          = $false
}

# Subset used by "Quick Harden" style presets (core mitigations without opt-ins).
$script:QuickSections = @(
    "Firewall","HighRiskServices","SMBv1","DeliveryOptimization",
    "DNS","Defender","PowerShellAuditing","LSAProtection","ScheduledTasks"
)

# Live section enable map used by menus and Apply. Starts as a full copy of defaults.
$script:Sections = [ordered]@{}

foreach ($k in $script:DefaultSections.Keys) {
    $script:Sections[$k] = [bool]$script:DefaultSections[$k]
}

# -----------------------------------------------------------------------------
# Section documentation for Help / Dry Run explanations
# -----------------------------------------------------------------------------
# Each entry: Intent (why), Changes (what Bastion does), Impact (user-facing),
# Revert (how to undo), Notes (edge cases). Keep text accurate when changing Apply.
$script:SectionDocs = [ordered]@{
    "Firewall" = @{
        Intent  = "Reduce unsolicited inbound exposure while keeping normal outbound traffic working (browsing, VPN, Windows Update)."
        Changes = "Enables the firewall on Domain, Private, and Public profiles; sets DefaultInboundAction=Block and leaves DefaultOutboundAction=Allow; disables inbound rule groups for File and Printer Sharing, Network Discovery, Remote Assistance, Remote Desktop, Windows Remote Management, and mDNS when those groups are present and enabled."
        Impact  = "Inbound discovery, SMB sharing, RDP, and WinRM from the network are blocked unless you later re-enable specific rules. Outbound apps continue to work. Does not by itself change fDenyTSConnections or TermService (see optional RdpHostLock)."
        Revert  = "Recovery > 3 Network: Remote access (RDP/Assistance/WinRM) and LAN/discovery (File Sharing, Network Discovery, mDNS) with live OPEN/LOCKED status. Recovery > 1 Undo restores tracked groups from last Apply. Or use wf.msc / System Restore."
        Notes   = "Verify with Get-NetFirewallProfile and Get-NetFirewallRule. Full RDP host needs OPEN Remote Desktop group + system allow + TermService. Dry Run and Audit report the RDP triad (firewall group, system policy, TermService)."
    }
    "HighRiskServices" = @{
        Intent  = "Turn off local services that are common attack surface or rarely needed on a single hardened workstation."
        Changes = "Stops and disables when present: LanmanServer, CDPSvc, SSDPSRV, upnphost, Spooler, bowser, RemoteRegistry, SharedAccess, Fax. Original startup types are recorded for Undo when possible."
        Impact  = "File sharing, SSDP/UPnP discovery, Remote Registry, and printing via the local spooler stop until re-enabled. Network printers and some device discovery may stop working."
        Revert  = "Recovery > 2 Services: Spooler shortcut, high-risk group enable/disable with live status, or Recovery > 1 Undo for tracked originals. Or services.msc / System Restore."
        Notes   = "Spooler is included because of PrintNightmare-class risk. If you print often, disable this section or re-enable Spooler from Recovery > 2 after Apply."
    }
    "SMBv1" = @{
        Intent  = "Remove the legacy SMBv1 stack, which is obsolete and historically exploited (for example EternalBlue-class issues)."
        Changes = "If Windows optional feature SMB1Protocol is Enabled, runs Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart."
        Impact  = "Very old NAS devices or appliances that only speak SMB1 will fail to connect. Modern SMB2/SMB3 devices are unaffected."
        Revert  = "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol (not recommended). Prefer upgrading the remote device."
        Notes   = "Dry Run and Apply both check feature state so already-disabled systems report Already OK."
    }
    "OneDrive" = @{
        Intent  = "Remove the OneDrive desktop client from this PC without deleting files already stored in Microsoft cloud accounts."
        Changes = "Stops OneDrive processes, runs the official OneDriveSetup uninstall for all users when present, cleans common startup leftovers, then verifies the client is gone."
        Impact  = "Local OneDrive sync and Explorer integration stop. Cloud data remains at Microsoft until you manage it in the web UI."
        Revert  = "Reinstall OneDrive from Microsoft. Bastion Undo does not reinstall OneDrive."
        Notes   = "If a residual binary or process is still detected after uninstall, the step is marked Failed so you are not given a false success."
    }
    "DeliveryOptimization" = @{
        Intent  = "Stop Windows Update from using peer-to-peer sharing on the LAN or Internet."
        Changes = "Sets policy HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization DODownloadMode=0 (HTTP only from Microsoft)."
        Impact  = "Updates download only from Microsoft (or your configured update source), not from other PCs. May slightly increase WAN usage on large fleets; fine for a single PC."
        Revert  = "Recovery > 6 Security mitigations > Policies and tasks: clear DODownloadMode. Settings UI is overridden while the policy exists."
        Notes   = "Dry Run reads the current policy value so repeated runs show Already OK when set."
    }
    "DNS" = @{
        Intent  = "Optionally set eligible adapters to a public DNS provider (with DNS-over-HTTPS), or leave DNS alone."
        Changes = "On Apply (main menu 8, or DNS menu A): snapshot prior DNS, set IPv4 servers, enable DoH for known resolvers. Providers: Quad9, Cloudflare, Cloudflare security, Google, OpenDNS. 'Do not change DNS' skips this section."
        Impact  = "Name resolution uses the chosen resolver. Settings should show Encrypted for DoH-capable resolvers. A VPN may override DNS while connected."
        Revert  = "Recovery > 3 Network: option 3 = DHCP, option 4 = restore last DNS snapshot (runs now). Undo can also restore the snapshot. Best-effort if adapters changed."
        Notes   = "Menu D only saves preference. Apply is required for Windows. Snapshot on disk is DPAPI-encrypted (separate from Settings Encrypted = DoH on the wire)."
    }
    "RdpHostLock" = @{
        Intent  = "Optionally deny this PC as a Remote Desktop host (workstation that should not accept RDP logons)."
        Changes = "When enabled: sets fDenyTSConnections=1 and stops TermService (Remote Desktop Services) with startup Manual. Prior system allow and TermService start type are tracked for Undo."
        Impact  = "This PC will not accept Remote Desktop sessions until restored. Outbound RDP clients are unaffected. Windows Home may not host RDP even when unlocked."
        Revert  = "Recovery > 3 Network > Remote access (system allow + TermService), or Undo when RdpHostPrior was saved. Firewall Remote Desktop group is separate (Firewall section)."
        Notes   = "Off by default. Firewall Apply already locks the Remote Desktop inbound group. Use this only if you also want the OS host switch denied."
    }
    "Defender" = @{
        Intent  = "Turn on stronger Microsoft Defender workstation protections that are often left off by default."
        Changes = "Enables Network Protection and Controlled Folder Access when Defender is available; refreshes a CFA allow-list for known catalog app paths and a few common system paths."
        Impact  = "Suspicious network connections and untrusted apps writing to protected folders are more likely to be blocked. Rare false positives may need an allow path."
        Revert  = "Recovery > 6 Security mitigations > Defender: soften NP and/or CFA, or re-harden with allow-path refresh. Or Windows Security UI."
        Notes   = "Requires Microsoft Defender features online. Third-party antivirus may limit or replace these settings."
    }
    "PowerShellAuditing" = @{
        Intent  = "Record PowerShell script block activity for later investigation if malware uses scripts."
        Changes = "Enables policy Script Block Logging (and invocation logging when available) under HKLM PowerShell policies."
        Impact  = "More events written to the PowerShell operational log. Minor disk use; helpful for forensics, not a prevention control by itself."
        Revert  = "Recovery > 6 > Policies and tasks: turn off Script Block Logging policy. Or set EnableScriptBlockLogging to 0 manually."
        Notes   = "Pairs well with process creation auditing if you enable that separately outside Bastion."
    }
    "ExploitProtection" = @{
        Intent  = "Apply a mild system exploit mitigation profile, including system-wide StrictHandle, with automatic per-app exceptions only for paths Bastion already knows (today: discovered Wow*.exe)."
        Changes = "Enables DEP, SEHOP, BottomUp, HighEntropy, and StrictHandle system-wide. Then turns StrictHandle OFF only for discovered exception EXEs (currently Wow*.exe discovery plus any StrictHandleExceptionPaths you list in Bastion-Config.json)."
        Impact  = "Most processes get stricter handle checks. Programs without an exception may fail to start. World of Warcraft is a documented example that broke under system StrictHandle and is now auto-excepted when found. CS2 was tested OK. Other titles are unknown until reported - no exception means they may still break."
        Revert  = "Recovery > 6 > StrictHandle: (1) disable system StrictHandle and reboot, or (2) add full .exe path under StrictHandleExceptionPaths and refresh exceptions. Report so we can ship an automatic exception. Then re-enable system StrictHandle when ready. System Restore remains bulletproof."
        Notes   = "WoW is an example, not the only possible break. Prefer Recovery > 6 so status stays accurate. Report game name + full .exe path on GitHub issue #18 or Discussions #23; until we add that exception, keep system StrictHandle off or use a config path exception. See docs/KNOWN-ISSUES.md."
    }
    "LSAProtection" = @{
        Intent  = "Protect the Local Security Authority process (credential material) with RunAsPPL."
        Changes = "Sets HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa RunAsPPL=1 when not already set."
        Impact  = "Harder for some credential-dumping techniques. Requires a reboot before full enforcement. A few poorly signed drivers/tools may conflict."
        Revert  = "Recovery > 6 > Policies and tasks: RunAsPPL OFF (or ON), then reboot. Only turn off if you accept weaker credential protection."
        Notes   = "Main menu and Apply both stress reboot after enabling."
    }
    "ScheduledTasks" = @{
        Intent  = "Disable selected Microsoft telemetry/compatibility scheduled tasks that are safe to turn off on a personal workstation."
        Changes = "Disables when present and enabled: Microsoft Compatibility Appraiser, ProgramDataUpdater, CEIP Consolidator, UsbCeip."
        Impact  = "Less background compatibility telemetry. Does not remove Windows Update itself."
        Revert  = "Recovery > 6 > Policies and tasks: re-enable or re-disable the Bastion task list. Or Task Scheduler / System Restore."
        Notes   = "Dry Run lists only tasks that are still enabled so repeated runs go quiet."
    }
    "XboxGaming" = @{
        Intent  = "Optional: disable Xbox-related services when you do not use Xbox features on this PC."
        Changes = "Disables XblAuthManager, XblGameSave, XboxNetApiSvc, XboxGipSvc when present. Also turns off Game DVR / Game Bar capture flags so games stop opening ms-gamingoverlay when Xbox Gaming Overlay is missing (avoids the 'Get an app to open this link' dialog)."
        Impact  = "Xbox networking services stop. Win+G / Game Bar capture is discouraged via registry so titles do not prompt for a missing overlay handler every launch."
        Revert  = "Recovery > 2 Services > Xbox for services; Recovery > 5 Apps and UI > Game Bar for DVR silence reverse. Or Undo when tracked / Microsoft Store for Game Bar."
        Notes   = "Defaults to off in Quick Harden. If you only removed the overlay via BloatApps, Apply also silences Game DVR when that package is removed. See docs/KNOWN-ISSUES.md (ms-gamingoverlay)."
    }
    "Programs" = @{
        Intent  = "Install selected catalog applications via winget with security checks."
        Changes = "For each selected missing app: validate catalog ID, winget source preflight, exact -e --id install, optional safe --location, post path check."
        Impact  = "Adds software you chose. Custom locations only on fixed local volumes outside system paths."
        Revert  = "Menu 10 Uninstall (catalog apps) or Settings > Apps."
        Notes   = "Never uses --ignore-security-hash. Free-typed package IDs are rejected."
    }
    "BrowserPolicies" = @{
        Intent  = "Optional privacy-oriented policy packs for installed Firefox, Chrome, and Brave only."
        Changes = "Menu 6 (works even if this section is off). Only installed engines are listed. Default / Medium / Strict per browser. Encrypted Client Hello (ECH) is a separate Yes/No under Strict and is never default. Dry Run and Security audit report live vs saved mode and ECH for each installed browser."
        Impact  = "Strict (HTTPS-Only) can break some sites. Encrypted Client Hello (ECH), only if you opt in, can break a few networks or middleboxes. Common pattern: one browser Strict (optional ECH), another Medium/Default."
        Revert  = "Menu 6 or Recovery > 4: that browser > Default (clears Bastion policies and any ECH pack for that browser only). System Restore is the bulletproof rollback."
        Notes   = "Installing Bastion or a browser does not enable Encrypted Client Hello (ECH). Restart browsers after changes. Firefox: about:policies. Chrome: chrome://policy. Brave: brave://policy."
    }
    "BloatApps" = @{
        Intent  = "Remove a curated list of consumer Appx packages many users do not want on a clean workstation."
        Changes = "Removes matching user and provisioned packages for items such as Bing News/Weather, Solitaire, Clipchamp, Phone Link, Feedback Hub, Maps, Get Started, Power Automate Desktop, and selected Xbox overlays when present."
        Impact  = "Those apps disappear for existing and new users on this image. Reinstall is not always trivial. Removing Xbox Gaming Overlay without silencing Game DVR can leave games opening ms-gamingoverlay (Windows 'Get an app to open this link' dialog); Bastion silences Game DVR when that overlay is removed or already absent."
        Revert  = "System Restore is the reliable rollback. Microsoft Store may reinstall some apps. Bastion Undo does not reinstall Appx. Recovery > 5 Apps and UI > Game Bar can re-enable Game DVR flags if you restore Game Bar from the Store."
        Notes   = "Path-not-found and already-removed cases are treated as Already, not hard failures. Defaults to off until you opt in. See docs/KNOWN-ISSUES.md (ms-gamingoverlay)."
    }
    "Suggestions" = @{
        Intent  = "Reduce Widgets/News distraction and Start/Settings suggestion surfaces."
        Changes = "Sets HKCU values for TaskbarDa, Feeds view mode, and ContentDeliveryManager suggestion flags; optionally attempts HKLM Windows Feeds / Dsh policies when Windows allows."
        Impact  = "Widgets button and many suggestions hide or reduce after Explorer refresh or sign-out."
        Revert  = "Recovery > 5 Apps and UI > Restore Widgets/Suggestions defaults."
        Notes   = "Some HKLM policy keys return unauthorized even when elevated; those are Soft and will not fail the whole Apply. HKCU controls still apply."
    }
    "CopilotM365" = @{
        Intent  = "Optional: disable Windows Copilot UI and remove Microsoft 365 Copilot / Office Hub style Appx packages when present."
        Changes = "Sets TurnOffWindowsCopilot policy and hides ShowCopilotButton; removes user Appx packages matching Copilot or MicrosoftOfficeHub. Does NOT uninstall full Microsoft 365 desktop (Word/Excel Click-to-Run) during Apply."
        Impact  = "Copilot taskbar entry and M365 hub/Copilot Store apps may disappear. Full Office suite remains unless you use Recovery > Office remover."
        Revert  = "Recovery > 5 Apps and UI > Copilot / M365 tools. Or reinstall from Microsoft Store / Microsoft 365 installer. System Restore for a full rollback."
        Notes   = "Defaults to OFF. Enable only if you do not want the M365 Copilot hub. Sign-out may be required for taskbar changes."
    }
}

# -----------------------------------------------------------------------------
# Winget program catalog (display name -> winget id + detection paths)
# -----------------------------------------------------------------------------
# Category is UI grouping only. Paths are used for "already installed" checks.
# ManualInstallOnly apps have no winget package; UI offers a download URL instead.
# Never accept free-typed package IDs outside this table (Programs security rule).
$script:ProgramDefs = [ordered]@{
    "Firefox"        = @{ WingetId = "Mozilla.Firefox"; Paths = @("C:\Program Files\Mozilla Firefox\firefox.exe","C:\Program Files (x86)\Mozilla Firefox\firefox.exe"); Category = "Browser" }
    "Chrome"         = @{ WingetId = "Google.Chrome"; Paths = @("C:\Program Files\Google\Chrome\Application\chrome.exe"); Category = "Browser" }
    "Brave"          = @{ WingetId = "Brave.Brave"; Paths = @("C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"); Category = "Browser" }
    "Steam"          = @{ WingetId = "Valve.Steam"; Paths = @("C:\Program Files (x86)\Steam\steam.exe"); Category = "Gaming" }
    "EA App"         = @{ WingetId = "ElectronicArts.EADesktop"; Paths = @(
                            "C:\Program Files\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe",
                            "C:\Program Files\Electronic Arts\EA Desktop\EA Desktop\EALauncher.exe",
                            "C:\Program Files (x86)\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe"
                         ); Category = "Gaming" }
    "Riot Client"    = @{
                            # No dedicated winget package for Riot Client alone; detect only + manual download URL.
                            WingetId = $null
                            ManualInstallOnly = $true
                            ManualUrl = "https://www.riotgames.com/en"
                            Paths = @(
                                "C:\Riot Games\Riot Client\RiotClientServices.exe",
                                "C:\Riot Games\Riot Client\RiotClientUx.exe"
                            )
                            Category = "Gaming"
                         }
    "Mullvad VPN"    = @{ WingetId = "MullvadVPN.MullvadVPN"; Paths = @("C:\Program Files\Mullvad VPN\Mullvad VPN.exe"); Category = "Security" }
    "Discord"        = @{ WingetId = "Discord.Discord"; Paths = @("$env:LOCALAPPDATA\Discord\Update.exe"); Category = "Social" }
    "Slack"          = @{ WingetId = "SlackTechnologies.Slack"; Paths = @("$env:LOCALAPPDATA\slack\slack.exe","C:\Program Files\Slack\slack.exe"); Category = "Social" }
    "Battle.net"     = @{ WingetId = "Blizzard.BattleNet"; Paths = @("C:\Program Files (x86)\Battle.net\Battle.net.exe"); Category = "Gaming" }
    "7-Zip"          = @{ WingetId = "7zip.7zip"; Paths = @("C:\Program Files\7-Zip\7zFM.exe","C:\Program Files\7-Zip\7z.exe"); Category = "Utility" }
    "Notepad++"      = @{ WingetId = "Notepad++.Notepad++"; Paths = @("C:\Program Files\Notepad++\notepad++.exe"); Category = "Dev" }
    "VLC"            = @{ WingetId = "VideoLAN.VLC"; Paths = @("C:\Program Files\VideoLAN\VLC\vlc.exe"); Category = "Media" }
    "PowerToys"      = @{ WingetId = "Microsoft.PowerToys"; Paths = @("$env:LOCALAPPDATA\PowerToys\PowerToys.exe","C:\Program Files\PowerToys\PowerToys.exe"); Category = "Utility" }
    "VS Code"        = @{ WingetId = "Microsoft.VisualStudioCode"; Paths = @("$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe","C:\Program Files\Microsoft VS Code\Code.exe"); Category = "Dev" }
    "Git"            = @{ WingetId = "Git.Git"; Paths = @("C:\Program Files\Git\cmd\git.exe"); Category = "Dev" }
    "GitHub Desktop" = @{ WingetId = "GitHub.GitHubDesktop"; Paths = @("$env:LOCALAPPDATA\GitHubDesktop\GitHubDesktop.exe"); Category = "Dev" }
    "Node.js"        = @{ WingetId = "OpenJS.NodeJS.LTS"; Paths = @("C:\Program Files\nodejs\node.exe"); Category = "Dev" }
    "Postman"        = @{ WingetId = "Postman.Postman"; Paths = @("$env:LOCALAPPDATA\Postman\Postman.exe","C:\Program Files\Postman\Postman.exe"); Category = "Dev" }
    "Docker Desktop" = @{ WingetId = "Docker.DockerDesktop"; Paths = @("C:\Program Files\Docker\Docker\Docker Desktop.exe"); Category = "Dev" }
    "PostgreSQL"     = @{ WingetId = "PostgreSQL.PostgreSQL.17"; Paths = @(
                            "C:\Program Files\PostgreSQL\18\bin\psql.exe",
                            "C:\Program Files\PostgreSQL\17\bin\psql.exe",
                            "C:\Program Files\PostgreSQL\16\bin\psql.exe",
                            "C:\Program Files\PostgreSQL\15\bin\psql.exe"
                         ); Category = "Dev" }
    "ShareX"         = @{ WingetId = "ShareX.ShareX"; Paths = @("C:\Program Files\ShareX\ShareX.exe"); Category = "Utility" }
    "Bitwarden"      = @{ WingetId = "Bitwarden.Bitwarden"; Paths = @("C:\Program Files\Bitwarden\Bitwarden.exe","$env:LOCALAPPDATA\Programs\Bitwarden\Bitwarden.exe"); Category = "Security" }
    "OBS Studio"     = @{ WingetId = "OBSProject.OBSStudio"; Paths = @("C:\Program Files\obs-studio\bin\64bit\obs64.exe"); Category = "Media" }
    "Telegram"       = @{ WingetId = "Telegram.TelegramDesktop"; Paths = @("$env:APPDATA\Telegram Desktop\Telegram.exe"); Category = "Social" }
    "LibreOffice"    = @{ WingetId = "TheDocumentFoundation.LibreOffice"; Paths = @("C:\Program Files\LibreOffice\program\soffice.exe"); Category = "Office" }
    "Blender"        = @{ WingetId = "BlenderFoundation.Blender"; Paths = @("C:\Program Files\Blender Foundation\Blender\blender.exe"); Category = "Media" }
    "Audacity"       = @{ WingetId = "Audacity.Audacity"; Paths = @("C:\Program Files\Audacity\Audacity.exe"); Category = "Media" }
    "Malwarebytes"   = @{ WingetId = "Malwarebytes.Malwarebytes"; Paths = @("C:\Program Files\Malwarebytes\Anti-Malware\mbam.exe","C:\Program Files\Malwarebytes\Anti-Malware\Malwarebytes.exe"); Category = "Security" }
}

# Extra Controlled Folder Access allow paths beyond catalog app detection.
$script:ExtraCfaPaths = @("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")

# Path fragments never allowed as custom winget --location roots (system / package stores).
$script:BlockedPathFragments = @(
    "\Windows\System32","\Windows\SysWOW64","\Windows\WinSxS",
    "\Windows\SystemApps","\Program Files\WindowsApps",
    '$Recycle.Bin',"\System Volume Information"
)

# Only these winget source names are accepted during install preflight.
$script:TrustedWingetSourceNames = @("winget","msstore")

# -----------------------------------------------------------------------------
# Service names used by HighRiskServices and XboxGaming Apply paths
# -----------------------------------------------------------------------------
$script:HighRiskServiceList = @("LanmanServer","CDPSvc","SSDPSRV","upnphost","Spooler","bowser","RemoteRegistry","SharedAccess","Fax")

$script:XboxServiceList = @("XblAuthManager","XblGameSave","XboxNetApiSvc","XboxGipSvc")

# Recovery UI catalog: service name, group, preferred start type after re-enable, why.
$script:ServiceRecoveryCatalog = @(
    @{ Name = "Spooler";        Group = "HighRisk"; Display = "Print Spooler";              PreferStart = "Automatic"; Why = "Local and network printing" }
    @{ Name = "LanmanServer";   Group = "HighRisk"; Display = "Server (SMB file sharing)"; PreferStart = "Automatic"; Why = "Host shared folders" }
    @{ Name = "CDPSvc";         Group = "HighRisk"; Display = "Connected Devices Platform"; PreferStart = "Automatic"; Why = "Nearby sharing / some device features" }
    @{ Name = "SSDPSRV";        Group = "HighRisk"; Display = "SSDP Discovery";            PreferStart = "Manual";    Why = "UPnP / media device discovery" }
    @{ Name = "upnphost";       Group = "HighRisk"; Display = "UPnP Device Host";          PreferStart = "Manual";    Why = "UPnP host features" }
    @{ Name = "bowser";         Group = "HighRisk"; Display = "Computer Browser";          PreferStart = "Manual";    Why = "Legacy network browse list" }
    @{ Name = "RemoteRegistry"; Group = "HighRisk"; Display = "Remote Registry";           PreferStart = "Manual";    Why = "Remote registry access (higher risk)" }
    @{ Name = "SharedAccess";   Group = "HighRisk"; Display = "Internet Connection Sharing"; PreferStart = "Manual";  Why = "ICS / some hotspot features" }
    @{ Name = "Fax";            Group = "HighRisk"; Display = "Fax";                       PreferStart = "Manual";    Why = "Fax modem service" }
    @{ Name = "XblAuthManager"; Group = "Xbox";     Display = "Xbox Live Auth Manager";    PreferStart = "Manual";    Why = "Xbox / Game Pass auth" }
    @{ Name = "XblGameSave";    Group = "Xbox";     Display = "Xbox Live Game Save";       PreferStart = "Manual";    Why = "Xbox cloud saves" }
    @{ Name = "XboxNetApiSvc";  Group = "Xbox";     Display = "Xbox Live Networking";      PreferStart = "Manual";    Why = "Xbox networking" }
    @{ Name = "XboxGipSvc";     Group = "Xbox";     Display = "Xbox Accessory Management"; PreferStart = "Manual";    Why = "Xbox accessories / GIP" }
)

# -----------------------------------------------------------------------------
# Firewall group names (Apply locks; Recovery opens subsets)
# -----------------------------------------------------------------------------
# LAN discovery subset used by Recovery network tools (not remote admin).
$script:LanDiscoveryFirewallGroups = @(
    "File and Printer Sharing",
    "Network Discovery",
    "mDNS"
)

# Full list Bastion disables under the Firewall section when rules exist and are on.
$script:FirewallGroups = @(
    "File and Printer Sharing","Network Discovery","Remote Assistance",
    "Remote Desktop","Windows Remote Management","mDNS"
)

# Remote administration subset (RDP / Assistance / WinRM) for Recovery status UI.
$script:RemoteAccessFirewallGroups = @(
    "Remote Desktop",
    "Remote Assistance",
    "Windows Remote Management"
)

# -----------------------------------------------------------------------------
# Scheduled tasks, Appx bloat list, suggestions registry, Copilot match
# -----------------------------------------------------------------------------
# Full Task Scheduler paths disabled by the ScheduledTasks section.
$script:BastionScheduledTaskPaths = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
)

# Regex used when removing Copilot / Office Hub style user Appx packages.
$script:CopilotM365PackageMatch = 'Copilot|MicrosoftOfficeHub|Microsoft.Copilot'

# Curated consumer Appx packages for the optional BloatApps section.
# Match is substring/package family style for Get-AppxPackage filtering.
$script:BloatAppxList = @(
    @{ Name = "Bing News"; Match = "Microsoft.BingNews" }
    @{ Name = "Bing Weather"; Match = "Microsoft.BingWeather" }
    @{ Name = "Solitaire"; Match = "Microsoft.MicrosoftSolitaireCollection" }
    @{ Name = "Clipchamp"; Match = "Clipchamp.Clipchamp" }
    @{ Name = "Phone Link"; Match = "Microsoft.YourPhone" }
    @{ Name = "Feedback Hub"; Match = "Microsoft.WindowsFeedbackHub" }
    @{ Name = "Maps"; Match = "Microsoft.WindowsMaps" }
    @{ Name = "Get Started"; Match = "Microsoft.Getstarted" }
    @{ Name = "Power Automate"; Match = "Microsoft.PowerAutomateDesktop" }
    @{ Name = "Xbox Gaming Overlay"; Match = "Microsoft.XboxGamingOverlay" }
    @{ Name = "Gaming App"; Match = "Microsoft.GamingApp" }
)

# Registry values for the Suggestions section.
# Soft=$true means unauthorized/write failure is non-fatal for whole Apply.
# Default is the value written when Recovery restores suggestion defaults.
$script:SuggestionRegistry = @(
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "TaskbarDa"; Value = 0; Default = 1; Type = "DWord"; Desc = "Hide Widgets button"; Soft = $false }
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"; Name = "ShellFeedsTaskbarViewMode"; Value = 2; Default = 0; Type = "DWord"; Desc = "Hide News/Interests taskbar feed (HKCU)"; Soft = $true }
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"; Name = "EnableFeeds"; Value = 0; Default = $null; Type = "DWord"; Desc = "Disable Windows Feeds policy"; Soft = $true }
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"; Name = "AllowNewsAndInterests"; Value = 0; Default = $null; Type = "DWord"; Desc = "Disable News and Interests (Dsh policy, optional)"; Soft = $true }
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338388Enabled"; Value = 0; Default = 1; Type = "DWord"; Desc = "Start suggestions"; Soft = $false }
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SystemPaneSuggestionsEnabled"; Value = 0; Default = 1; Type = "DWord"; Desc = "System pane suggestions"; Soft = $false }
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SoftLandingEnabled"; Value = 0; Default = 1; Type = "DWord"; Desc = "Soft Landing"; Soft = $false }
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338389Enabled"; Value = 0; Default = 1; Type = "DWord"; Desc = "Settings suggestions"; Soft = $false }
)

# -----------------------------------------------------------------------------
# DPAPI optional entropy for undo secrets (not a password; not for source files)
# -----------------------------------------------------------------------------
# Used only by Protect-BastionBlob / Unprotect-BastionBlob in Bastion.Config.ps1
# for DNS snapshots and RDP host prior values inside Bastion-LastApply.json.
# Changing this string breaks decryption of existing undo blobs for this user.
$script:BastionDpapiEntropy = [System.Text.Encoding]::UTF8.GetBytes("BastionHardening.ProtectedState.v15.8")
