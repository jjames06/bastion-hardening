#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Bastion Hardening Framework v15.1 FINAL
.DESCRIPTION
    Selective Windows hardening. Catalog-only winget installs. Pure ASCII source
    to avoid smart-quote / em-dash parse failures when pasting into editors.
.NOTES
    Version 15.1 FINAL. System Restore is the strongest rollback. Run elevated. Save as UTF-8 (ASCII subset).
#>

$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"
$ConfirmPreference     = "None"

$script:Config = @{
    ScriptVersion = "15.1"
    # Preferred new-store root; Resolve-BastionLogDirectory may reuse legacy C:\Temp or fall back.
    LogDirectory  = "C:\Temp\Bastion"
    EventSource   = "BastionHardening"
}

function Get-BastionDataDirCandidates {
    # Discovery order for existing state + durable fallbacks. %TEMP%\Bastion is last (wipe-prone).
    $raw = @(
        (Join-Path "C:\Temp" "Bastion"),
        "C:\Temp",   # legacy flat layout (pre-subfolder)
        (Join-Path $env:ProgramData "Bastion"),
        (Join-Path $env:LOCALAPPDATA "Bastion"),
        (Join-Path $env:TEMP "Bastion")
    )
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($c in $raw) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        if (-not $list.Contains($c)) { [void]$list.Add($c) }
    }
    return @($list)
}

function Test-BastionDirWritable {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $probe = Join-Path $Path ("bastion-write-test-{0}.tmp" -f [guid]::NewGuid().ToString("N"))
        Set-Content -LiteralPath $probe -Value "ok" -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

function Test-BastionStatePresent {
    param([string]$Dir)
    if ([string]::IsNullOrWhiteSpace($Dir)) { return $false }
    if (-not (Test-Path -LiteralPath $Dir)) { return $false }
    foreach ($name in @("Bastion-Config.json", "Bastion-LastApply.json", "Bastion-BrowserPolicies-State.json", "Bastion-Session.json")) {
        if (Test-Path -LiteralPath (Join-Path $Dir $name)) { return $true }
    }
    return $false
}

function Resolve-BastionLogDirectory {
    # 1) Reuse a writable dir that already has Bastion state (prefer newest config).
    # 2) Else create the first durable writable path (never invent Apply history).
    $candidates = @(Get-BastionDataDirCandidates)
    $withState = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $candidates) {
        if (-not (Test-Path -LiteralPath $c)) { continue }
        if (-not (Test-BastionStatePresent -Dir $c)) { continue }
        if (-not (Test-BastionDirWritable -Path $c)) { continue }
        $cfg = Join-Path $c "Bastion-Config.json"
        $mtime = [datetime]::MinValue
        if (Test-Path -LiteralPath $cfg) {
            try { $mtime = (Get-Item -LiteralPath $cfg).LastWriteTimeUtc } catch {}
        }
        [void]$withState.Add([PSCustomObject]@{ Path = $c; Mtime = $mtime })
    }
    if ($withState.Count -gt 0) {
        $best = $withState | Sort-Object Mtime -Descending | Select-Object -First 1
        return $best.Path
    }

    # New store: durable first. Prefer C:\Temp\Bastion over flat C:\Temp and over wipeable %TEMP%.
    $preferredNew = @(
        (Join-Path "C:\Temp" "Bastion"),
        (Join-Path $env:ProgramData "Bastion"),
        (Join-Path $env:LOCALAPPDATA "Bastion"),
        "C:\Temp",
        (Join-Path $env:TEMP "Bastion")
    )
    foreach ($c in $preferredNew) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        if (Test-BastionDirWritable -Path $c) { return $c }
    }
    return $null
}

function Bind-BastionDataPaths {
    param([string]$LogDirectory)
    $script:Config.LogDirectory = $LogDirectory
    $script:logFile    = Join-Path $LogDirectory ("Bastion-Log-{0}.txt" -f $script:timestamp)
    $script:tempDir    = Join-Path $LogDirectory "BastionInstallers"
    $script:undoFile   = Join-Path $LogDirectory "Bastion-LastApply.json"
    $script:configFile = Join-Path $LogDirectory "Bastion-Config.json"
    $script:sessionFile = Join-Path $LogDirectory "Bastion-Session.json"
}

$script:timestamp   = Get-Date -Format "yyyyMMdd-HHmmss"
$script:sessionFile = $null
$script:HadPriorConfig  = $false
$script:HadPriorApply   = $false
$script:FirstRunSeeded  = $false
$script:DataStoreReady  = $false

$resolvedLog = Resolve-BastionLogDirectory
if ($resolvedLog) {
    Bind-BastionDataPaths -LogDirectory $resolvedLog
} else {
    Write-Host "  WARNING: Could not create a writable Bastion data directory." -ForegroundColor Red
    Write-Host "  Tried C:\Temp\Bastion, C:\Temp, %ProgramData%\Bastion, %LOCALAPPDATA%\Bastion, %TEMP%\Bastion." -ForegroundColor Yellow
    # Keep placeholders so later messages still show intended names.
    Bind-BastionDataPaths -LogDirectory "C:\Temp\Bastion"
}

$script:SkipSpoolerThisApply = $false

# Catalog installs start unselected; users opt in via the Programs menu.
$script:SelectedApps = [System.Collections.Generic.List[string]]::new()
$script:GlobalInstallRoot   = $null
$script:ProgramInstallRoots = @{}
# Per-browser policy mode (Default | Medium | Strict). Independent so Firefox can stay Strict while Chrome stays Medium.
$script:BrowserPolicyModes  = [ordered]@{
    Firefox = "Default"
    Chrome  = "Default"
    Brave   = "Default"
}
# Encrypted Client Hello (ECH) pack: NEVER on by default. Only true after an explicit Yes in menu 6
# (or a prior saved Yes). Apply will not invent ECH. Firefox: preference locks. Chrome/Brave: BastionEchLock + transport policies.
$script:BrowserEchLocks = [ordered]@{
    Firefox = $false
    Chrome  = $false
    Brave   = $false
}
# Legacy single-mode field (older configs / last bulk choice summary).
$script:BrowserPolicyMode   = "Default"
# DNS: pick a public resolver or leave adapters unchanged (see $script:DnsProviders).
$script:DnsProviderId       = "Quad9"
# Registry value names Bastion may write under Chrome/Brave policy keys (targeted revert).
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
$script:ConfigLoaded        = $false
$script:ApplyFailures       = [System.Collections.Generic.List[string]]::new()
$script:BrowserPolicyLastChange = $null

# Curated public recursive DNS resolvers (IPv4). IDs are stable config keys.
$script:DnsProviders = [ordered]@{
    "Quad9" = @{
        DisplayName = "Quad9 (malware blocking)"
        Primary     = "9.9.9.9"
        Secondary   = "149.112.112.112"
        Notes       = "Blocks known malicious domains. Privacy-oriented recursive resolver (quad9.net)."
    }
    "Cloudflare" = @{
        DisplayName = "Cloudflare (1.1.1.1)"
        Primary     = "1.1.1.1"
        Secondary   = "1.0.0.1"
        Notes       = "Fast, privacy-focused public DNS. Widely used and independently audited practices."
    }
    "CloudflareSecurity" = @{
        DisplayName = "Cloudflare security (malware block)"
        Primary     = "1.1.1.2"
        Secondary   = "1.0.0.2"
        Notes       = "Cloudflare DNS with malware domain blocking (1.1.1.2 family)."
    }
    "Google" = @{
        DisplayName = "Google Public DNS"
        Primary     = "8.8.8.8"
        Secondary   = "8.8.4.4"
        Notes       = "Highly available public DNS with broad client and network support."
    }
    "OpenDNS" = @{
        DisplayName = "Cisco OpenDNS"
        Primary     = "208.67.222.222"
        Secondary   = "208.67.220.220"
        Notes       = "Cisco OpenDNS public resolvers with phishing protection features."
    }
    "None" = @{
        DisplayName = "Do not change DNS"
        Primary     = $null
        Secondary   = $null
        Notes       = "Leave adapter DNS as-is (DHCP/manual). Disables the DNS hardening section."
    }
}
$script:Stats = @{
    AlreadyConfigured = 0
    Applied           = 0
    Failed            = 0
    ProgramsInstalled = 0
    ServicesDisabled  = 0
}

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
}

$script:QuickSections = @(
    "Firewall","HighRiskServices","SMBv1","DeliveryOptimization",
    "DNS","Defender","PowerShellAuditing","LSAProtection","ScheduledTasks"
)

$script:Sections = [ordered]@{}
foreach ($k in $script:DefaultSections.Keys) {
    $script:Sections[$k] = [bool]$script:DefaultSections[$k]
}

$script:SectionDocs = [ordered]@{
    "Firewall" = @{
        Intent  = "Reduce unsolicited inbound exposure while keeping normal outbound traffic working (browsing, VPN, Windows Update)."
        Changes = "Enables the firewall on Domain, Private, and Public profiles; sets DefaultInboundAction=Block and leaves DefaultOutboundAction=Allow; disables inbound rule groups for File and Printer Sharing, Network Discovery, Remote Assistance, Remote Desktop, Windows Remote Management, and mDNS when those groups are present and enabled."
        Impact  = "Inbound discovery, SMB sharing, RDP, and WinRM from the network are blocked unless you later re-enable specific rules. Outbound apps continue to work."
        Revert  = "Recovery > Undo last hardening restores tracked firewall groups from the last Apply. You can also use Windows Defender Firewall with Advanced Security, or System Restore."
        Notes   = "Verify with Get-NetFirewallProfile and Get-NetFirewallRule. This is profile hardening plus group toggles, not a full custom rule set."
    }
    "HighRiskServices" = @{
        Intent  = "Turn off local services that are common attack surface or rarely needed on a single hardened workstation."
        Changes = "Stops and disables when present: LanmanServer, CDPSvc, SSDPSRV, upnphost, Spooler, bowser, RemoteRegistry, SharedAccess, Fax. Original startup types are recorded for Undo when possible."
        Impact  = "File sharing, SSDP/UPnP discovery, Remote Registry, and printing via the local spooler stop until re-enabled. Network printers and some device discovery may stop working."
        Revert  = "Recovery > Undo for tracked services, Recovery > Re-enable Print Spooler for printing only, or services.msc. System Restore for a full rollback."
        Notes   = "Spooler is included because of PrintNightmare-class risk. If you print often, disable this section or re-enable Spooler after Apply."
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
        Revert  = "Remove DODownloadMode or set another documented mode. Settings UI is overridden while the policy exists."
        Notes   = "Dry Run reads the current policy value so repeated runs show Already OK when set."
    }
    "DNS" = @{
        Intent  = "Optionally set eligible network adapters to a user-chosen public recursive DNS provider, or leave DNS unchanged."
        Changes = "When a provider is selected (menu D), sets IPv4 DNS on active adapters via Set-DnsClientServerAddress. Providers: Quad9 malware-blocking, Cloudflare 1.1.1.1, Cloudflare security 1.1.1.2, Google Public DNS, Cisco OpenDNS. Choose 'Do not change DNS' to skip."
        Impact  = "Name resolution uses the chosen resolver while those adapter settings apply. A connected VPN may override DNS while the tunnel is up; that is expected."
        Revert  = "Reset DNS on the adapter (automatic/DHCP) or set your preferred servers. VPN apps may manage DNS independently. Bastion Undo does not restore previous DNS servers."
        Notes   = "Default provider is Quad9. Dry Run and Audit compare the first configured IPv4 DNS server per adapter against the selected primary."
    }
    "Defender" = @{
        Intent  = "Turn on stronger Microsoft Defender workstation protections that are often left off by default."
        Changes = "Enables Network Protection and Controlled Folder Access when Defender is available; refreshes a CFA allow-list for known catalog app paths and a few common system paths."
        Impact  = "Suspicious network connections and untrusted apps writing to protected folders are more likely to be blocked. Rare false positives may need an allow path."
        Revert  = "Set-MpPreference to disable NP/CFA if required, or adjust Controlled Folder Access allow-list in Windows Security."
        Notes   = "Requires Microsoft Defender features online. Third-party antivirus may limit or replace these settings."
    }
    "PowerShellAuditing" = @{
        Intent  = "Record PowerShell script block activity for later investigation if malware uses scripts."
        Changes = "Enables policy Script Block Logging (and invocation logging when available) under HKLM PowerShell policies."
        Impact  = "More events written to the PowerShell operational log. Minor disk use; helpful for forensics, not a prevention control by itself."
        Revert  = "Clear EnableScriptBlockLogging policy values or set them to 0."
        Notes   = "Pairs well with process creation auditing if you enable that separately outside Bastion."
    }
    "ExploitProtection" = @{
        Intent  = "Apply a mild system exploit mitigation profile that stays compatible with common games and launchers."
        Changes = "Set-ProcessMitigation -System enabling DEP, SEHOP, BottomUp, and HighEntropy only. Does NOT enable StrictHandle (strict handle checks)."
        Impact  = "Hardens memory protections for many processes without the aggressive options that caused black-screen logons or game loader crashes on some PCs."
        Revert  = "Windows Security > App and browser control > Exploit protection, or: Set-ProcessMitigation -System -Disable DEP,SEHOP,BottomUp,HighEntropy,StrictHandle (elevated). System Restore for full rollback."
        Notes   = "StrictHandle is intentionally omitted: it can crash World of Warcraft at Play/Wow.exe with Eidolon INVALID_HANDLE in Wow_loader.dll (see GitHub issue #18). If an older Bastion Apply already enabled StrictHandle, disable it with Set-ProcessMitigation -System -Disable StrictHandle and reboot. Dry Run inspects DEP/SEHOP when queryable."
    }
    "LSAProtection" = @{
        Intent  = "Protect the Local Security Authority process (credential material) with RunAsPPL."
        Changes = "Sets HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa RunAsPPL=1 when not already set."
        Impact  = "Harder for some credential-dumping techniques. Requires a reboot before full enforcement. A few poorly signed drivers/tools may conflict."
        Revert  = "Set RunAsPPL back to 0 and reboot (only if you accept weaker credential protection)."
        Notes   = "Main menu and Apply both stress reboot after enabling."
    }
    "ScheduledTasks" = @{
        Intent  = "Disable selected Microsoft telemetry/compatibility scheduled tasks that are safe to turn off on a personal workstation."
        Changes = "Disables when present and enabled: Microsoft Compatibility Appraiser, ProgramDataUpdater, CEIP Consolidator, UsbCeip."
        Impact  = "Less background compatibility telemetry. Does not remove Windows Update itself."
        Revert  = "Re-enable the tasks in Task Scheduler, or System Restore."
        Notes   = "Dry Run lists only tasks that are still enabled so repeated runs go quiet."
    }
    "XboxGaming" = @{
        Intent  = "Optional: disable Xbox-related services when you do not use Xbox features on this PC."
        Changes = "Disables XblAuthManager, XblGameSave, XboxNetApiSvc, XboxGipSvc when present."
        Impact  = "Xbox app, some Game Bar features, and Xbox networking services will not run."
        Revert  = "Re-enable services in services.msc or Undo when tracked."
        Notes   = "Defaults to off in Quick Harden. Enable only if you want this trade-off."
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
        Revert  = "Menu 6 or Recovery > 3: that browser > Default (clears Bastion policies and any ECH pack for that browser only). System Restore is the bulletproof rollback."
        Notes   = "Installing Bastion or a browser does not enable Encrypted Client Hello (ECH). Restart browsers after changes. Firefox: about:policies. Chrome: chrome://policy. Brave: brave://policy."
    }
    "BloatApps" = @{
        Intent  = "Remove a curated list of consumer Appx packages many users do not want on a clean workstation."
        Changes = "Removes matching user and provisioned packages for items such as Bing News/Weather, Solitaire, Clipchamp, Phone Link, Feedback Hub, Maps, Get Started, Power Automate Desktop, and selected Xbox overlays when present."
        Impact  = "Those apps disappear for existing and new users on this image. Reinstall is not always trivial."
        Revert  = "System Restore is the reliable rollback. Microsoft Store may reinstall some apps. Bastion Undo does not reinstall Appx."
        Notes   = "Path-not-found and already-removed cases are treated as Already, not hard failures. Defaults to off until you opt in."
    }
    "Suggestions" = @{
        Intent  = "Reduce Widgets/News distraction and Start/Settings suggestion surfaces."
        Changes = "Sets HKCU values for TaskbarDa, Feeds view mode, and ContentDeliveryManager suggestion flags; optionally attempts HKLM Windows Feeds / Dsh policies when Windows allows."
        Impact  = "Widgets button and many suggestions hide or reduce after Explorer refresh or sign-out."
        Revert  = "Recovery > Restore Widgets/Suggestions defaults."
        Notes   = "Some HKLM policy keys return unauthorized even when elevated; those are Soft and will not fail the whole Apply. HKCU controls still apply."
    }
    "CopilotM365" = @{
        Intent  = "Optional: disable Windows Copilot UI and remove Microsoft 365 Copilot / Office Hub style Appx packages when present."
        Changes = "Sets TurnOffWindowsCopilot policy and hides ShowCopilotButton; removes user Appx packages matching Copilot or MicrosoftOfficeHub. Does NOT uninstall full Microsoft 365 desktop (Word/Excel Click-to-Run) during Apply."
        Impact  = "Copilot taskbar entry and M365 hub/Copilot Store apps may disappear. Full Office suite remains unless you use Recovery > Office remover."
        Revert  = "Reinstall from Microsoft Store or Microsoft 365 installer. Policy keys can be cleared manually. System Restore for a full rollback."
        Notes   = "Defaults to OFF. Enable only if you do not want the M365 Copilot hub. Sign-out may be required for taskbar changes."
    }
}


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

$script:ExtraCfaPaths = @("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
$script:BlockedPathFragments = @(
    "\Windows\System32","\Windows\SysWOW64","\Windows\WinSxS",
    "\Windows\SystemApps","\Program Files\WindowsApps",
    '$Recycle.Bin',"\System Volume Information"
)
$script:TrustedWingetSourceNames = @("winget","msstore")
$script:HighRiskServiceList = @("LanmanServer","CDPSvc","SSDPSRV","upnphost","Spooler","bowser","RemoteRegistry","SharedAccess","Fax")
function Get-HighRiskServicesForApply {
    # Spooler can be skipped for one Apply when Quick Harden user opts to keep printing.
    $list = @($script:HighRiskServiceList)
    if ($script:SkipSpoolerThisApply) {
        $list = @($list | Where-Object { $_ -ne "Spooler" })
    }
    return $list
}
$script:XboxServiceList = @("XblAuthManager","XblGameSave","XboxNetApiSvc","XboxGipSvc")
$script:FirewallGroups = @(
    "File and Printer Sharing","Network Discovery","Remote Assistance",
    "Remote Desktop","Windows Remote Management","mDNS"
)
$script:CopilotM365PackageMatch = 'Copilot|MicrosoftOfficeHub|Microsoft.Copilot'
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
# Suggestion / Widgets registry targets.
# Prefer HKCU and Windows Feeds policy. Avoid sole reliance on Policies\Microsoft\Dsh
# (often returns "unauthorized operation" even elevated on some Windows 11 builds).
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

function Ensure-BastionPaths {
    try {
        # Re-resolve if preferred path became unusable mid-session
        if (-not (Test-Path -LiteralPath $script:Config.LogDirectory) -or -not (Test-BastionDirWritable -Path $script:Config.LogDirectory)) {
            $again = Resolve-BastionLogDirectory
            if ($again) {
                Bind-BastionDataPaths -LogDirectory $again
            }
        }
        $backupDir = Join-Path $script:Config.LogDirectory "browser-policy-backups"
        foreach ($p in @($script:Config.LogDirectory, $script:tempDir, $backupDir)) {
            if (-not (Test-Path -LiteralPath $p)) {
                New-Item -Path $p -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
        }
        if (-not $script:sessionFile) {
            $script:sessionFile = Join-Path $script:Config.LogDirectory "Bastion-Session.json"
        }
        return $true
    } catch {
        Write-Host ("  ERROR: Cannot prepare Bastion data directory ({0}): {1}" -f $script:Config.LogDirectory, $_.Exception.Message) -ForegroundColor Red
        return $false
    }
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Color = "White",
        [ValidateSet("Information","Warning","Error")][string]$Level = "Information",
        [switch]$NoConsole
    )
    $line = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Message
    if (-not $NoConsole) {
        try { Write-Host $line -ForegroundColor $Color } catch { try { Write-Host $line } catch {} }
    }
    [void](Ensure-BastionPaths)
    try { Add-Content -LiteralPath $script:logFile -Value $line -ErrorAction SilentlyContinue } catch {}
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:Config.EventSource)) {
            New-EventLog -LogName Application -Source $script:Config.EventSource -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName Application -Source $script:Config.EventSource -EventId 1000 -EntryType $Level -Message ("Bastion: {0}" -f $Message) -ErrorAction SilentlyContinue
    } catch {}
}

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Already","Applied","Failed","Info","Skip","Warn")][string]$Type = "Info"
    )
    # Console once here; Write-Log uses -NoConsole to avoid duplicate lines
    switch ($Type) {
        "Already" {
            Write-Host ("    {0}" -f $Message) -ForegroundColor DarkGray
            if ($null -ne $script:Stats) { $script:Stats.AlreadyConfigured++ }
            Write-Log $Message -Color DarkGray -NoConsole
        }
        "Applied" {
            Write-Host ("    {0}" -f $Message) -ForegroundColor Green
            if ($null -ne $script:Stats) { $script:Stats.Applied++ }
            Write-Log $Message -Color Green -NoConsole
        }
        "Failed"  {
            Write-Host ("    {0}" -f $Message) -ForegroundColor Red
            if ($null -ne $script:Stats) { $script:Stats.Failed++ }
            if ($null -ne $script:ApplyFailures) { [void]$script:ApplyFailures.Add($Message) }
            Write-Log $Message -Color Red -Level Error -NoConsole
        }
        "Warn" {
            Write-Host ("    {0}" -f $Message) -ForegroundColor Yellow
            Write-Log $Message -Color Yellow -Level Warning -NoConsole
        }
        "Skip" {
            Write-Host ("    {0}" -f $Message) -ForegroundColor DarkYellow
            Write-Log $Message -Color DarkYellow -NoConsole
        }
        default {
            Write-Host ("    {0}" -f $Message) -ForegroundColor White
            Write-Log $Message -NoConsole
        }
    }
}

function Wait-ForKey([string]$Message = "Press any key to return...") {
    Write-Host ""
    Write-Host ("  {0}" -f $Message) -ForegroundColor Gray
    try { [void][System.Console]::ReadKey($true) } catch { [void](Read-Host "  Press Enter") }
}

function Write-Banner {
    # External Bastion-Banner.utf8.txt (UTF-8) next to script if present; else ASCII fallback
    Write-Host ""
    $bannerFile = $null
    try {
        if ($PSScriptRoot) { $bannerFile = Join-Path $PSScriptRoot "Bastion-Banner.utf8.txt" }
        if (-not $bannerFile -or -not (Test-Path -LiteralPath $bannerFile)) {
            if ($MyInvocation.MyCommand.Path) {
                $bannerFile = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "Bastion-Banner.utf8.txt"
            }
        }
    } catch { $bannerFile = $null }

    $usedUnicode = $false
    if ($bannerFile -and (Test-Path -LiteralPath $bannerFile)) {
        try {
            $lines = Get-Content -LiteralPath $bannerFile -Encoding UTF8 -ErrorAction Stop
            Write-Host "  ================================================================" -ForegroundColor DarkCyan
            foreach ($line in $lines) {
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    Write-Host $line -ForegroundColor Cyan
                }
            }
            $usedUnicode = $true
        } catch { $usedUnicode = $false }
    }

    if (-not $usedUnicode) {
        $logo = @(
            '      ____    _    ____ _____ ___ ___  _   _',
            '     | __ )  / \  / ___|_   _|_ _/ _ \| \ | |',
            '     |  _ \ / _ \ \___ \ | |  | | | | |  \| |',
            '     | |_) / ___ \ ___) || |  | | |_| | |\  |',
            '     |____/_/   \_\____/ |_| |___\___/|_| \_|'
        )
        Write-Host "  ================================================================" -ForegroundColor DarkCyan
        foreach ($line in $logo) { Write-Host $line -ForegroundColor Cyan }
    }

    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    # Fixed-width frame: "  " + 64x'=' = 66 columns. Inner body width 62 between edges.
    $boxInner = 62
    function Write-BastionBoxLine {
        param([string]$Text, [string]$Color = "White", [string]$Edge = "|")
        $body = if ($null -eq $Text) { "" } else { [string]$Text }
        if ($body.Length -gt $boxInner) { $body = $body.Substring(0, $boxInner) }
        $body = $body.PadRight($boxInner)
        Write-Host ("  {0}{1}{0}" -f $Edge, $body) -ForegroundColor $Color
    }
    $ver = [string]$script:Config.ScriptVersion
    Write-BastionBoxLine ("  WINDOWS HARDENING FRAMEWORK          v{0} FINAL" -f $ver) "White" "|"
    Write-BastionBoxLine "  Selective  /  State-aware  /  Safety-first" "DarkGray" "|"
    Write-BastionBoxLine ("  {0}" -f (Get-Date -Format "yyyy-MM-dd  HH:mm")) "DarkGray" "|"
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-BastionBoxLine "  Create a System Restore Point before Apply / BloatApps." "Yellow" "!"
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host ""
}




function Get-BastionConsoleWidth {
    try {
        $w = [int]$Host.UI.RawUI.WindowSize.Width
        if ($w -lt 50) { return 78 }
        # Leave a small margin so wrap does not touch the border
        return [Math]::Min(120, [Math]::Max(60, $w - 2))
    } catch {
        return 78
    }
}
function Get-BastionConsoleHeight {
    try {
        $h = [int]$Host.UI.RawUI.WindowSize.Height
        if ($h -lt 16) { return 30 }
        return $h
    } catch {
        return 30
    }
}

function Clear-BastionScreen {
    # Clear visible buffer and pin cursor to top so the user always starts at the header
    try { Clear-Host } catch {}
    try {
        $ui = $Host.UI.RawUI
        $origin = New-Object System.Management.Automation.Host.Coordinates 0, 0
        $ui.CursorPosition = $origin
    } catch {}
}

function Maximize-BastionConsole {
    # Maximize host window for readability. Not exclusive Alt+Enter fullscreen.
    # Fails softly in ISE, some Windows Terminal profiles, remoting, or constrained hosts.
    try {
        if (-not ("BastionNative.ConsoleWin" -as [type])) {
            Add-Type -Namespace BastionNative -Name ConsoleWin -MemberDefinition @"
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
"@ -ErrorAction Stop
        }
        $hwnd = [BastionNative.ConsoleWin]::GetConsoleWindow()
        if ($hwnd -ne [IntPtr]::Zero) {
            # SW_MAXIMIZE = 3
            [void][BastionNative.ConsoleWin]::ShowWindow($hwnd, 3)
        }
    } catch { }

    try {
        $ui = $Host.UI.RawUI
        $max = $ui.MaxPhysicalWindowSize
        if ($max -and $max.Width -ge 40 -and $max.Height -ge 15) {
            $bufW = [Math]::Max([int]$ui.BufferSize.Width, [int]$max.Width)
            $bufH = [Math]::Max([int]$ui.BufferSize.Height, 3000)
            try {
                $ui.BufferSize = New-Object System.Management.Automation.Host.Size $bufW, $bufH
            } catch { }
            try {
                $ui.WindowSize = New-Object System.Management.Automation.Host.Size ([int]$max.Width, [int]$max.Height)
            } catch { }
        }
    } catch { }
}

function Get-WrappedLines {
    param(
        [string]$Text,
        [int]$Indent = 2,
        [int]$Width = 0
    )
    if ($null -eq $Text) { $Text = "" }
    if ($Width -le 0) { $Width = Get-BastionConsoleWidth }
    $pad = " " * [Math]::Max(0, $Indent)
    $maxBody = [Math]::Max(24, $Width - $Indent)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @("") }
    $words = @($Text.Trim() -split '\s+' | Where-Object { $_ })
    if ($words.Count -eq 0) { return @("") }
    $lines = New-Object System.Collections.Generic.List[string]
    $line = $pad + $words[0]
    for ($i = 1; $i -lt $words.Count; $i++) {
        $w = $words[$i]
        if ($w.Length -gt $maxBody) {
            if ($line.Trim().Length -gt 0) { [void]$lines.Add($line); $line = $pad }
            $chunk = $w
            while ($chunk.Length -gt $maxBody) {
                [void]$lines.Add($pad + $chunk.Substring(0, $maxBody))
                $chunk = $chunk.Substring($maxBody)
            }
            $line = $pad + $chunk
            continue
        }
        if (($line.Length + 1 + $w.Length) -le $Width) {
            $line = $line + " " + $w
        } else {
            [void]$lines.Add($line)
            $line = $pad + $w
        }
    }
    if ($line.Length -gt 0) { [void]$lines.Add($line) }
    return @($lines)
}



function Write-Wrapped {
    param(
        [string]$Text,
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::White,
        [int]$Indent = 2,
        [int]$Width = 0
    )
    if ($null -eq $Text) { $Text = "" }
    if ($Width -le 0) { $Width = Get-BastionConsoleWidth }
    $pad = " " * [Math]::Max(0, $Indent)
    $maxBody = [Math]::Max(24, $Width - $Indent)
    if ($Text.Trim().Length -eq 0) {
        Write-Host ""
        return
    }
    # Preserve leading marker spaces in original by trimming only for word split content
    $words = @($Text.Trim() -split '\s+' | Where-Object { $_ -and $_.Length -gt 0 })
    if ($words.Count -eq 0) {
        Write-Host ""
        return
    }
    $line = $pad + $words[0]
    for ($i = 1; $i -lt $words.Count; $i++) {
        $w = $words[$i]
        # Hard-break very long tokens (paths/URLs) so they never blow the width
        if ($w.Length -gt $maxBody) {
            if ($line.Trim().Length -gt 0) {
                Write-Host $line -ForegroundColor $ForegroundColor
                $line = $pad
            }
            $chunk = $w
            while ($chunk.Length -gt $maxBody) {
                Write-Host ($pad + $chunk.Substring(0, $maxBody)) -ForegroundColor $ForegroundColor
                $chunk = $chunk.Substring($maxBody)
            }
            $line = $pad + $chunk
            continue
        }
        if (($line.Length + 1 + $w.Length) -le $Width) {
            $line = $line + " " + $w
        } else {
            Write-Host $line -ForegroundColor $ForegroundColor
            $line = $pad + $w
        }
    }
    if ($line.Length -gt 0) {
        Write-Host $line -ForegroundColor $ForegroundColor
    }
}

function Write-WrappedBlock {
    param(
        [string]$Label,
        [string]$Body,
        [ConsoleColor]$LabelColor = [ConsoleColor]::Cyan,
        [ConsoleColor]$BodyColor = [ConsoleColor]::Gray
    )
    if ([string]::IsNullOrWhiteSpace($Body)) { return }
    Write-Host ("  {0}" -f $Label) -ForegroundColor $LabelColor
    Write-Wrapped -Text $Body -Indent 4 -ForegroundColor $BodyColor
}

function Write-Header([string]$Title) {
    Write-Host ""
    Write-Host "  ==============================================================" -ForegroundColor DarkCyan
    Write-Host ("  {0}" -f $Title.ToUpper()) -ForegroundColor Cyan
    Write-Host ("  Bastion v{0} | {1}" -f $script:Config.ScriptVersion, (Get-Date -Format "yyyy-MM-dd HH:mm")) -ForegroundColor DarkGray
    Write-Host "  ==============================================================" -ForegroundColor DarkCyan
}

function Write-MenuGroup([string]$Label) {
    Write-Host ""
    Write-Host ("  -- {0} --" -f $Label) -ForegroundColor DarkCyan
}

function Read-YesNo([string]$Prompt) {
    $tries = 0
    while ($true) {
        $tries++
        if ($tries -gt 12) {
            Write-Host "  Too many invalid inputs; defaulting to N." -ForegroundColor Red
            return "N"
        }
        try {
            $raw = Read-Host $Prompt
            $a = if ($null -eq $raw) { "" } else { ([string]$raw).Trim() }
        } catch {
            Write-Host "  Input error. Enter Y or N." -ForegroundColor Red
            continue
        }
        if ($a -match '^[Yy]$') { return "Y" }
        if ($a -match '^[Nn]$') { return "N" }
        Write-Host "  Invalid input. Enter Y or N only." -ForegroundColor Red
    }
}

function Read-ConfirmYes([string]$Prompt = "  Type YES to proceed") {
    $tries = 0
    while ($true) {
        $tries++
        if ($tries -gt 12) {
            Write-Host "  Too many invalid inputs; cancelling." -ForegroundColor Red
            return $false
        }
        try {
            $raw = Read-Host $Prompt
            $a = if ($null -eq $raw) { "" } else { ([string]$raw).Trim() }
        } catch {
            Write-Host "  Input error. Type YES to confirm, or NO to cancel." -ForegroundColor Red
            continue
        }
        if ($a -eq "YES") { return $true }
        if ($a -eq "NO" -or $a -match '^[Nn]$') { return $false }
        Write-Host "  Invalid input. Type YES (all caps) to confirm, or NO to cancel." -ForegroundColor Red
    }
}

function Read-MenuChoice {
    param([string]$Prompt = "  Select", [string[]]$Valid)
    if (-not $Valid -or @($Valid).Count -eq 0) {
        Write-Host "  Internal error: no valid choices configured." -ForegroundColor Red
        return "0"
    }
    $tries = 0
    while ($true) {
        $tries++
        if ($tries -gt 20) {
            Write-Host "  Too many invalid inputs; returning cancel (0) if available." -ForegroundColor Red
            foreach ($v in $Valid) {
                if ([string]$v -eq "0") { return "0" }
            }
            return [string]$Valid[0]
        }
        try {
            $raw = Read-Host $Prompt
        } catch {
            Write-Host ("  Input error. Choose one of: {0}" -f ($Valid -join ", ")) -ForegroundColor Red
            continue
        }
        if ($null -eq $raw -or [string]::IsNullOrWhiteSpace([string]$raw)) {
            Write-Host ("  Empty input. Choose one of: {0}" -f ($Valid -join ", ")) -ForegroundColor Red
            continue
        }
        $n = ([string]$raw).Trim()
        if ($n.Length -gt 32) {
            Write-Host "  Invalid input (too long)." -ForegroundColor Red
            continue
        }
        $hasControl = $false
        foreach ($ch in $n.ToCharArray()) {
            if ([int][char]$ch -lt 32) { $hasControl = $true; break }
        }
        if ($hasControl) {
            Write-Host "  Invalid input (control characters not allowed)." -ForegroundColor Red
            continue
        }
        foreach ($v in $Valid) {
            if ($n -eq [string]$v -or $n.ToUpperInvariant() -eq ([string]$v).ToUpperInvariant()) {
                return [string]$v
            }
        }
        Write-Host ("  Invalid choice '{0}'. Allowed: {1}" -f $n, ($Valid -join ", ")) -ForegroundColor Red
    }
}


function Open-UrlSafe([string]$Url) {
    if ([string]::IsNullOrWhiteSpace($Url)) {
        Write-Host "  No URL to open." -ForegroundColor Yellow
        return
    }
    try {
        Start-Process $Url -ErrorAction Stop | Out-Null
    } catch {
        Write-Host ("  Could not open browser: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        Write-Host ("  Open manually: {0}" -f $Url) -ForegroundColor Cyan
    }
}

function Test-WingetAvailable {
    try {
        $cmd = Get-Command winget -ErrorAction Stop
        return [PSCustomObject]@{ Ok = $true; Path = $cmd.Source; Error = $null }
    } catch {
        return [PSCustomObject]@{
            Ok = $false
            Path = $null
            Error = "winget not found. Install App Installer from the Microsoft Store, then re-run."
        }
    }
}

function Test-WingetSecurityPreflight {
    $wg = Test-WingetAvailable
    if (-not $wg.Ok) {
        return [PSCustomObject]@{ Ok = $false; Detail = $wg.Error }
    }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "winget"
        $psi.Arguments = "source list"
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $out = $p.StandardOutput.ReadToEnd()
        [void]$p.WaitForExit(15000)
        $sourceOk = $false
        foreach ($name in $script:TrustedWingetSourceNames) {
            if ($out -match [regex]::Escape($name)) { $sourceOk = $true; break }
        }
        if (-not $sourceOk) {
            return [PSCustomObject]@{
                Ok = $false
                Detail = "No trusted winget/msstore source visible. Refusing installs. Next step: winget source reset --force"
            }
        }
        return [PSCustomObject]@{ Ok = $true; Detail = ("winget OK; trusted source present ({0})" -f $wg.Path) }
    } catch {
        return [PSCustomObject]@{
            Ok = $true
            Detail = ("winget present; source list check failed (continuing cautiously). {0}" -f $_.Exception.Message)
        }
    }
}

function Test-CatalogPackageId {
    param([string]$AppName, [string]$WingetId)
    if ([string]::IsNullOrWhiteSpace($AppName) -or -not $script:ProgramDefs.Contains($AppName)) {
        return [PSCustomObject]@{ Ok = $false; Detail = ("Not in Bastion catalog: {0}" -f $AppName) }
    }
    $def = $script:ProgramDefs[$AppName]
    if ($def.ManualInstallOnly) {
        return [PSCustomObject]@{ Ok = $false; Detail = ("Manual install only (not on winget): {0}" -f $AppName); Manual = $true }
    }
    $expected = $def.WingetId
    if ($WingetId -ne $expected) {
        return [PSCustomObject]@{ Ok = $false; Detail = ("Package ID mismatch for {0}" -f $AppName) }
    }
    if ([string]::IsNullOrWhiteSpace($WingetId) -or $WingetId -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{1,120}$') {
        return [PSCustomObject]@{ Ok = $false; Detail = ("Package ID failed format validation: {0}" -f $WingetId) }
    }
    return [PSCustomObject]@{ Ok = $true; Detail = $WingetId }
}

function Invoke-WingetShow([string]$WingetId) {
    try {
        $outFile = Join-Path $script:tempDir "wg-show-out.txt"
        $errFile = Join-Path $script:tempDir "wg-show-err.txt"
        $p = Start-Process -FilePath "winget" -ArgumentList @("show","--id",$WingetId,"-e") `
            -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile -ErrorAction Stop
        $out = ""
        if (Test-Path -LiteralPath $outFile) {
            $out = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue
        }
        return [PSCustomObject]@{ ExitCode = $p.ExitCode; Output = $out }
    } catch {
        return [PSCustomObject]@{ ExitCode = -1; Output = $_.Exception.Message }
    }
}

function Test-AuthenticodeRelaxed([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return [PSCustomObject]@{ Status = "Missing"; Detail = "Path not found" }
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        switch ($sig.Status) {
            "Valid" { return [PSCustomObject]@{ Status = "Valid"; Detail = [string]$sig.SignerCertificate.Subject } }
            "NotSigned" { return [PSCustomObject]@{ Status = "NotSigned"; Detail = "Unsigned (common for some apps)" } }
            default { return [PSCustomObject]@{ Status = [string]$sig.Status; Detail = [string]$sig.StatusMessage } }
        }
    } catch {
        return [PSCustomObject]@{ Status = "Error"; Detail = $_.Exception.Message }
    }
}

function Get-AvailableInstallVolumes {
    $list = [System.Collections.Generic.List[object]]::new()
    try {
        Get-CimInstance Win32_LogicalDisk -ErrorAction Stop |
            Where-Object { $_.DriveType -eq 3 -and $_.Size -gt 0 -and $null -ne $_.FreeSpace } |
            ForEach-Object {
                [void]$list.Add([PSCustomObject]@{
                    Root   = ($_.DeviceID.TrimEnd('\') + '\')
                    Label  = $(if ($_.VolumeName) { $_.VolumeName } else { "Local Disk" })
                    FreeGB = [math]::Round($_.FreeSpace / 1GB, 1)
                })
            }
    } catch {
        Write-Status ("Volume enumeration failed: {0}. Next step: check disk management." -f $_.Exception.Message) "Warn"
    }
    return @($list | Sort-Object Root)
}

function Test-SafeInstallRoot {
    param([string]$Path, [object[]]$AllowedVolumes)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [PSCustomObject]@{ Ok = $false; Reason = "Empty path"; Path = $null }
    }
    $trimmed = $Path.Trim().Trim('"').Trim("'")
    if ($trimmed -match '[\x00-\x1F<>|?*]') {
        return [PSCustomObject]@{ Ok = $false; Reason = "Invalid path characters"; Path = $null }
    }
    if ($trimmed -match '^\\\\' -or $trimmed -match '^[A-Za-z]:\\\\') {
        return [PSCustomObject]@{ Ok = $false; Reason = "UNC / network paths are not allowed"; Path = $null }
    }
    if ($trimmed -notmatch '^[A-Za-z]:\\') {
        return [PSCustomObject]@{ Ok = $false; Reason = "Path must start with a drive letter (e.g. C:\\Apps)"; Path = $null }
    }
    try {
        $full = [System.IO.Path]::GetFullPath($trimmed)
    } catch {
        return [PSCustomObject]@{ Ok = $false; Reason = "Path resolve failed"; Path = $null }
    }
    $fullNorm = $full.TrimEnd('\')
    $under = $false
    foreach ($v in @($AllowedVolumes)) {
        if (-not $v) { continue }
        $rootNorm = $v.Root.TrimEnd('\')
        if ($fullNorm.Equals($rootNorm, [StringComparison]::OrdinalIgnoreCase) -or
            $fullNorm.StartsWith($rootNorm + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $under = $true
            break
        }
    }
    if (-not $under) {
        return [PSCustomObject]@{ Ok = $false; Reason = "Not on an allowed fixed local volume"; Path = $null }
    }
    $lower = $fullNorm.ToLowerInvariant()
    foreach ($frag in $script:BlockedPathFragments) {
        $f = $frag.ToLowerInvariant()
        if ($lower.Contains($f)) {
            return [PSCustomObject]@{ Ok = $false; Reason = ("Blocked system path ({0})" -f $frag); Path = $null }
        }
    }
    return [PSCustomObject]@{ Ok = $true; Reason = "OK"; Path = $fullNorm }
}

function Get-EffectiveInstallRoot([string]$AppName) {
    if ($AppName -and $script:ProgramInstallRoots.ContainsKey($AppName) -and $script:ProgramInstallRoots[$AppName]) {
        return $script:ProgramInstallRoots[$AppName]
    }
    if ($script:GlobalInstallRoot) { return $script:GlobalInstallRoot }
    return $null
}

function Test-Installed {
    param([string]$Name, [string[]]$Paths)
    foreach ($p in @($Paths)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        # Literal first; also allow simple * wildcards in a single path segment.
        try {
            if (Test-Path -LiteralPath $p) { return $true }
        } catch {}
        if ($p -match '\*') {
            try {
                $hit = Get-Item -Path $p -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($hit) { return $true }
            } catch {}
        }
    }
    if ($Name -eq "Blender" -and (Test-Path -LiteralPath "C:\Program Files\Blender Foundation")) {
        $hit = Get-ChildItem "C:\Program Files\Blender Foundation" -Filter blender.exe -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return $true }
    }
    if ($Name -eq "PostgreSQL" -and (Test-Path -LiteralPath "C:\Program Files\PostgreSQL")) {
        $hit = Get-ChildItem "C:\Program Files\PostgreSQL" -Filter psql.exe -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return $true }
    }
    $root = Get-EffectiveInstallRoot -AppName $Name
    if (-not $root -or -not (Test-Path -LiteralPath $root)) { return $false }
    foreach ($exe in @($Paths | ForEach-Object { Split-Path $_ -Leaf } | Select-Object -Unique | Where-Object { $_ -and $_ -ne '*' })) {
        $hit = Get-ChildItem -LiteralPath $root -Filter $exe -Recurse -Depth 5 -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return $true }
    }
    return $false
}

function Get-SelectedMissingApps {
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @($script:SelectedApps)) {
        if (-not $script:ProgramDefs.Contains($name)) { continue }
        if (-not (Test-Installed -Name $name -Paths $script:ProgramDefs[$name].Paths)) {
            [void]$list.Add($name)
        }
    }
    return @($list)
}

function Sync-ProgramInstallQueue {
    # Install queue = catalog apps the user opted in to install that are still missing.
    # Never keep already-installed names selected (avoids green [X] on installed rows).
    $kept = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @($script:SelectedApps)) {
        if (-not $script:ProgramDefs.Contains($name)) { continue }
        if (-not (Test-Installed -Name $name -Paths $script:ProgramDefs[$name].Paths)) {
            if (-not ($kept -contains $name)) { [void]$kept.Add($name) }
        }
    }
    $script:SelectedApps.Clear()
    foreach ($n in $kept) { [void]$script:SelectedApps.Add($n) }
    Clear-StaleInstallRoots
}

function Get-CatalogProgramRows {
    # Live detect installed/missing for every catalog entry (order matches ProgramDefs).
    $rows = foreach ($name in $script:ProgramDefs.Keys) {
        $def = $script:ProgramDefs[$name]
        $installed = [bool](Test-Installed -Name $name -Paths $def.Paths)
        $queued = (-not $installed) -and ($script:SelectedApps -contains $name)
        [PSCustomObject]@{
            Name      = $name
            Paths     = $def.Paths
            WingetId  = $def.WingetId
            Installed = $installed
            Selected  = $queued
        }
    }
    return @($rows)
}

function Clear-StaleInstallRoots {
    foreach ($k in @($script:ProgramInstallRoots.Keys)) {
        if ($script:SelectedApps -notcontains $k) {
            $script:ProgramInstallRoots.Remove($k)
        }
    }
}

function Install-BastionCatalogApp {
    param([string]$AppName, [string]$LocationPath = $null)

    if (-not $script:ProgramDefs.Contains($AppName)) {
        Write-Status ("REFUSED non-catalog app '{0}'" -f $AppName) "Failed"
        return $false
    }
    $def = $script:ProgramDefs[$AppName]
    if (Test-Installed -Name $AppName -Paths $def.Paths) {
        Write-Status ("{0} already installed" -f $AppName) "Already"
        return $true
    }
    if ($def.ManualInstallOnly) {
        $url = if ($def.ManualUrl) { [string]$def.ManualUrl } else { "(vendor site)" }
        Write-Status ("{0} is not available via winget" -f $AppName) "Warn"
        Write-Host ("      Download/install from: {0}" -f $url) -ForegroundColor Cyan
        Write-Host "      After install, Bastion will detect it for uninstall if paths match." -ForegroundColor DarkGray
        return $false
    }
    $idCheck = Test-CatalogPackageId -AppName $AppName -WingetId $def.WingetId
    if (-not $idCheck.Ok) {
        Write-Status ("REFUSED: {0}" -f $idCheck.Detail) "Failed"
        return $false
    }

    $pre = Test-WingetSecurityPreflight
    if (-not $pre.Ok) {
        Write-Status ("Install blocked: {0}" -f $pre.Detail) "Failed"
        return $false
    }
    Write-Host ("      {0}" -f $pre.Detail) -ForegroundColor DarkGray

    $show = Invoke-WingetShow -WingetId $def.WingetId
    if ($show.ExitCode -ne 0) {
        Write-Status ("{0}: winget show failed (exit {1}). Next step: check network/source with winget source list." -f $AppName, $show.ExitCode) "Failed"
        return $false
    }

    $argList = [System.Collections.Generic.List[string]]::new()
    [void]$argList.AddRange([string[]]@(
        "install","--id",$def.WingetId,"-e",
        "--accept-package-agreements","--accept-source-agreements",
        "--disable-interactivity","--silent"
    ))
    # Never pass --ignore-security-hash

    if ($LocationPath) {
        $vols = @(Get-AvailableInstallVolumes)
        $check = Test-SafeInstallRoot -Path $LocationPath -AllowedVolumes $vols
        if ($check.Ok) {
            [void]$argList.Add("--location")
            [void]$argList.Add($check.Path)
            Write-Host ("      Location: {0}" -f $check.Path) -ForegroundColor DarkGray
        } else {
            Write-Status ("Custom location ignored ({0}); vendor default will be used. Next step: pick a folder under a fixed drive." -f $check.Reason) "Warn"
        }
    }

    Write-Host ("      Installing {0} ({1})..." -f $AppName, $def.WingetId) -ForegroundColor White
    try {
        $p = Start-Process -FilePath "winget" -ArgumentList $argList -Wait -PassThru -NoNewWindow -ErrorAction Stop
    } catch {
        Write-Status ("{0} process error: {1}" -f $AppName, $_.Exception.Message) "Failed"
        return $false
    }

    Start-Sleep -Seconds 2
    $found = Test-Installed -Name $AppName -Paths $def.Paths

    if (-not $found -and $p.ExitCode -ne 0) {
        Write-Status ("{0} failed (winget exit {1}, binary not found). Next step: run winget install -e --id {2} manually." -f $AppName, $p.ExitCode, $def.WingetId) "Failed"
        return $false
    }
    if (-not $found -and $p.ExitCode -eq 0) {
        Write-Status ("{0} winget exit 0 but expected binary not detected yet. Next step: reboot or launch once, then re-run Audit." -f $AppName) "Warn"
        $script:Stats.ProgramsInstalled++
        Write-Status ("{0} reported OK by winget (verify manually)" -f $AppName) "Applied"
        return $true
    }

    foreach ($path in $def.Paths) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            $sig = Test-AuthenticodeRelaxed -Path $path
            Write-Host ("      Signature: {0} - {1}" -f $sig.Status, $sig.Detail) -ForegroundColor DarkGray
            if ($sig.Status -match 'HashMismatch|NotTrusted') {
                Write-Status ("{0} signature concern ({1}). Next step: uninstall if unexpected." -f $AppName, $sig.Status) "Warn"
            }
            break
        }
    }

    $script:Stats.ProgramsInstalled++
    Write-Status ("{0} installed and verified" -f $AppName) "Applied"
    return $true
}

function Get-ServiceState([string]$Name) {
    try { return Get-Service -Name $Name -ErrorAction Stop } catch { return $null }
}

function Disable-BastionService {
    param([string]$Name)
    $svc = Get-ServiceState $Name
    if ($null -eq $svc) {
        Write-Status ("{0} absent" -f $Name) "Already"
        return $null
    }
    if ($svc.StartType -eq "Disabled") {
        Write-Status ("{0} already disabled" -f $Name) "Already"
        return $null
    }
    $orig = $svc.StartType.ToString()
    $stopOk = $true
    try {
        if ($svc.Status -ne "Stopped") {
            Stop-Service -Name $Name -Force -ErrorAction Stop
        }
    } catch {
        $stopOk = $false
        Write-Status ("{0}: could not stop process ({1}). Will still try to disable start type. Next step: reboot if it stays running." -f $Name, $_.Exception.Message) "Warn"
    }
    try {
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
        if ($stopOk) {
            Write-Status ("Disabled {0} (was {1})" -f $Name, $orig) "Applied"
        } else {
            Write-Status ("Disabled start type for {0} (was {1}); process may still run until reboot" -f $Name, $orig) "Applied"
        }
        $script:Stats.ServicesDisabled++
        return [PSCustomObject]@{ Name = $Name; Original = $orig }
    } catch {
        Write-Status ("Failed to disable {0}. Next step: services.msc -> {0} -> Disabled." -f $Name) "Failed"
        return $null
    }
}

function Get-OneDriveStatus {
    $signals = [System.Collections.Generic.List[string]]::new()
    if (Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue) {
        [void]$signals.Add("process")
    }
    $pf86 = ${env:ProgramFiles(x86)}
    foreach ($p in @(
        "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
        "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
        $(if ($pf86) { Join-Path $pf86 "Microsoft OneDrive\OneDrive.exe" } else { $null })
    )) {
        if ($p -and (Test-Path -LiteralPath $p)) {
            [void]$signals.Add(("binary:{0}" -f $p))
        }
    }
    return [PSCustomObject]@{
        Present = ($signals.Count -gt 0)
        Detail  = $(if ($signals.Count) { $signals -join ", " } else { "Not present" })
    }
}

function Remove-BastionOneDrive {
    $before = Get-OneDriveStatus
    if (-not $before.Present) {
        Write-Status "OneDrive not present" "Already"
        return
    }

    Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $setup = @(
        "$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
        "$env:SystemRoot\System32\OneDriveSetup.exe"
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if (-not $setup) {
        Write-Status "OneDriveSetup.exe not found. Next step: Settings > Apps > uninstall OneDrive manually." "Failed"
        return
    }

    try {
        $p = Start-Process -FilePath $setup -ArgumentList @("/uninstall","/allusers") -Wait -PassThru -ErrorAction Stop
        Write-Host ("      OneDriveSetup exit {0}" -f $p.ExitCode) -ForegroundColor DarkGray
    } catch {
        Write-Status ("OneDriveSetup failed: {0}. Next step: uninstall from Settings > Apps." -f $_.Exception.Message) "Failed"
        return
    }

    Start-Sleep -Seconds 2
    Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $after = Get-OneDriveStatus
    if ($after.Present) {
        Write-Status ("OneDrive residual still detected ({0}). Next step: reboot and re-run, or remove leftover package manually." -f $after.Detail) "Failed"
    } else {
        Write-Status "OneDrive removed (verified)" "Applied"
    }
}

function Get-BloatAppxStatus {
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $script:BloatAppxList) {
        $pkgs = @()
        try {
            $pkgs += @(Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ("{0}*" -f $item.Match) })
            $pkgs += @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ("{0}*" -f $item.Match) })
        } catch {}
        $pkgs = @($pkgs | Sort-Object PackageFullName -Unique)
        $prov = @()
        try {
            $prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -like ("{0}*" -f $item.Match) -or $_.PackageName -like ("{0}*" -f $item.Match)
            })
        } catch {}
        if ($pkgs.Count -or $prov.Count) {
            [void]$found.Add([PSCustomObject]@{ DisplayName = $item.Name; UserPkgs = $pkgs; Provisioned = $prov })
        }
    }
    return $found
}

function Get-CfaCandidatePaths {
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $script:ProgramDefs.Keys) {
        foreach ($p in @($script:ProgramDefs[$name].Paths)) {
            if ($p -and (Test-Path -LiteralPath $p) -and -not $paths.Contains($p)) {
                [void]$paths.Add($p)
            }
        }
    }
    foreach ($p in $script:ExtraCfaPaths) {
        if ($p -and (Test-Path -LiteralPath $p) -and -not $paths.Contains($p)) {
            [void]$paths.Add($p)
        }
    }
    return @($paths)
}

function Add-CfaAllowPaths {
    $added = 0
    foreach ($p in (Get-CfaCandidatePaths)) {
        try {
            Add-MpPreference -ControlledFolderAccessAllowedApplications $p -ErrorAction Stop
            Write-Host ("      CFA allow: {0}" -f $p) -ForegroundColor DarkGray
            $added++
        } catch {}
    }
    if ($added -gt 0) {
        Write-Status (("CFA allow-list updated ({0} paths)" -f $added)) "Applied"
    } else {
        Write-Status "No new CFA paths to add" "Already"
    }
}

function Set-RegistryValueSafe {
    param(
        $Path,
        $Name,
        $Value,
        $Type = "DWord",
        $Desc = "",
        [bool]$Soft = $false
    )
    # Soft = optional keys Windows may deny even when elevated; warn quietly, never fail Apply
    try {
        $parts = @(($Path -replace '^HK(LM|CU):\\', '' -split '\\') | Where-Object { $_ })
        $root = if ($Path -match '^HKLM:') { "HKLM:" } else { "HKCU:" }
        $build = $root
        foreach ($part in $parts) {
            $build = Join-Path $build $part
            if (-not (Test-Path -LiteralPath $build)) {
                try {
                    New-Item -Path $build -Force -ErrorAction Stop | Out-Null
                } catch {
                    if ($Soft) {
                        Write-Status ("Optional skipped (key locked): {0}" -f $Desc) "Warn"
                        return $false
                    }
                    throw
                }
            }
        }
        $current = $null
        try { $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name } catch {}
        if ($null -ne $current -and $current -eq $Value) {
            Write-Status ("{0} already set" -f $Desc) "Already"
            return $true
        }
        try {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
            Write-Status ("Set: {0}" -f $Desc) "Applied"
            return $true
        } catch {
            $psErr = $_.Exception.Message
            # Access denied on Soft keys: do not run noisy reg.exe fallback
            if ($Soft -and ($psErr -match 'access is denied|unauthorized|Access is denied|denied')) {
                Write-Status ("Optional skipped (Windows locked): {0}" -f $Desc) "Warn"
                return $false
            }
            $regRoot = if ($Path -match '^HKLM:') { "HKLM" } else { "HKCU" }
            $regPath = ($Path -replace '^HK(LM|CU):\\', '')
            $regType = switch ($Type) {
                "DWord" { "REG_DWORD" }
                "String" { "REG_SZ" }
                "QWord" { "REG_QWORD" }
                default { "REG_DWORD" }
            }
            $outFile = Join-Path $script:tempDir "reg-out.txt"
            $errFile = Join-Path $script:tempDir "reg-err.txt"
            try {
                # Use argument array (avoids quote/parse issues; supports spaces in key paths)
                $regKey = "{0}\{1}" -f $regRoot, $regPath
                $proc = Start-Process -FilePath "reg.exe" -ArgumentList @(
                    "add", $regKey,
                    "/v", "$Name",
                    "/t", "$regType",
                    "/d", "$Value",
                    "/f"
                ) -Wait -PassThru -NoNewWindow `
                    -RedirectStandardOutput $outFile -RedirectStandardError $errFile -ErrorAction Stop
                if ($proc.ExitCode -eq 0) {
                    Write-Status ("Set via reg.exe: {0}" -f $Desc) "Applied"
                    return $true
                }
                $errText = ""
                if (Test-Path -LiteralPath $errFile) {
                    $errText = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
                }
                if ($Soft) {
                    Write-Status ("Optional skipped: {0}" -f $Desc) "Warn"
                    return $false
                }
                throw [System.Exception]::new(("reg exit {0}; {1}; PS: {2}" -f $proc.ExitCode, $errText, $psErr))
            } catch {
                if ($Soft) {
                    Write-Status ("Optional skipped: {0}" -f $Desc) "Warn"
                    return $false
                }
                throw
            }
        }
    } catch {
        $msg = $_.Exception.Message
        if ($Soft -or $msg -match 'unauthorized|access is denied|Access is denied|denied') {
            Write-Status ("Optional skipped: {0}" -f $Desc) "Warn"
            return $false
        }
        Write-Status ("Could not set: {0} ({1})" -f $Desc, $msg) "Warn"
        return $false
    }
}


function Restore-SuggestionDefaults {
    Write-Host "  Restoring Widgets / Suggestions toward defaults..." -ForegroundColor Cyan
    foreach ($item in $script:SuggestionRegistry) {
        $path = $item.Path
        $name = $item.Name
        try {
            if (-not (Test-Path -LiteralPath $path)) {
                Write-Status ("{0}: key absent (nothing to restore)" -f $item.Desc) "Already"
                continue
            }
            if ($null -eq $item.Default) {
                try {
                    Remove-ItemProperty -Path $path -Name $name -Force -ErrorAction Stop
                    Write-Status ("Removed policy value: {0}" -f $item.Desc) "Applied"
                } catch {
                    if ($_.Exception.Message -match 'cannot find|does not exist') {
                        Write-Status ("{0}: already absent" -f $item.Desc) "Already"
                    } else {
                        Write-Status ("Could not remove {0}: {1}" -f $item.Desc, $_.Exception.Message) "Warn"
                    }
                }
            } else {
                $soft = $false
                if ($item.ContainsKey("Soft")) { $soft = [bool]$item.Soft }
                [void](Set-RegistryValueSafe -Path $path -Name $name -Value $item.Default -Type $item.Type -Desc ("Restore {0}" -f $item.Desc) -Soft:$soft)
            }
        } catch {
            Write-Status ("Restore failed {0}: {1}" -f $item.Desc, $_.Exception.Message) "Warn"
        }
    }
    Write-Host "  Sign out or restart Explorer for full UI effect." -ForegroundColor Yellow
}



function Get-FirefoxPoliciesPath {
    foreach ($c in @(
        "C:\Program Files\Mozilla Firefox\distribution\policies.json",
        "C:\Program Files (x86)\Mozilla Firefox\distribution\policies.json"
    )) {
        $root = Split-Path (Split-Path $c -Parent) -Parent
        if (Test-Path -LiteralPath $root) { return $c }
    }
    return "C:\Program Files\Mozilla Firefox\distribution\policies.json"
}

function Test-FirefoxEchLocksPresent {
    $path = Get-FirefoxPoliciesPath
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    try {
        $j = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
        $p = $j.policies
        if (-not $p -or -not $p.Preferences) { return $false }
        $prefNames = @($p.Preferences.PSObject.Properties | ForEach-Object { $_.Name })
        return [bool]($prefNames -match 'echconfig|EncryptedClientHello|network\.dns\.ech')
    } catch {
        return $false
    }
}

function Get-FirefoxPolicyModeFromFile {
    # Classify Bastion-written (or compatible) policies.json for UI display.
    $path = Get-FirefoxPoliciesPath
    if (-not (Test-Path -LiteralPath $path)) { return "Default" }
    try {
        $j = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
        $p = $j.policies
        if (-not $p) { return "Custom" }
        $httpsOnly = ("$($p.HTTPSOnlyMode)" -eq "force_enabled")
        $echPref = Test-FirefoxEchLocksPresent
        $echDisabled = ($p.DisableEncryptedClientHello -eq $true)
        if ($httpsOnly -or $echPref -or ($p.DisablePocket -eq $true -and $p.EnableTrackingProtection -and $p.EnableTrackingProtection.Locked)) {
            return "Strict"
        }
        if ($p.DisableTelemetry -eq $true -or $p.DisableFirefoxStudies -eq $true) {
            return "Medium"
        }
        if ($echDisabled) { return "Custom" }
        return "Custom"
    } catch {
        return "Custom"
    }
}

function Set-FirefoxPolicyMode {
    param(
        [ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch = $false
    )
    $path = Get-FirefoxPoliciesPath
    $dist = Split-Path $path -Parent
    $modeBefore = Get-FirefoxPolicyModeFromFile
    $echBefore = Test-FirefoxEchLocksPresent
    try {
        if ($Mode -eq "Default") {
            $bak = Backup-FirefoxPoliciesFile
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                Write-Status "Firefox policies.json removed (full Bastion revert)" "Applied"
                Write-Host "      Cleared: telemetry/studies locks, tracking protection locks," -ForegroundColor DarkGray
                Write-Host "      HTTPS-Only force, Pocket disable, Encrypted Client Hello (ECH) preference locks." -ForegroundColor DarkGray
                Write-Host ("      File was: {0}" -f $path) -ForegroundColor DarkGray
                Write-Host "      Restart Firefox. about:policies should show no active Bastion file." -ForegroundColor DarkGray
            } else {
                Write-Status "Firefox already default (no policies.json)" "Already"
            }
            if ($script:BrowserPolicyModes.Contains("Firefox")) { $script:BrowserPolicyModes["Firefox"] = "Default" }
            if ($script:BrowserEchLocks.Contains("Firefox")) { $script:BrowserEchLocks["Firefox"] = $false }
            Record-BrowserPolicyChange -Browser "Firefox" -ModeBefore $modeBefore -ModeAfter "Default" `
                -Detail ("Deleted policies.json (revert; ECH was {0})" -f $(if ($echBefore) { "on" } else { "off" })) -BackupPath $bak
            return $true
        }

        # Encrypted Client Hello (ECH): never by default; only if EnableEch was explicitly true for Strict.
        $EnableEch = Resolve-BrowserEchChoice -Mode $Mode -EnableEch:$EnableEch

        $bak = Backup-FirefoxPoliciesFile
        $policy = if ($Mode -eq "Medium") {
            @{ policies = @{
                DisableTelemetry = $true
                DisableFirefoxStudies = $true
                EnableTrackingProtection = @{ Value = $true; Cryptomining = $true; Fingerprinting = $true }
            }}
        } else {
            $pol = @{
                DisableTelemetry = $true
                DisableFirefoxStudies = $true
                DisablePocket = $true
                HTTPSOnlyMode = "force_enabled"
                EnableTrackingProtection = @{
                    Value = $true
                    Locked = $true
                    Cryptomining = $true
                    Fingerprinting = $true
                }
            }
            if ($EnableEch) {
                # Lock Encrypted Client Hello (ECH) related prefs on. Never set DisableEncryptedClientHello.
                $pol.Preferences = @{
                    "network.dns.echconfig.enabled" = @{
                        Value  = $true
                        Status = "locked"
                    }
                    "network.dns.http3_echconfig.enabled" = @{
                        Value  = $true
                        Status = "locked"
                    }
                }
            }
            @{ policies = $pol }
        }
        if (-not (Test-Path -LiteralPath $dist)) {
            New-Item -Path $dist -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $json = ($policy | ConvertTo-Json -Depth 10)
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($path, $json, $utf8)
        Write-Status ("Firefox policies -> {0}{1}" -f $Mode, $(if ($EnableEch) { " + Encrypted Client Hello (ECH) locks" } else { "" })) "Applied"
        if ($Mode -eq "Strict") {
            Write-Host "      Strict base: HTTPS-Only force, tracking protection locked, Pocket off, telemetry/studies off." -ForegroundColor DarkGray
            if ($EnableEch) {
                Write-Host "      Encrypted Client Hello (ECH): preference locks ON (handshake privacy when supported)." -ForegroundColor DarkGray
                Write-Host "      Some networks mishandle Encrypted Client Hello (ECH); use another browser or Default if needed." -ForegroundColor DarkGray
            } else {
                Write-Host "      Encrypted Client Hello (ECH): not locked (you declined the optional ECH pack)." -ForegroundColor DarkGray
            }
            Write-Host "      Revert this browser: menu 6 > Firefox > Default." -ForegroundColor DarkGray
        }
        if ($script:BrowserPolicyModes.Contains("Firefox")) { $script:BrowserPolicyModes["Firefox"] = $Mode }
        if ($script:BrowserEchLocks.Contains("Firefox")) { $script:BrowserEchLocks["Firefox"] = [bool]$EnableEch }
        Record-BrowserPolicyChange -Browser "Firefox" -ModeBefore $modeBefore -ModeAfter $Mode `
            -Detail ("Wrote Bastion {0} policies.json; ECH locks={1}" -f $Mode, $EnableEch) -BackupPath $bak
        return $true
    } catch {
        Write-Status ("Firefox policy failed: {0}" -f $_.Exception.Message) "Failed"
        return $false
    }
}

function Get-BrowserPolicyBackupDir {
    $dir = Join-Path $script:Config.LogDirectory "browser-policy-backups"
    try {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
    } catch {}
    return $dir
}

function Get-BrowserPolicyStatePath {
    return (Join-Path $script:Config.LogDirectory "Bastion-BrowserPolicies-State.json")
}

function Write-BrowserStrictDisclaimer {
    param([switch]$Compact)
    Write-Host ""
    Write-Host "  ---------- Strict mode notice ----------" -ForegroundColor Yellow
    Write-Host "  Strict favors privacy and transport hardening over maximum site compatibility." -ForegroundColor Yellow
    if (-not $Compact) {
        Write-Host "  HTTPS-Only: the browser prefers or requires HTTPS. Plain HTTP, mixed content," -ForegroundColor DarkYellow
        Write-Host "  captive portals, and some older or misconfigured hosts may fail or warn." -ForegroundColor DarkYellow
        Write-Host "  Encrypted Client Hello (ECH) is NOT included unless you answer Yes to the" -ForegroundColor DarkYellow
        Write-Host "  separate ECH pack question. ECH can hide the destination hostname in the TLS" -ForegroundColor DarkYellow
        Write-Host "  Client Hello from passive observers (when supported); some networks mishandle it." -ForegroundColor DarkYellow
        Write-Host "  Other Strict effects: stronger tracking/cookie limits (varies by browser)." -ForegroundColor DarkYellow
        Write-Host "  Suggested pattern: one browser Strict (optional ECH) for daily use; another" -ForegroundColor Cyan
        Write-Host "  Medium/Default for sites that need looser settings." -ForegroundColor Cyan
        Write-Host "  Revert one browser: menu 6 > that browser > Default (best-effort)." -ForegroundColor DarkGray
        Write-Host "  Bulletproof rollback: System Restore (menu 13 / R)." -ForegroundColor DarkGray
    } else {
        Write-Host "  May break HTTP-only or misconfigured sites and some SSO/embeds." -ForegroundColor DarkYellow
        Write-Host "  Encrypted Client Hello (ECH) is optional (asked separately; never on by default)." -ForegroundColor DarkYellow
        Write-Host "  Tip: different modes per browser. Restore Point if unsure." -ForegroundColor Cyan
    }
    Write-Host "  ----------------------------------------" -ForegroundColor Yellow
    Write-Host ""
}

function Clear-BrowserEchLocksAll {
    foreach ($k in @($script:BrowserEchLocks.Keys)) {
        $script:BrowserEchLocks[$k] = $false
    }
}

function Resolve-BrowserEchChoice {
    # Single gate: ECH only when caller passes explicit true AND mode is Strict.
    param(
        [ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch
    )
    if ($Mode -ne "Strict") { return $false }
    return [bool]$EnableEch
}

function Get-BrowserPolicyModesSummary {
    $parts = foreach ($k in @($script:BrowserPolicyModes.Keys)) {
        $mode = $script:BrowserPolicyModes[$k]
        $ech = if ($script:BrowserEchLocks.Contains($k) -and $script:BrowserEchLocks[$k] -and $mode -eq "Strict") {
            "+ECH"
        } else {
            ""
        }
        "{0}={1}{2}" -f $k, $mode, $ech
    }
    return ($parts -join ", ")
}

function Get-BrowserPolicyWantedEch {
    param([string]$BrowserName)
    if (-not $script:BrowserPolicyModes.Contains($BrowserName)) { return $false }
    if ($script:BrowserPolicyModes[$BrowserName] -ne "Strict") { return $false }
    if (-not $script:BrowserEchLocks.Contains($BrowserName)) { return $false }
    return [bool]$script:BrowserEchLocks[$BrowserName]
}

function Format-BrowserPolicyStatusLine {
    # Compact readable line for Dry Run / Audit / logs.
    param(
        [string]$Name,
        [string]$LiveMode,
        [string]$WantMode,
        [bool]$EchLive,
        [bool]$WantEch
    )
    $echL = if ($EchLive) { "Yes" } else { "No" }
    $echW = if ($WantEch) { "Yes" } else { "No" }
    return ("{0}: live {1} (ECH {2}) -> want {3} (ECH {4})" -f $Name, $LiveMode, $echL, $WantMode, $echW)
}

function Get-LiveBrowserPostureSnapshot {
    # Live OS/file detection only - never invents Bastion Apply history.
    $modes = [ordered]@{}
    $ech = [ordered]@{}
    $installed = [ordered]@{}
    foreach ($name in @("Firefox", "Chrome", "Brave")) {
        $isOn = $false
        try {
            if ($script:ProgramDefs.Contains($name)) {
                $isOn = [bool](Test-Installed -Name $name -Paths $script:ProgramDefs[$name].Paths)
            }
        } catch { $isOn = $false }
        $installed[$name] = $isOn
        if (-not $isOn) {
            $modes[$name] = "NotInstalled"
            $ech[$name] = $false
            continue
        }
        try {
            if ($name -eq "Firefox") { $modes[$name] = [string](Get-FirefoxPolicyModeFromFile) }
            else { $modes[$name] = [string](Get-ChromiumPolicyMode -Browser $name) }
        } catch { $modes[$name] = "Unknown" }
        try { $ech[$name] = [bool](Test-BrowserEchLockLive -Browser $name) } catch { $ech[$name] = $false }
    }
    return @{ Modes = $modes; Ech = $ech; Installed = $installed }
}

function Save-BrowserPolicyStateFile {
    if (-not (Ensure-BastionPaths)) { return }
    try {
        $path = Get-BrowserPolicyStatePath
        $live = Get-LiveBrowserPostureSnapshot
        $data = @{
            UpdatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ScriptVersion = $script:Config.ScriptVersion
            # Wanted (menu / Bastion-Config) vs Live (policies on disk / registry).
            Modes = [ordered]@{}
            EchLocks = [ordered]@{}
            LiveModes = $live.Modes
            LiveEch = $live.Ech
            Installed = $live.Installed
            LastChange = $script:BrowserPolicyLastChange
            Note = "Wanted modes come from Bastion config. Live modes are detected each save. Deleting this file does not fake Apply history."
        }
        foreach ($k in $script:BrowserPolicyModes.Keys) {
            $data.Modes[$k] = $script:BrowserPolicyModes[$k]
        }
        foreach ($k in $script:BrowserEchLocks.Keys) {
            $data.EchLocks[$k] = [bool]$script:BrowserEchLocks[$k]
        }
        ($data | ConvertTo-Json -Depth 8) | Out-File -LiteralPath $path -Encoding utf8 -Force
        Write-Log ("Browser policy state saved: {0}" -f $path) -NoConsole
    } catch {
        Write-Log ("Browser policy state save failed: {0}" -f $_.Exception.Message) -Level Warning -NoConsole
    }
}

function Load-BrowserPolicyStateFile {
    # Restore last-change metadata only. Wanted modes live in Bastion-Config.json.
    $path = Get-BrowserPolicyStatePath
    if (-not (Test-Path -LiteralPath $path)) { return }
    try {
        $data = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($data.LastChange) {
            $lc = $data.LastChange
            $script:BrowserPolicyLastChange = @{
                Timestamp  = [string]$lc.Timestamp
                Browser    = [string]$lc.Browser
                ModeBefore = [string]$lc.ModeBefore
                ModeAfter  = [string]$lc.ModeAfter
                Detail     = [string]$lc.Detail
                BackupPath = [string]$lc.BackupPath
                LogFile    = [string]$lc.LogFile
            }
        }
    } catch {
        Write-Log ("Browser policy state load failed: {0}" -f $_.Exception.Message) -Level Warning -NoConsole
    }
}

function Write-BastionSessionSnapshot {
    # Rewritten every launch: proves the store is real and records live detection vs Bastion files.
    if (-not (Ensure-BastionPaths)) { return }
    try {
        if (-not $script:sessionFile) {
            $script:sessionFile = Join-Path $script:Config.LogDirectory "Bastion-Session.json"
        }
        $live = Get-LiveBrowserPostureSnapshot
        $wantedModes = [ordered]@{}
        $wantedEch = [ordered]@{}
        foreach ($k in $script:BrowserPolicyModes.Keys) { $wantedModes[$k] = [string]$script:BrowserPolicyModes[$k] }
        foreach ($k in $script:BrowserEchLocks.Keys) { $wantedEch[$k] = [bool]$script:BrowserEchLocks[$k] }
        $sectionSnap = [ordered]@{}
        foreach ($k in $script:Sections.Keys) { $sectionSnap[$k] = [bool]$script:Sections[$k] }
        $data = [ordered]@{
            WrittenAt         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ScriptVersion     = $script:Config.ScriptVersion
            DataDirectory     = $script:Config.LogDirectory
            HadPriorConfig    = [bool]$script:HadPriorConfig
            HadPriorApply     = [bool]$script:HadPriorApply
            ConfigLoaded      = [bool]$script:ConfigLoaded
            FirstRunSeeded    = [bool]$script:FirstRunSeeded
            DnsProviderId     = [string]$script:DnsProviderId
            SectionsEnabled   = $sectionSnap
            WantedBrowserModes = $wantedModes
            WantedBrowserEch   = $wantedEch
            LiveBrowserModes   = $live.Modes
            LiveBrowserEch     = $live.Ech
            BrowsersInstalled  = $live.Installed
            HasConfigFile      = (Test-Path -LiteralPath $script:configFile)
            HasLastApplyFile   = (Test-Path -LiteralPath $script:undoFile)
            Note = "Apply and Dry Run detect live Windows state. Bastion-LastApply.json is only written after a real Apply. Deleting this data directory just forces a clean seed next run - it does not invent prior hardening."
        }
        ($data | ConvertTo-Json -Depth 8) | Out-File -LiteralPath $script:sessionFile -Encoding utf8 -Force
        Write-Log ("Session snapshot written: {0}" -f $script:sessionFile) -NoConsole
    } catch {
        Write-Log ("Session snapshot failed: {0}" -f $_.Exception.Message) -Level Warning -NoConsole
    }
}

function Initialize-BastionDataStore {
    # First bat/ps1 run (and every later run): ensure dirs exist, load real files if present,
    # seed defaults only when missing, rewrite session/browser state from live detection.
    # Never invent Bastion-LastApply.json without a completed Apply.
    if (-not (Ensure-BastionPaths)) {
        $script:DataStoreReady = $false
        return $false
    }

    $script:HadPriorConfig = Test-Path -LiteralPath $script:configFile
    $script:HadPriorApply  = Test-Path -LiteralPath $script:undoFile
    $script:FirstRunSeeded = $false

    Load-BastionConfig
    Load-BrowserPolicyStateFile

    if (-not $script:HadPriorConfig) {
        # Materialize a real config on first run / after wipe so the store is not empty theater.
        Save-BastionConfig
        $script:FirstRunSeeded = $true
        Write-Log "First-run (or wiped store): seeded Bastion-Config.json with defaults (no Apply history invented)."
    }

    # Always refresh browser policy state + session snapshot from live OS + current wants.
    Save-BrowserPolicyStateFile
    Write-BastionSessionSnapshot

    $script:DataStoreReady = $true
    Write-Log ("Data store ready at {0} (priorConfig={1} priorApply={2} seeded={3})" -f `
        $script:Config.LogDirectory, $script:HadPriorConfig, $script:HadPriorApply, $script:FirstRunSeeded)
    return $true
}

function Record-BrowserPolicyChange {
    param(
        [string]$Browser,
        [string]$ModeBefore,
        [string]$ModeAfter,
        [string]$Detail,
        [string]$BackupPath = ""
    )
    $script:BrowserPolicyLastChange = @{
        Timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Browser    = $Browser
        ModeBefore = $ModeBefore
        ModeAfter  = $ModeAfter
        Detail     = $Detail
        BackupPath = $BackupPath
        LogFile    = $script:logFile
    }
    Write-Log ("BrowserPolicy {0}: {1} -> {2} | {3} | backup={4}" -f $Browser, $ModeBefore, $ModeAfter, $Detail, $BackupPath)
    Save-BrowserPolicyStateFile
}

function Backup-FirefoxPoliciesFile {
    $path = Get-FirefoxPoliciesPath
    if (-not (Test-Path -LiteralPath $path)) { return "" }
    try {
        $dir = Get-BrowserPolicyBackupDir
        $dest = Join-Path $dir ("firefox-policies-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
        Copy-Item -LiteralPath $path -Destination $dest -Force -ErrorAction Stop
        Write-Log ("Firefox policies backup: {0}" -f $dest) -NoConsole
        return $dest
    } catch {
        Write-Log ("Firefox policies backup failed: {0}" -f $_.Exception.Message) -Level Warning -NoConsole
        return ""
    }
}

function Get-ChromiumPolicyBase {
    param([ValidateSet("Chrome","Brave")][string]$Browser)
    if ($Browser -eq "Brave") {
        return "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
    }
    return "HKLM:\SOFTWARE\Policies\Google\Chrome"
}

function Backup-ChromiumPolicyValues {
    param([ValidateSet("Chrome","Brave")][string]$Browser)
    $base = Get-ChromiumPolicyBase -Browser $Browser
    $snap = [ordered]@{ Browser = $Browser; Path = $base; Values = [ordered]@{}; Existed = $false }
    if (-not (Test-Path -LiteralPath $base)) {
        return $snap
    }
    $snap.Existed = $true
    try {
        $props = Get-ItemProperty -LiteralPath $base -ErrorAction Stop
        foreach ($n in $script:ChromiumBastionValueNames) {
            if ($null -ne $props.PSObject.Properties[$n]) {
                $snap.Values[$n] = $props.$n
            }
        }
        $dir = Get-BrowserPolicyBackupDir
        $dest = Join-Path $dir ("{0}-policy-{1}.json" -f $Browser.ToLowerInvariant(), (Get-Date -Format "yyyyMMdd-HHmmss"))
        ($snap | ConvertTo-Json -Depth 6) | Out-File -LiteralPath $dest -Encoding utf8 -Force
        Write-Log ("{0} policy backup: {1}" -f $Browser, $dest) -NoConsole
        $snap.BackupFile = $dest
        return $snap
    } catch {
        Write-Log ("{0} policy backup failed: {1}" -f $Browser, $_.Exception.Message) -Level Warning -NoConsole
        return $snap
    }
}

function Get-ChromiumPolicyMode {
    param([ValidateSet("Chrome","Brave")][string]$Browser)
    $base = Get-ChromiumPolicyBase -Browser $Browser
    if (-not (Test-Path -LiteralPath $base)) { return "Default" }
    try {
        $c = Get-ItemProperty -LiteralPath $base -ErrorAction SilentlyContinue
        if ($null -eq $c) { return "Default" }
        if ($c.HttpsOnlyMode -eq 2 -or $c.DefaultCookiesSetting -eq 4 -or $c.BastionEchLock -eq 1) { return "Strict" }
        if ($null -ne $c.MetricsReportingEnabled -or $null -ne $c.BlockThirdPartyCookies -or $c.BastionManaged -eq 1) {
            return "Medium"
        }
        # Key exists but no Bastion markers - treat as custom foreign policy.
        return "Custom"
    } catch {
        return "Custom"
    }
}

function Test-ChromiumEchLockPresent {
    param([ValidateSet("Chrome","Brave")][string]$Browser)
    $base = Get-ChromiumPolicyBase -Browser $Browser
    if (-not (Test-Path -LiteralPath $base)) { return $false }
    try {
        $v = (Get-ItemProperty -LiteralPath $base -Name BastionEchLock -ErrorAction SilentlyContinue).BastionEchLock
        return ($v -eq 1)
    } catch {
        return $false
    }
}

function Test-BrowserEchLockLive {
    param([ValidateSet("Firefox","Chrome","Brave")][string]$Browser)
    switch ($Browser) {
        "Firefox" { return (Test-FirefoxEchLocksPresent) }
        "Chrome"  { return (Test-ChromiumEchLockPresent -Browser Chrome) }
        "Brave"   { return (Test-ChromiumEchLockPresent -Browser Brave) }
    }
    return $false
}

function Remove-ChromiumBastionValues {
    param([ValidateSet("Chrome","Brave")][string]$Browser)
    $base = Get-ChromiumPolicyBase -Browser $Browser
    if (-not (Test-Path -LiteralPath $base)) {
        Write-Status ("{0} already default (no policy key)" -f $Browser) "Already"
        return $true
    }
    $removed = 0
    foreach ($n in $script:ChromiumBastionValueNames) {
        try {
            if ($null -ne (Get-ItemProperty -LiteralPath $base -Name $n -ErrorAction SilentlyContinue)) {
                Remove-ItemProperty -LiteralPath $base -Name $n -Force -ErrorAction Stop
                $removed++
                Write-Log ("Removed {0} policy value: {1}" -f $Browser, $n) -NoConsole
            }
        } catch {
            Write-Log ("Could not remove {0}\{1}: {2}" -f $Browser, $n, $_.Exception.Message) -Level Warning -NoConsole
        }
    }
    # If no values remain, remove the key.
    try {
        $key = Get-Item -LiteralPath $base -ErrorAction SilentlyContinue
        if ($key -and @($key.GetValueNames()).Count -eq 0) {
            Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log ("Removed empty policy key: {0}" -f $base) -NoConsole
        }
    } catch {}
    if ($removed -gt 0) {
        Write-Status ("{0} Bastion policy values removed ({1})" -f $Browser, $removed) "Applied"
        Write-Host "      Non-Bastion policy values (if any) were left in place." -ForegroundColor DarkGray
    } else {
        Write-Status ("{0}: no Bastion-managed values found" -f $Browser) "Already"
    }
    return $true
}

function Set-ChromiumPolicyMode {
    param(
        [ValidateSet("Chrome","Brave")][string]$Browser,
        [ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch = $false
    )
    $base = Get-ChromiumPolicyBase -Browser $Browser
    $modeBefore = Get-ChromiumPolicyMode -Browser $Browser
    $echBefore = Test-ChromiumEchLockPresent -Browser $Browser
    try {
        if ($Mode -eq "Default") {
            $bak = Backup-ChromiumPolicyValues -Browser $Browser
            $bakPath = if ($bak.BackupFile) { [string]$bak.BackupFile } else { "" }
            [void](Remove-ChromiumBastionValues -Browser $Browser)
            if ($script:BrowserPolicyModes.Contains($Browser)) { $script:BrowserPolicyModes[$Browser] = "Default" }
            if ($script:BrowserEchLocks.Contains($Browser)) { $script:BrowserEchLocks[$Browser] = $false }
            Record-BrowserPolicyChange -Browser $Browser -ModeBefore $modeBefore -ModeAfter "Default" `
                -Detail ("Removed Bastion Chromium values (ECH intent was {0})" -f $(if ($echBefore) { "on" } else { "off" })) -BackupPath $bakPath
            return $true
        }

        # Encrypted Client Hello (ECH) pack: never by default; only explicit Yes + Strict.
        $EnableEch = Resolve-BrowserEchChoice -Mode $Mode -EnableEch:$EnableEch

        $bak = Backup-ChromiumPolicyValues -Browser $Browser
        $bakPath = if ($bak.BackupFile) { [string]$bak.BackupFile } else { "" }

        if ($Browser -eq "Chrome") {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Google")) {
                New-Item "HKLM:\SOFTWARE\Policies\Google" -Force | Out-Null
            }
        } else {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\BraveSoftware")) {
                New-Item "HKLM:\SOFTWARE\Policies\BraveSoftware" -Force | Out-Null
            }
        }
        if (-not (Test-Path $base)) { New-Item $base -Force | Out-Null }

        foreach ($n in @("BlockThirdPartyCookies","DefaultCookiesSetting","HttpsOnlyMode","DnsOverHttpsMode","BastionEchLock","EncryptedClientHelloEnabled")) {
            try { Remove-ItemProperty -LiteralPath $base -Name $n -Force -ErrorAction SilentlyContinue } catch {}
        }

        New-ItemProperty $base -Name "BastionManaged" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty $base -Name "MetricsReportingEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty $base -Name "SafeBrowsingEnabled" -Value 1 -PropertyType DWord -Force | Out-Null

        if ($Mode -eq "Strict") {
            New-ItemProperty $base -Name "HttpsOnlyMode" -Value 2 -PropertyType DWord -Force | Out-Null
            New-ItemProperty $base -Name "BlockThirdPartyCookies" -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty $base -Name "DnsOverHttpsMode" -Value 2 -PropertyType DWord -Force | Out-Null
            Write-Host ("      {0} Strict: HTTPS-Only force, third-party cookie block, DNS-over-HTTPS preference, telemetry off." -f $Browser) -ForegroundColor DarkGray
            if ($EnableEch) {
                # Intent marker + best-effort Chromium policy. Not identical to Firefox preference locks.
                New-ItemProperty $base -Name "BastionEchLock" -Value 1 -PropertyType DWord -Force | Out-Null
                try {
                    New-ItemProperty $base -Name "EncryptedClientHelloEnabled" -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                } catch {}
                Write-Host ("      Encrypted Client Hello (ECH) pack: ON for {0}." -f $Browser) -ForegroundColor DarkGray
                Write-Host "      Chromium cannot use Firefox policies.json prefs; Bastion records ECH intent and applies" -ForegroundColor DarkGray
                Write-Host "      the strongest transport policies available (HTTPS-Only + DNS-over-HTTPS + optional ECH policy)." -ForegroundColor DarkGray
            } else {
                Write-Host ("      Encrypted Client Hello (ECH) pack: OFF for {0} (optional; not selected)." -f $Browser) -ForegroundColor DarkGray
            }
        } else {
            New-ItemProperty $base -Name "BlockThirdPartyCookies" -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Host ("      {0} Medium: telemetry off, Safe Browsing on, third-party cookies blocked." -f $Browser) -ForegroundColor DarkGray
        }

        Write-Status ("{0} policies -> {1}{2}" -f $Browser, $Mode, $(if ($EnableEch) { " + ECH pack" } else { "" })) "Applied"
        if ($script:BrowserPolicyModes.Contains($Browser)) { $script:BrowserPolicyModes[$Browser] = $Mode }
        if ($script:BrowserEchLocks.Contains($Browser)) { $script:BrowserEchLocks[$Browser] = [bool]$EnableEch }
        Record-BrowserPolicyChange -Browser $Browser -ModeBefore $modeBefore -ModeAfter $Mode `
            -Detail ("Wrote Bastion {0} pack under {1}; ECH pack={2}" -f $Mode, $base, $EnableEch) -BackupPath $bakPath
        Write-Host ("      Revert this browser only: menu 6 > {0} > Default." -f $Browser) -ForegroundColor DarkGray
        return $true
    } catch {
        Write-Status ("{0} policy failed: {1}" -f $Browser, $_.Exception.Message) "Failed"
        return $false
    }
}

function Set-ChromePolicyMode {
    param(
        [ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch = $false
    )
    return (Set-ChromiumPolicyMode -Browser Chrome -Mode $Mode -EnableEch:$EnableEch)
}

function Set-BravePolicyMode {
    param(
        [ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch = $false
    )
    return (Set-ChromiumPolicyMode -Browser Brave -Mode $Mode -EnableEch:$EnableEch)
}

function Get-BastionDnsProvider {
    param([string]$Id = $script:DnsProviderId)
    if ([string]::IsNullOrWhiteSpace($Id)) { $Id = "Quad9" }
    if ($script:DnsProviders.Contains($Id)) { return $script:DnsProviders[$Id] }
    return $script:DnsProviders["Quad9"]
}

function Get-BastionDnsProviderLabel {
    param([string]$Id = $script:DnsProviderId)
    if ([string]::IsNullOrWhiteSpace($Id) -or $Id -eq "None" -or -not $script:Sections["DNS"]) {
        return "Do not change DNS"
    }
    $p = Get-BastionDnsProvider -Id $Id
    if ($p -and $p.Primary) {
        return ("{0} ({1})" -f $p.DisplayName, $p.Primary)
    }
    return "Do not change DNS"
}

function Get-BastionDnsAdapters {
    # Unified filter for Dry Run, Audit, and Apply so results stay consistent.
    return @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq "Up" -and
        $_.InterfaceDescription -notmatch "Loopback|Bluetooth|Virtual|Hyper-V|vEthernet|WSL|Docker|VPN|TAP|TUN|WireGuard|Mullvad|OpenVPN|Cisco AnyConnect|NordLynx"
    })
}

function Get-AdapterDnsServers {
    param([int]$InterfaceIndex)
    try {
        return @(Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            ForEach-Object { $_.ServerAddresses } | ForEach-Object { $_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    } catch {
        return @()
    }
}

function Test-AdapterDnsMatchesProvider {
    param(
        [int]$InterfaceIndex,
        [string]$ProviderId = $script:DnsProviderId
    )
    $prov = Get-BastionDnsProvider -Id $ProviderId
    if (-not $prov -or -not $prov.Primary) { return $false }
    $dns = @(Get-AdapterDnsServers -InterfaceIndex $InterfaceIndex)
    if ($dns.Count -lt 1) { return $false }
    return ($dns[0] -eq [string]$prov.Primary)
}

function Set-BastionDnsProviderId {
    param([Parameter(Mandatory)][string]$Id)
    if (-not $script:DnsProviders.Contains($Id)) { return $false }
    $script:DnsProviderId = $Id
    if ($Id -eq "None") {
        $script:Sections["DNS"] = $false
    } else {
        $script:Sections["DNS"] = $true
    }
    return $true
}

function Save-BastionConfig {
    if (-not (Ensure-BastionPaths)) { return }
    try {
        $data = @{
            Version = $script:Config.ScriptVersion
            SavedAt = Get-Date -Format "yyyy-MM-dd HH:mm"
            Sections = [ordered]@{}
            SelectedApps = @($script:SelectedApps)
            GlobalInstallRoot = $script:GlobalInstallRoot
            ProgramInstallRoots = @{}
            BrowserPolicyMode = $script:BrowserPolicyMode
            BrowserPolicyModes = [ordered]@{}
            BrowserEchLocks = [ordered]@{}
            DnsProviderId = $script:DnsProviderId
        }
        foreach ($k in $script:Sections.Keys) { $data.Sections[$k] = [bool]$script:Sections[$k] }
        foreach ($k in $script:ProgramInstallRoots.Keys) { $data.ProgramInstallRoots[$k] = $script:ProgramInstallRoots[$k] }
        foreach ($k in $script:BrowserPolicyModes.Keys) { $data.BrowserPolicyModes[$k] = [string]$script:BrowserPolicyModes[$k] }
        foreach ($k in $script:BrowserEchLocks.Keys) { $data.BrowserEchLocks[$k] = [bool]$script:BrowserEchLocks[$k] }
        $data | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $script:configFile -Encoding utf8 -Force
    } catch {
        Write-Log ("Config save failed: {0}" -f $_.Exception.Message) -Level Warning
    }
}

function Load-BastionConfig {
    if (-not (Test-Path -LiteralPath $script:configFile)) { return }
    try {
        $data = Get-Content -LiteralPath $script:configFile -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($data.Sections) {
            foreach ($prop in $data.Sections.PSObject.Properties) {
                if ($script:Sections.Contains($prop.Name)) {
                    $script:Sections[$prop.Name] = [bool]$prop.Value
                }
            }
        }
        if ($data.SelectedApps) {
            $script:SelectedApps.Clear()
            foreach ($a in @($data.SelectedApps)) {
                if ($script:ProgramDefs.Contains("$a")) { [void]$script:SelectedApps.Add("$a") }
            }
            # Drop names already present on disk so the install menu is not pre-checked.
            Sync-ProgramInstallQueue
        }
        if ($data.BrowserPolicyMode) { $script:BrowserPolicyMode = [string]$data.BrowserPolicyMode }
        if ($data.BrowserPolicyModes) {
            foreach ($prop in $data.BrowserPolicyModes.PSObject.Properties) {
                if ($script:BrowserPolicyModes.Contains($prop.Name)) {
                    $v = [string]$prop.Value
                    if ($v -in @("Default","Medium","Strict")) {
                        $script:BrowserPolicyModes[$prop.Name] = $v
                    }
                }
            }
        } elseif ($data.BrowserPolicyMode -and $data.BrowserPolicyMode -in @("Default","Medium","Strict")) {
            foreach ($k in @($script:BrowserPolicyModes.Keys)) {
                $script:BrowserPolicyModes[$k] = [string]$data.BrowserPolicyMode
            }
        }
        # Start from all-false, then apply only explicit saved Yes flags (never infer ECH from Strict alone).
        Clear-BrowserEchLocksAll
        if ($data.BrowserEchLocks) {
            foreach ($prop in $data.BrowserEchLocks.PSObject.Properties) {
                if ($script:BrowserEchLocks.Contains($prop.Name) -and [bool]$prop.Value) {
                    # Only honor saved ECH Yes when that browser's saved mode is Strict.
                    $modeForBrowser = if ($script:BrowserPolicyModes.Contains($prop.Name)) {
                        $script:BrowserPolicyModes[$prop.Name]
                    } else { "Default" }
                    if ($modeForBrowser -eq "Strict") {
                        $script:BrowserEchLocks[$prop.Name] = $true
                    }
                }
            }
        }
        if ($data.DnsProviderId -and $script:DnsProviders.Contains([string]$data.DnsProviderId)) {
            $script:DnsProviderId = [string]$data.DnsProviderId
            if ($script:DnsProviderId -eq "None") { $script:Sections["DNS"] = $false }
        }
        # If DNS section is off after load, treat provider as None for clear UI unless a real provider was saved.
        if (-not $script:Sections["DNS"] -and $script:DnsProviderId -ne "None") {
            # Keep last real provider in memory for re-enable, but label shows do-not-change via Sections.
        }
        $script:ProgramInstallRoots = @{}
        $vols = @(Get-AvailableInstallVolumes)
        if ($data.ProgramInstallRoots) {
            foreach ($prop in $data.ProgramInstallRoots.PSObject.Properties) {
                if ($script:ProgramDefs.Contains($prop.Name) -and $prop.Value) {
                    $check = Test-SafeInstallRoot -Path ([string]$prop.Value) -AllowedVolumes $vols
                    if ($check.Ok) { $script:ProgramInstallRoots[$prop.Name] = $check.Path }
                }
            }
        }
        if ($data.GlobalInstallRoot) {
            $check = Test-SafeInstallRoot -Path ([string]$data.GlobalInstallRoot) -AllowedVolumes $vols
            $script:GlobalInstallRoot = $(if ($check.Ok) { $check.Path } else { $null })
        }
        $script:ConfigLoaded = $true
    } catch {
        Write-Log ("Config load failed: {0}" -f $_.Exception.Message) -Level Warning
    }
}

function Save-UndoData($Data) {
    if (-not (Ensure-BastionPaths)) { return }
    try {
        $Data | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $script:undoFile -Encoding utf8 -Force
    } catch {
        Write-Log ("Undo save failed: {0}" -f $_.Exception.Message) -Level Warning
    }
}

function Get-LastApplyInfo {
    if (-not (Test-Path -LiteralPath $script:undoFile)) { return $null }
    try {
        $d = Get-Content -LiteralPath $script:undoFile -Raw -ErrorAction Stop | ConvertFrom-Json
        return [PSCustomObject]@{
            Timestamp = $d.Timestamp
            ScriptVersion = $d.ScriptVersion
            SectionsRun = @($d.SectionsRun)
        }
    } catch { return $null }
}

function Convert-RestorePointTime {
    param($CreationTime)
    if ($null -eq $CreationTime) { return $null }
    if ($CreationTime -is [datetime]) { return $CreationTime }
    $s = [string]$CreationTime
    try {
        return [System.Management.ManagementDateTimeConverter]::ToDateTime($s)
    } catch {}
    try { return [datetime]::Parse($s) } catch {}
    return $null
}

function Get-RestorePointStatus {
    $status = [ordered]@{
        Ok = $false
        HasAny = $false
        HasRecent = $false
        RecentHours = 48
        Points = @()
        RecentPoints = @()
        Error = ""
    }
    try {
        $all = @(Get-ComputerRestorePoint -ErrorAction Stop)
        $status.HasAny = ($all.Count -gt 0)
        $status.Ok = $true
        $cutoff = (Get-Date).AddHours(-48)
        $enriched = foreach ($rp in $all) {
            $dt = Convert-RestorePointTime $rp.CreationTime
            [PSCustomObject]@{
                SequenceNumber = $rp.SequenceNumber
                Description = $rp.Description
                CreationTime = $dt
                CreationTimeRaw = $rp.CreationTime
            }
        }
        $status.Points = @($enriched | Sort-Object CreationTime -Descending)
        $status.RecentPoints = @($status.Points | Where-Object {
            ($null -ne $_.CreationTime -and $_.CreationTime -ge $cutoff) -or
            ("$($_.Description)" -match 'Bastion')
        } | Select-Object -First 8)
        if ($status.RecentPoints.Count -gt 0) { $status.HasRecent = $true }
    } catch {
        $status.Error = $_.Exception.Message
        $status.Ok = $false
    }
    return $status
}

function Show-RestorePointMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "SYSTEM RESTORE POINT"
        Write-Host "  Create a named restore point before Apply / Quick Harden / BloatApps." -ForegroundColor Cyan
        Write-Host "  Requires System Protection enabled on the OS drive (sysdm.cpl)." -ForegroundColor DarkGray
        Write-Host ""

        $st = Get-RestorePointStatus
        if (-not $st.Ok) {
            Write-Host "  Could not query restore points." -ForegroundColor Red
            Write-Host ("  {0}" -f $st.Error) -ForegroundColor DarkGray
            Write-Host "  Next step: sysdm.cpl > System Protection > enable for C: > create manually if needed." -ForegroundColor Yellow
        } elseif (-not $st.HasAny) {
            Write-Host "  Status: NO restore points found on this system." -ForegroundColor Red
        } else {
            if ($st.HasRecent) {
                Write-Host "  Status: Recent / Bastion-related restore point(s) found." -ForegroundColor Green
            } else {
                Write-Host "  Status: Points exist, but none in the last 48 hours (and no Bastion-named)." -ForegroundColor Yellow
            }
            Write-Host ""
            Write-Host "  Latest points:" -ForegroundColor Cyan
            foreach ($rp in @($st.Points | Select-Object -First 6)) {
                $when = if ($rp.CreationTime) { $rp.CreationTime.ToString("yyyy-MM-dd HH:mm") } else { "?" }
                $desc = if ($rp.Description) { $rp.Description } else { "(no description)" }
                Write-Host ("    [{0}] {1}" -f $when, $desc) -ForegroundColor White
            }
        }

        Write-Host ""
        Write-Host "  1  Create restore point (choose / confirm name)" -ForegroundColor Green
        Write-Host "  0  Back" -ForegroundColor DarkGray
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0", "1")
        if ($c -eq "0") { return }
        if ($c -eq "1") {
            Write-Host ""
            $ok = New-BastionRestorePoint -SuggestedName ("Bastion v{0} - {1}" -f $script:Config.ScriptVersion, (Get-Date -Format "yyyy-MM-dd HH:mm"))
            if ($ok) {
                Write-Host "  You can now run Apply or Quick Harden with a known fallback." -ForegroundColor Green
            }
            Wait-ForKey
        }
    }
}

function Confirm-RestorePointBeforeApply {
    param([string]$ActionLabel = "Apply")
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor DarkRed
    Write-Host ("  RESTORE POINT CHECK  ({0})" -f $ActionLabel) -ForegroundColor Yellow
    Write-Host "  ================================================================" -ForegroundColor DarkRed

    $st = Get-RestorePointStatus
    if (-not $st.Ok) {
        Write-Host "  WARNING: Cannot verify restore points." -ForegroundColor Red
        Write-Host ("  {0}" -f $st.Error) -ForegroundColor DarkGray
        Write-Host "  Strongly recommended: enable System Protection, create a point (menu R), then retry." -ForegroundColor Yellow
        if ((Read-YesNo -Prompt "  Try to create a restore point now (Y/N)?") -eq "Y") {
            $ok = New-BastionRestorePoint
            if ($ok) { return $true }
        }
        Write-Host "  Continuing without a verified restore point is risky." -ForegroundColor Red
        return (Read-ConfirmYes -Prompt ("  Type YES to continue {0} WITHOUT a verified restore point" -f $ActionLabel))
    }

    if ($st.HasRecent) {
        Write-Host "  Recent restore coverage detected (last 48h and/or Bastion-named):" -ForegroundColor Green
        foreach ($rp in @($st.RecentPoints | Select-Object -First 5)) {
            $when = if ($rp.CreationTime) { $rp.CreationTime.ToString("yyyy-MM-dd HH:mm") } else { "?" }
            $desc = if ($rp.Description) { $rp.Description } else { "(no description)" }
            Write-Host ("    [{0}] {1}" -f $when, $desc) -ForegroundColor White
        }
        Write-Host ""
        Write-Host "  You can continue, or create another named point first." -ForegroundColor Cyan
        $choice = Read-MenuChoice -Prompt "  1 Continue  2 Create another point first  0 Cancel" -Valid @("0", "1", "2")
        if ($choice -eq "0") { return $false }
        if ($choice -eq "2") {
            $ok = New-BastionRestorePoint
            if (-not $ok) {
                Write-Host "  Create failed." -ForegroundColor Red
                return (Read-ConfirmYes -Prompt ("  Type YES to continue {0} anyway" -f $ActionLabel))
            }
        }
        return $true
    }

    Write-Host "  *** NO recent restore point found (48 hours / Bastion-named). ***" -ForegroundColor Red
    if ($st.HasAny) {
        Write-Host "  Older points exist, but a fresh point is strongly recommended before hardening." -ForegroundColor Yellow
        foreach ($rp in @($st.Points | Select-Object -First 3)) {
            $when = if ($rp.CreationTime) { $rp.CreationTime.ToString("yyyy-MM-dd HH:mm") } else { "?" }
            Write-Host ("    [{0}] {1}" -f $when, $rp.Description) -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  No System Restore points exist on this PC." -ForegroundColor Red
        Write-Host "  If Apply breaks logon or a feature, recovery is much harder without one." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  Recommended: create a named restore point now (takes about a minute)." -ForegroundColor Green
    $choice = Read-MenuChoice -Prompt "  1 Create restore point now  2 Continue without  0 Cancel" -Valid @("0", "1", "2")
    if ($choice -eq "0") { return $false }
    if ($choice -eq "1") {
        $ok = New-BastionRestorePoint
        if ($ok) { return $true }
        Write-Host "  Create failed. Enable System Protection (sysdm.cpl) if needed." -ForegroundColor Red
        return (Read-ConfirmYes -Prompt ("  Type YES to continue {0} WITHOUT a restore point" -f $ActionLabel))
    }
    Write-Host "  You chose to continue without a fresh restore point." -ForegroundColor Yellow
    return (Read-ConfirmYes -Prompt ("  Type YES to confirm {0} with NO fresh restore point" -f $ActionLabel))
}

function New-BastionRestorePoint {
    param([string]$SuggestedName = "")
    if ([string]::IsNullOrWhiteSpace($SuggestedName)) {
        $SuggestedName = ("Bastion v{0} - {1}" -f $script:Config.ScriptVersion, (Get-Date -Format "yyyy-MM-dd HH:mm"))
    }
    Write-Host ""
    Write-Host "  --------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  CREATE SYSTEM RESTORE POINT" -ForegroundColor Cyan
    Write-Host "  --------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host ("  Suggested name: {0}" -f $SuggestedName) -ForegroundColor DarkGray
    Write-Host "  Press Enter to accept, or type a custom name." -ForegroundColor DarkGray
    try { $custom = Read-Host "  Restore point name" } catch { $custom = "" }
    if ([string]::IsNullOrWhiteSpace($custom)) { $custom = $SuggestedName }
    $custom = $custom.Trim()
    if ($custom.Length -gt 200) { $custom = $custom.Substring(0, 200) }
    Write-Host ("  Creating: {0} ..." -f $custom) -ForegroundColor White
    try {
        Checkpoint-Computer -Description $custom -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Host ("  Restore point created: {0}" -f $custom) -ForegroundColor Green
        Write-Log ("Restore point created: {0}" -f $custom)
        return $true
    } catch {
        Write-Host ("  Restore point FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
        Write-Host "  Next step: sysdm.cpl > System Protection > turn on for OS drive > Create." -ForegroundColor Yellow
        Write-Log ("Restore point failed: {0}" -f $_.Exception.Message) -Level Warning
        return $false
    }
}

function Invoke-DryRun {
    Clear-BastionScreen
    Write-Header "DRY RUN (NO CHANGES)"
    Write-Host "  State-aware preview of what Apply would do with current toggles." -ForegroundColor Cyan
    Write-Host ""

    $would = 0
    $already = 0
    $skip = 0

    function Show-DryItem([string]$Section, [string]$Verdict, [string]$Detail) {
        $col = "White"
        switch ($Verdict) {
            "Would change" { $col = "Yellow"; $script:dryWould++ }
            "Already OK"   { $col = "Green";  $script:dryAlready++ }
            "Skipped"      { $col = "DarkGray"; $script:drySkip++ }
        }
        Write-Host ("  [{0}]" -f $Section) -ForegroundColor Cyan
        Write-Host ("      {0}: {1}" -f $Verdict, $Detail) -ForegroundColor $col
    }

    $script:dryWould = 0; $script:dryAlready = 0; $script:drySkip = 0

    if (-not $script:Sections["Firewall"]) { Show-DryItem "Firewall" "Skipped" "Section disabled" }
    else {
        try {
            $fwOk = $true
            foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) {
                if (-not $p.Enabled -or $p.DefaultInboundAction -ne "Block") { $fwOk = $false }
            }
            if ($fwOk) { Show-DryItem "Firewall" "Already OK" "Profiles enabled, Inbound=Block" }
            else { Show-DryItem "Firewall" "Would change" "Set profiles Enabled + Inbound=Block; disable discovery/RDP/WinRM/mDNS inbound groups if enabled" }
        } catch { Show-DryItem "Firewall" "Would change" "Could not read profiles; Apply would set Inbound=Block" }
    }

    if (-not $script:Sections["HighRiskServices"]) { Show-DryItem "HighRiskServices" "Skipped" "Section disabled" }
    else {
        $need = @()
        foreach ($s in (Get-HighRiskServicesForApply)) {
            $svc = Get-ServiceState $s
            if ($svc -and $svc.StartType -ne "Disabled") { $need += $s }
        }
        if ($need.Count -eq 0) { Show-DryItem "HighRiskServices" "Already OK" "Target services absent or already disabled" }
        else { Show-DryItem "HighRiskServices" "Would change" ("Disable: {0}" -f ($need -join ", ")) }
    }

    if (-not $script:Sections["SMBv1"]) { Show-DryItem "SMBv1" "Skipped" "Section disabled" }
    else {
        try {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
            if ($feat -and $feat.State -eq "Enabled") { Show-DryItem "SMBv1" "Would change" "Disable SMB1Protocol optional feature" }
            else { Show-DryItem "SMBv1" "Already OK" "SMB1 disabled or not present" }
        } catch { Show-DryItem "SMBv1" "Would change" "Unable to query feature; Apply would try disable" }
    }

    if (-not $script:Sections["OneDrive"]) { Show-DryItem "OneDrive" "Skipped" "Section disabled" }
    else {
        $od = Get-OneDriveStatus
        if ($od.Present) { Show-DryItem "OneDrive" "Would change" ("Uninstall client ({0})" -f $od.Detail) }
        else { Show-DryItem "OneDrive" "Already OK" "OneDrive client not present" }
    }

    if (-not $script:Sections["DeliveryOptimization"]) { Show-DryItem "DeliveryOptimization" "Skipped" "Section disabled" }
    else {
        try {
            $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
            $cur = (Get-ItemProperty $key -Name DODownloadMode -ErrorAction SilentlyContinue).DODownloadMode
            if ($cur -eq 0) { Show-DryItem "DeliveryOptimization" "Already OK" "DODownloadMode=0 (HTTP only)" }
            else { Show-DryItem "DeliveryOptimization" "Would change" "Set DODownloadMode=0 (disable P2P update sharing)" }
        } catch { Show-DryItem "DeliveryOptimization" "Would change" "Set DODownloadMode=0" }
    }

    if (-not $script:Sections["DNS"] -or $script:DnsProviderId -eq "None") {
        Show-DryItem "DNS" "Skipped" "Do not change DNS (section off or provider None)"
    } else {
        $prov = Get-BastionDnsProvider
        $label = if ($prov -and $prov.Primary) { ("{0} / {1}" -f $prov.Primary, $prov.Secondary) } else { "selected provider" }
        try {
            $adapters = @(Get-BastionDnsAdapters)
            $need = @(); $ok = @()
            foreach ($a in $adapters) {
                try {
                    if (Test-AdapterDnsMatchesProvider -InterfaceIndex $a.ifIndex) { $ok += $a.Name }
                    else { $need += $a.Name }
                } catch { $need += $a.Name }
            }
            if ($need.Count -eq 0 -and $ok.Count -gt 0) {
                Show-DryItem "DNS" "Already OK" ("{0}-first on: {1} (VPN may still override while connected)" -f $prov.DisplayName, ($ok -join ", "))
            } elseif ($ok.Count -gt 0) {
                Show-DryItem "DNS" "Would change" ("Need {0} on: {1}; already OK: {2}" -f $prov.DisplayName, ($need -join ", "), ($ok -join ", "))
            } else {
                Show-DryItem "DNS" "Would change" ("Set eligible adapters to {0} ({1})" -f $prov.DisplayName, $label)
            }
        } catch {
            Show-DryItem "DNS" "Would change" ("Set eligible adapters to {0} (could not fully query current DNS)" -f $prov.DisplayName)
        }
    }

    if (-not $script:Sections["Defender"]) { Show-DryItem "Defender" "Skipped" "Section disabled" }
    else {
        try {
            $pref = Get-MpPreference -ErrorAction Stop
            $np = ($pref.EnableNetworkProtection -eq 1 -or "$($pref.EnableNetworkProtection)" -eq "Enabled")
            $cfa = ($pref.EnableControlledFolderAccess -eq 1 -or "$($pref.EnableControlledFolderAccess)" -eq "Enabled")
            if ($np -and $cfa) { Show-DryItem "Defender" "Already OK" "Network Protection + CFA on (Apply still refreshes CFA allow-list)" }
            else { Show-DryItem "Defender" "Would change" "Enable Network Protection and/or CFA; allow-list known app paths" }
        } catch { Show-DryItem "Defender" "Would change" "Enable NP + CFA if Defender available" }
    }

    if (-not $script:Sections["PowerShellAuditing"]) { Show-DryItem "PowerShellAuditing" "Skipped" "Section disabled" }
    else {
        try {
            $v = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
            if ($v -eq 1) { Show-DryItem "PowerShellAuditing" "Already OK" "Script Block Logging enabled" }
            else { Show-DryItem "PowerShellAuditing" "Would change" "Enable Script Block Logging policy" }
        } catch { Show-DryItem "PowerShellAuditing" "Would change" "Enable Script Block Logging policy" }
    }

    if (-not $script:Sections["ExploitProtection"]) { Show-DryItem "ExploitProtection" "Skipped" "Section disabled" }
    else {
        try {
            $mit = Get-ProcessMitigation -System -ErrorAction Stop
            $depOn = ($mit.DEP.Enable -eq "ON" -or "$($mit.DEP.Enable)" -eq "ON" -or $mit.DEP.Enable -eq $true)
            $sehOn = $true
            try { $sehOn = ($mit.SEHOP.Enable -eq "ON" -or "$($mit.SEHOP.Enable)" -eq "ON" -or $mit.SEHOP.Enable -eq $true) } catch {}
            if ($depOn -and $sehOn) {
                Show-DryItem "ExploitProtection" "Already OK" "DEP/SEHOP already ON (mild profile; StrictHandle not applied by Bastion)"
            } else {
                Show-DryItem "ExploitProtection" "Would change" "Apply mild system mitigations (DEP, SEHOP, BottomUp, HighEntropy; no StrictHandle)"
            }
        } catch {
            Show-DryItem "ExploitProtection" "Would change" "Apply mild mitigations (could not query ProcessMitigation)"
        }
    }

    if (-not $script:Sections["LSAProtection"]) { Show-DryItem "LSAProtection" "Skipped" "Section disabled" }
    else {
        try {
            $lsa = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
            if ($lsa -eq 1) { Show-DryItem "LSAProtection" "Already OK" "RunAsPPL=1 (reboot still needed if just set)" }
            else { Show-DryItem "LSAProtection" "Would change" "Set RunAsPPL=1 (requires reboot)" }
        } catch { Show-DryItem "LSAProtection" "Would change" "Set RunAsPPL=1" }
    }

    if (-not $script:Sections["ScheduledTasks"]) { Show-DryItem "ScheduledTasks" "Skipped" "Section disabled" }
    else {
        $taskPaths = @(
            "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
        )
        $need = @()
        foreach ($tp in $taskPaths) {
            try {
                $task = Get-ScheduledTask -TaskPath (Split-Path $tp -Parent) -TaskName (Split-Path $tp -Leaf) -ErrorAction SilentlyContinue
                if ($task -and $task.State -ne "Disabled") { $need += $task.TaskName }
            } catch {}
        }
        if ($need.Count -eq 0) {
            Show-DryItem "ScheduledTasks" "Already OK" "CEIP/Compatibility tasks absent or already disabled"
        } else {
            Show-DryItem "ScheduledTasks" "Would change" ("Disable: {0}" -f ($need -join ", "))
        }
    }

    if (-not $script:Sections["XboxGaming"]) { Show-DryItem "XboxGaming" "Skipped" "Section disabled" }
    else {
        $need = @()
        foreach ($s in $script:XboxServiceList) {
            $svc = Get-ServiceState $s
            if ($svc -and $svc.StartType -ne "Disabled") { $need += $s }
        }
        if ($need.Count -eq 0) {
            Show-DryItem "XboxGaming" "Already OK" "Xbox services absent or already disabled"
        } else {
            Show-DryItem "XboxGaming" "Would change" ("Disable: {0}" -f ($need -join ", "))
        }
    }

    if (-not $script:Sections["BrowserPolicies"]) {
        $installedCount = 0
        try { $installedCount = @(Get-InstalledBastionBrowsers).Count } catch {}
        Show-DryItem "BrowserPolicies" "Skipped" (
            "Section off (menu 6 still works). Installed supported browsers: {0}. Encrypted Client Hello (ECH) never applies unless you opt in." -f $installedCount
        )
    } else {
        try {
            $browsers = @(Get-InstalledBastionBrowsers)
            if ($browsers.Count -eq 0) {
                Show-DryItem "BrowserPolicies" "Already OK" "No supported browsers installed (Firefox/Chrome/Brave); nothing to apply"
            } else {
                $need = @()
                $okLines = @()
                foreach ($b in $browsers) {
                    $want = if ($script:BrowserPolicyModes.Contains($b.Name)) { $script:BrowserPolicyModes[$b.Name] } else { "Default" }
                    $wantEch = Get-BrowserPolicyWantedEch -BrowserName $b.Name
                    $line = Format-BrowserPolicyStatusLine -Name $b.Name -LiveMode $b.Mode -WantMode $want `
                        -EchLive ([bool]$b.EchLive) -WantEch $wantEch
                    if ($b.Mode -ne $want -or [bool]$b.EchLive -ne $wantEch) {
                        $need += $line
                    } else {
                        $okLines += ("{0}={1}{2}" -f $b.Name, $want, $(if ($wantEch) { "+ECH" } else { "" }))
                    }
                }
                if ($need.Count -eq 0) {
                    Show-DryItem "BrowserPolicies" "Already OK" (
                        "Installed browsers match saved intent: {0}. ECH only where saved Yes." -f ($okLines -join ", ")
                    )
                } else {
                    Show-DryItem "BrowserPolicies" "Would change" ($need -join " | ")
                }
            }
        } catch {
            Show-DryItem "BrowserPolicies" "Would change" (
                "Apply saved modes for installed browsers only: {0}" -f (Get-BrowserPolicyModesSummary)
            )
        }
    }

    if (-not $script:Sections["BloatApps"]) { Show-DryItem "BloatApps" "Skipped" "Section disabled" }
    else {
        $b = @(Get-BloatAppxStatus)
        if ($b.Count -eq 0) { Show-DryItem "BloatApps" "Already OK" "No curated bloat packages detected" }
        else { Show-DryItem "BloatApps" "Would change" ("Remove {0} curated package group(s) (hard to reverse)" -f $b.Count) }
    }

    if (-not $script:Sections["Suggestions"]) { Show-DryItem "Suggestions" "Skipped" "Section disabled" }
    else {
        $need = @()
        foreach ($item in $script:SuggestionRegistry) {
            if ($item.Soft) { continue }  # optional policies do not force "Would change"
            try {
                if (-not (Test-Path -LiteralPath $item.Path)) { $need += $item.Desc; continue }
                $cur = (Get-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction SilentlyContinue).($item.Name)
                if ($null -eq $cur -or $cur -ne $item.Value) { $need += $item.Desc }
            } catch { $need += $item.Desc }
        }
        if ($need.Count -eq 0) {
            Show-DryItem "Suggestions" "Already OK" "Core Widgets/Suggestions HKCU values already set"
        } else {
            Show-DryItem "Suggestions" "Would change" ("Set: {0}" -f ($need -join "; "))
        }
    }

    if (-not $script:Sections["CopilotM365"]) { Show-DryItem "CopilotM365" "Skipped" "Section disabled (opt-in; enable in menu 4)" }
    else {
        try {
            $st = Get-CopilotM365Status
            if (-not $st.NeedsWork) {
                Show-DryItem "CopilotM365" "Already OK" "Policy/button set and no matching Copilot/Office Hub Appx"
            } else {
                $bits = @()
                if (-not $st.PolicyOff) { $bits += "set TurnOffWindowsCopilot" }
                if (-not $st.ButtonHidden) { $bits += "hide taskbar button" }
                if ($st.HasAppx) { $bits += ("remove {0} Appx package(s)" -f $st.UserPackages.Count) }
                if ($st.OfficeClickToRun) { $bits += "Office C2R present (NOT removed by Apply)" }
                Show-DryItem "CopilotM365" "Would change" ($bits -join "; ")
            }
        } catch {
            Show-DryItem "CopilotM365" "Would change" "Apply policy, hide button, remove Copilot/Office Hub Appx if present"
        }
    }

    if (-not $script:Sections["Programs"]) { Show-DryItem "Programs" "Skipped" "Section disabled" }
    else {
        $pending = @(Get-SelectedMissingApps)
        if ($pending.Count -eq 0) { Show-DryItem "Programs" "Already OK" "All selected catalog apps installed (or none selected)" }
        else { Show-DryItem "Programs" "Would change" ("winget install: {0}" -f ($pending -join ", ")) }
    }

    Write-Host ""
    Write-Host ("  Summary: Would change={0}  Already OK={1}  Skipped={2}" -f $script:dryWould, $script:dryAlready, $script:drySkip) -ForegroundColor Cyan
    Write-Host "  No changes were made. Use option 8 Apply (or 7 Quick Harden) to execute." -ForegroundColor DarkGray
    Wait-ForKey
}

function Show-ApplyPreview {
    Write-Host ""
    Write-Host "  Enabled sections:" -ForegroundColor Cyan
    foreach ($k in $script:Sections.Keys) {
        if (-not $script:Sections[$k]) { continue }
        $extra = switch ($k) {
            "BrowserPolicies" { (" [{0}]" -f (Get-BrowserPolicyModesSummary)) }
            "DNS" {
                $p = Get-BastionDnsProvider
                if ($script:DnsProviderId -eq "None" -or -not $p.Primary) { " [leave unchanged]" }
                else { (" -> {0} ({1})" -f $p.DisplayName, $p.Primary) }
            }
            "HighRiskServices" { " [includes Print Spooler]" }
            "Programs" {
                if ($script:SelectedApps.Count) { (" -> {0}" -f ($script:SelectedApps -join ", ")) } else { " -> none" }
            }
            "LSAProtection" { " [reboot required]" }
            "BloatApps" { " [hard to reverse]" }
            default { "" }
        }
        Write-Host ("    * {0}{1}" -f $k, $extra) -ForegroundColor White
    }
    Write-Host ""
}

function Get-HardwareInventory {
    $gpu = @()
    try {
        $gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -and $_.Name -notmatch 'Microsoft Basic|Remote Desktop|Virtual'
        } | ForEach-Object {
            $vendor = "Other"
            if ($_.Name -match 'NVIDIA|GeForce|RTX|GTX') { $vendor = "NVIDIA" }
            elseif ($_.Name -match 'AMD|Radeon') { $vendor = "AMD" }
            elseif ($_.Name -match 'Intel') { $vendor = "Intel" }
            [PSCustomObject]@{
                Name = $_.Name
                DriverVersion = $_.DriverVersion
                DriverDate = if ($_.DriverDate) { $_.DriverDate.ToString("yyyy-MM-dd") } else { "?" }
                Vendor = $vendor
            }
        })
    } catch {}
    $board = $null; $bios = $null; $cpu = $null; $cs = $null
    try {
        $bb = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($bb) { $board = [PSCustomObject]@{ Manufacturer = $bb.Manufacturer; Product = $bb.Product } }
    } catch {}
    try {
        $b = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($b) {
            $bios = [PSCustomObject]@{
                SMBIOSBIOSVersion = $b.SMBIOSBIOSVersion
                ReleaseDate = if ($b.ReleaseDate) { $b.ReleaseDate.ToString("yyyy-MM-dd") } else { "?" }
            }
        }
    } catch {}
    try {
        $c = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { $cpu = [PSCustomObject]@{ Name = (($c.Name -replace '\s+', ' ').Trim()) } }
    } catch {}
    try {
        $s = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($s) { $cs = [PSCustomObject]@{ Manufacturer = $s.Manufacturer; Model = $s.Model } }
    } catch {}
    return [PSCustomObject]@{ GPUs = $gpu; Motherboard = $board; BIOS = $bios; CPU = $cpu; ComputerSystem = $cs }
}

function Get-MotherboardSupportLinks {
    param($Manufacturer, $Product)
    $m = ("{0} {1}" -f $Manufacturer, $Product)
    $links = [System.Collections.Generic.List[object]]::new()
    # Official vendor support only
    if ($m -match 'Gigabyte|AORUS|Aorus') {
        [void]$links.Add([PSCustomObject]@{ Name = "Gigabyte Support"; Url = "https://www.gigabyte.com/Support" })
        [void]$links.Add([PSCustomObject]@{ Name = "Gigabyte BIOS downloads"; Url = "https://www.gigabyte.com/Support/Motherboard" })
    }
    if ($m -match 'ASUS|ROG|TUF|PRIME|ProArt') {
        [void]$links.Add([PSCustomObject]@{ Name = "ASUS Support"; Url = "https://www.asus.com/support/" })
    }
    if ($m -match 'Micro-Star|MSI\b') {
        [void]$links.Add([PSCustomObject]@{ Name = "MSI Support"; Url = "https://www.msi.com/support" })
    }
    if ($m -match 'ASRock') {
        [void]$links.Add([PSCustomObject]@{ Name = "ASRock Support"; Url = "https://www.asrock.com/support/" })
    }
    if ($m -match 'Dell') {
        [void]$links.Add([PSCustomObject]@{ Name = "Dell Support"; Url = "https://www.dell.com/support" })
    }
    if ($m -match 'HP|Hewlett') {
        [void]$links.Add([PSCustomObject]@{ Name = "HP Support"; Url = "https://support.hp.com" })
    }
    if ($m -match 'Lenovo|ThinkPad|ThinkCentre') {
        [void]$links.Add([PSCustomObject]@{ Name = "Lenovo Support"; Url = "https://support.lenovo.com" })
    }
    if ($m -match 'ASRock|Intel Corporation|Default string' -and $links.Count -eq 0) {
        [void]$links.Add([PSCustomObject]@{ Name = "Intel Download Center"; Url = "https://www.intel.com/content/www/us/en/download-center/home.html" })
    }
    return @($links)
}

function Show-HardwareDriverGuide {
    $hw = Get-HardwareInventory
    while ($true) {
        Clear-BastionScreen
        Write-Header "HARDWARE AND DRIVER GUIDANCE"
        Write-Host "  Bastion does NOT install GPU drivers or flash BIOS." -ForegroundColor Yellow
        Write-Host "  Official vendor/OEM sites only. Avoid third-party driver boosters." -ForegroundColor Gray
        Write-Host ""
        if ($hw.ComputerSystem) {
            Write-Host ("  PC   : {0} {1}" -f $hw.ComputerSystem.Manufacturer, $hw.ComputerSystem.Model)
        }
        if ($hw.CPU) { Write-Host ("  CPU  : {0}" -f $hw.CPU.Name) }
        if ($hw.Motherboard) {
            Write-Host ("  Board: {0} {1}" -f $hw.Motherboard.Manufacturer, $hw.Motherboard.Product) -ForegroundColor White
        }
        if ($hw.BIOS) {
            Write-Host ("  BIOS : {0} ({1})" -f $hw.BIOS.SMBIOSBIOSVersion, $hw.BIOS.ReleaseDate)
        }
        Write-Host "  BIOS safety: AC power, vendor image only, never interrupt flash." -ForegroundColor Yellow
        Write-Host ""

        $menu = [System.Collections.Generic.List[object]]::new()
        if ($hw.GPUs) {
            foreach ($g in $hw.GPUs) {
                Write-Host ("  GPU  : {0}" -f $g.Name) -ForegroundColor White
                Write-Host ("         {0} | driver {1} ({2})" -f $g.Vendor, $g.DriverVersion, $g.DriverDate) -ForegroundColor DarkGray
                switch ($g.Vendor) {
                    "NVIDIA" {
                        Write-Host "         https://www.nvidia.com/Download/index.aspx" -ForegroundColor Green
                        [void]$menu.Add([PSCustomObject]@{ Label = "Open NVIDIA driver page"; Url = "https://www.nvidia.com/Download/index.aspx" })
                    }
                    "AMD" {
                        Write-Host "         https://www.amd.com/en/support" -ForegroundColor Green
                        [void]$menu.Add([PSCustomObject]@{ Label = "Open AMD driver page"; Url = "https://www.amd.com/en/support" })
                    }
                    "Intel" {
                        Write-Host "         https://www.intel.com/content/www/us/en/download-center/home.html" -ForegroundColor Green
                        [void]$menu.Add([PSCustomObject]@{ Label = "Open Intel driver page"; Url = "https://www.intel.com/content/www/us/en/download-center/home.html" })
                    }
                }
            }
        } else {
            Write-Host "  No GPU data found." -ForegroundColor Yellow
        }

        Write-Host ""
        Write-Host "  Motherboard / OEM support (detected vendors only):" -ForegroundColor Cyan
        $moboLinks = @()
        if ($hw.Motherboard) {
            $moboLinks = @(Get-MotherboardSupportLinks -Manufacturer $hw.Motherboard.Manufacturer -Product $hw.Motherboard.Product)
        }
        if ($moboLinks.Count -eq 0) {
            Write-Host "  No mapped motherboard vendor links for this board string." -ForegroundColor DarkGray
        } else {
            foreach ($l in $moboLinks) {
                Write-Host ("         {0}: {1}" -f $l.Name, $l.Url) -ForegroundColor Green
                [void]$menu.Add([PSCustomObject]@{ Label = $l.Name; Url = $l.Url })
            }
        }

        Write-Host ""
        if ($menu.Count -eq 0) {
            Write-Host "  0 Back"
            $c = Read-MenuChoice -Prompt "  Select" -Valid @("0")
            return
        }
        for ($i = 0; $i -lt $menu.Count; $i++) {
            Write-Host ("  {0}. {1}" -f ($i + 1), $menu[$i].Label) -ForegroundColor White
        }
        Write-Host "  0 Back (stay until you choose 0)" -ForegroundColor Yellow
        $valid = @("0") + (1..$menu.Count | ForEach-Object { "$_" })
        $c = Read-MenuChoice -Prompt "  Select" -Valid $valid
        if ($c -eq "0") { return }
        $idx = [int]$c - 1
        if ($idx -ge 0 -and $idx -lt $menu.Count) {
            Open-UrlSafe $menu[$idx].Url
            Write-Host "  Browser opened. You can pick another link or 0 to leave." -ForegroundColor DarkGray
            Start-Sleep -Seconds 1
        }
    }
}


function Write-AuditRow {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Detail = "",
        [ValidateSet("Good","Warn","Bad","Info")][string]$Level = "Info",
        [string]$Hint = ""
    )
    $col = switch ($Level) { "Good" { "Green" } "Warn" { "Yellow" } "Bad" { "Red" } default { "Cyan" } }
    Write-Host ("  {0,-34} {1}" -f $Name, $Status) -ForegroundColor $col
    if ($Detail) { Write-Host ("  {0,-34} {1}" -f "", $Detail) -ForegroundColor DarkGray }
    if ($Hint) { Write-Host ("  {0,-34} -> {1}" -f "", $Hint) -ForegroundColor DarkCyan }
}

function Write-AuditCategory([string]$Title) {
    Write-Host ""
    Write-Host ("  -- {0} --" -f $Title) -ForegroundColor Cyan
}

function Invoke-SelfTest {
    Clear-BastionScreen
    Write-Header "SECURITY AUDIT"
    Write-Host "  Live posture check (read-only). Independent of section toggles." -ForegroundColor DarkGray
    Write-Host "  Good = hardened. Warn = review. Bad = likely exposure." -ForegroundColor DarkGray
    $script:_ag = 0; $script:_aw = 0; $script:_ab = 0
    function Add-Good { param($n,$s,$d="",$h="") Write-AuditRow $n $s $d -Level Good -Hint $h; $script:_ag++ }
    function Add-Warn { param($n,$s,$d="",$h="") Write-AuditRow $n $s $d -Level Warn -Hint $h; $script:_aw++ }
    function Add-Bad  { param($n,$s,$d="",$h="") Write-AuditRow $n $s $d -Level Bad -Hint $h; $script:_ab++ }

    Write-AuditCategory "Network / Firewall"
    try {
        $fwOk = $true; $detail = @()
        foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) {
            if (-not $p.Enabled -or $p.DefaultInboundAction -ne "Block") { $fwOk = $false }
            $detail += ("{0}: Enabled={1} In={2}" -f $p.Name, $p.Enabled, $p.DefaultInboundAction)
        }
        if ($fwOk) { Add-Good "Firewall profiles" "Hardened" ($detail -join "; ") }
        else { Add-Bad "Firewall profiles" "Not fully hardened" ($detail -join "; ") "Firewall section + Apply" }
    } catch { Add-Warn "Firewall profiles" "Query failed" $_.Exception.Message }

    try {
        $openGroups = @()
        foreach ($g in $script:FirewallGroups) {
            $rules = @(Get-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue |
                Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" })
            if ($rules.Count -gt 0) { $openGroups += ("{0}({1})" -f $g, $rules.Count) }
        }
        if ($openGroups.Count -eq 0) { Add-Good "Inbound discovery groups" "Disabled / none allowing" }
        else { Add-Warn "Inbound discovery groups" "Some allow rules on" ($openGroups -join ", ") "Firewall section + Apply" }
    } catch { Add-Warn "Inbound discovery groups" "Query failed" $_.Exception.Message }

    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.State -eq "Enabled") { Add-Bad "SMBv1" "Enabled" "" "SMBv1 section + Apply" }
        else { Add-Good "SMBv1" "Disabled / not present" }
    } catch { Add-Warn "SMBv1" "Query failed" }

    try {
        $dnsLines = @(); $mismatch = 0
        $wantChange = ($script:Sections["DNS"] -and $script:DnsProviderId -ne "None")
        $prov = Get-BastionDnsProvider
        $targetPrimary = if ($wantChange -and $prov.Primary) { [string]$prov.Primary } else { $null }
        foreach ($a in @(Get-BastionDnsAdapters)) {
            try {
                $dns = @(Get-AdapterDnsServers -InterfaceIndex $a.ifIndex)
                $first = if ($dns -and $dns.Count) { $dns[0] } else { "(none)" }
                $dnsLines += ("{0}={1}" -f $a.Name, $first)
                if ($targetPrimary) {
                    if ($first -ne $targetPrimary) { $mismatch++ }
                }
            } catch {}
        }
        if ($dnsLines.Count -eq 0) { Add-Warn "DNS adapters" "No eligible active adapters" }
        elseif (-not $wantChange) {
            Add-Good "DNS adapters" "Leave unchanged (by choice)" ($dnsLines -join "; ") "Menu D: pick a provider to change"
        }
        elseif ($mismatch -eq 0) {
            Add-Good "DNS adapters" ("{0}-first" -f $prov.DisplayName) ($dnsLines -join "; ") "VPN may override while connected"
        }
        else {
            Add-Warn "DNS adapters" ("Not all on {0}" -f $prov.DisplayName) ($dnsLines -join "; ") "DNS section / menu D (VPN override is normal)"
        }
    } catch { Add-Warn "DNS adapters" "Query failed" }

    try {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::" } |
            Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
        $interesting = @($listeners | Where-Object { $_ -in 135,139,445,3389,5985,5986,22,23 })
        if ($interesting.Count -eq 0) {
            Add-Good "Sensitive listen ports" "None of 135/139/445/RDP/WinRM on all-interfaces" ("All-iface count: {0}" -f $listeners.Count)
        } else {
            Add-Warn "Sensitive listen ports" ($interesting -join ", ") "All-interface listeners" "Review services / Firewall"
        }
    } catch { Add-Warn "Sensitive listen ports" "Query failed" $_.Exception.Message }

    Write-AuditCategory "Services / Tasks"
    try {
        $need = @()
        foreach ($s in $script:HighRiskServiceList) {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($svc -and $svc.StartType -ne "Disabled") { $need += $s }
        }
        if ($need.Count -eq 0) { Add-Good "High-risk services" "Absent or disabled" }
        else { Add-Warn "High-risk services" "Still enabled" ($need -join ", ") "HighRiskServices (Spooler = printing)" }
    } catch { Add-Warn "High-risk services" "Query failed" }

    try {
        $need = @()
        foreach ($s in $script:XboxServiceList) {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($svc -and $svc.StartType -ne "Disabled") { $need += $s }
        }
        if ($need.Count -eq 0) { Add-Good "Xbox services" "Absent or disabled" "" "Optional" }
        else { Add-Warn "Xbox services" "Enabled" ($need -join ", ") "Optional XboxGaming section" }
    } catch { Add-Warn "Xbox services" "Query failed" }

    try {
        $taskPaths = @(
            "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
        )
        $need = @()
        foreach ($tp in $taskPaths) {
            $task = Get-ScheduledTask -TaskPath (Split-Path $tp -Parent) -TaskName (Split-Path $tp -Leaf) -ErrorAction SilentlyContinue
            if ($task -and $task.State -ne "Disabled") { $need += $task.TaskName }
        }
        if ($need.Count -eq 0) { Add-Good "CEIP / Compat tasks" "Absent or disabled" }
        else { Add-Warn "CEIP / Compat tasks" "Enabled" ($need -join ", ") "ScheduledTasks section" }
    } catch { Add-Warn "CEIP / Compat tasks" "Query failed" }

    try {
        $cur = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name DODownloadMode -ErrorAction SilentlyContinue).DODownloadMode
        if ($cur -eq 0) { Add-Good "Delivery Optimization" "HTTP only (0)" }
        else { Add-Warn "Delivery Optimization" ("Mode={0}" -f $(if ($null -eq $cur) { "default/unset" } else { $cur })) "" "DeliveryOptimization section" }
    } catch { Add-Warn "Delivery Optimization" "Query failed" }

    Write-AuditCategory "Defender / OS protections"
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $np = ($pref.EnableNetworkProtection -eq 1 -or "$($pref.EnableNetworkProtection)" -eq "Enabled")
        $cfa = ($pref.EnableControlledFolderAccess -eq 1 -or "$($pref.EnableControlledFolderAccess)" -eq "Enabled")
        if ($np) { Add-Good "Network Protection" "On" } else { Add-Warn "Network Protection" "Off" "" "Defender section" }
        if ($cfa) { Add-Good "Controlled Folder Access" "On" } else { Add-Warn "Controlled Folder Access" "Off" "" "Defender section" }
        if ($st -and $st.RealTimeProtectionEnabled) { Add-Good "Defender realtime" "On" } else { Add-Bad "Defender realtime" "Off / unknown" "" "Windows Security" }
        if ($st -and $st.AntivirusSignatureLastUpdated) {
            $age = (Get-Date) - [datetime]$st.AntivirusSignatureLastUpdated
            if ($age.TotalDays -le 2) { Add-Good "Defender signatures" "Fresh" ($st.AntivirusSignatureLastUpdated.ToString()) }
            elseif ($age.TotalDays -le 7) { Add-Warn "Defender signatures" ("{0:N0} days old" -f $age.TotalDays) "" "Windows Security update" }
            else { Add-Bad "Defender signatures" ("{0:N0} days old" -f $age.TotalDays) "" "Update immediately" }
        }
        if ($st -and $st.IsTamperProtected) { Add-Good "Tamper Protection" "On" }
        elseif ($st) { Add-Warn "Tamper Protection" "Off / unknown" "" "Windows Security settings" }
        try {
            $asr = @($pref.AttackSurfaceReductionRules_Actions)
            $asrOn = @($asr | Where-Object { $_ -eq 1 }).Count
            if ($asrOn -gt 0) { Add-Good "ASR rules enabled" ("{0} rule actions set" -f $asrOn) }
            else { Add-Warn "ASR rules enabled" "None detected" "" "Optional ASR config" }
        } catch {}
    } catch { Add-Warn "Defender" "Query failed" $_.Exception.Message }

    try {
        $lsa = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
        if ($lsa -eq 1) { Add-Good "LSA RunAsPPL" "On" "" "Reboot after first enable" }
        else { Add-Warn "LSA RunAsPPL" "Off" "" "LSAProtection section" }
    } catch { Add-Warn "LSA RunAsPPL" "Query failed" }

    try {
        $sb = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        if ($sb -eq 1) { Add-Good "PS Script Block Logging" "On" }
        else { Add-Warn "PS Script Block Logging" "Off" "" "PowerShellAuditing section" }
    } catch { Add-Warn "PS Script Block Logging" "Query failed" }

    try {
        $mit = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        $depOn = ($mit.DEP.Enable -eq "ON" -or "$($mit.DEP.Enable)" -eq "ON")
        if ($depOn) { Add-Good "Exploit Protection (DEP)" "On" }
        else { Add-Warn "Exploit Protection (DEP)" "Not ON" "" "ExploitProtection section" }
    } catch { Add-Warn "Exploit Protection" "Query failed" }

    Write-AuditCategory "Apps / UI surface"
    $od = Get-OneDriveStatus
    if (-not $od.Present) { Add-Good "OneDrive client" "Absent" }
    else { Add-Warn "OneDrive client" "Present" $od.Detail "OneDrive section" }

    try {
        $stc = Get-CopilotM365Status
        if (-not $stc.NeedsWork) { Add-Good "Copilot / M365 hub" "Hardened indicators OK" }
        else {
            $bits = @()
            if (-not $stc.PolicyOff) { $bits += "policy" }
            if (-not $stc.ButtonHidden) { $bits += "taskbar button" }
            if ($stc.HasAppx) { $bits += "Appx" }
            Add-Warn "Copilot / M365 hub" "Needs attention" ($bits -join ", ") "CopilotM365 section or Recovery > 4"
        }
        if ($stc.OfficeClickToRun) { Add-Warn "Office Click-to-Run" "Present" "Full suite possible" "Recovery > 4 Office remover only if desired" }
        else { Add-Good "Office Click-to-Run" "Not detected" }
    } catch { Add-Warn "Copilot / M365 hub" "Query failed" }

    try {
        $tb = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarDa -ErrorAction SilentlyContinue).TaskbarDa
        if ($tb -eq 0) { Add-Good "Widgets button" "Hidden" }
        else { Add-Warn "Widgets button" "Visible / default" "" "Suggestions section" }
    } catch { Add-Warn "Widgets button" "Query failed" }

    try {
        $browsers = @(Get-InstalledBastionBrowsers)
        if ($browsers.Count -eq 0) {
            Add-Good "Browser policies" "No supported browsers installed" "Firefox / Chrome / Brave not detected" "Programs menu 5"
        } else {
            $strictOrEch = $false
            foreach ($b in $browsers) {
                $want = if ($script:BrowserPolicyModes.Contains($b.Name)) { $script:BrowserPolicyModes[$b.Name] } else { "Default" }
                $wantEch = Get-BrowserPolicyWantedEch -BrowserName $b.Name
                $echLive = if ($b.EchLive) { "ECH live Yes" } else { "ECH live No" }
                $echWant = if ($wantEch) { "saved ECH Yes" } else { "saved ECH No" }
                $detail = "live {0}; saved {1}; {2}; {3}" -f $b.Mode, $want, $echLive, $echWant
                if ($b.Mode -eq "Strict" -or $b.EchLive -or $want -eq "Strict" -or $wantEch) {
                    $strictOrEch = $true
                    Add-Warn ("Browser {0}" -f $b.Name) ("{0} / transport privacy active or intended" -f $b.Mode) $detail "Menu 6 (Default reverts this browser)"
                } elseif ($b.Mode -eq "Medium" -or $want -eq "Medium") {
                    Add-Good ("Browser {0}" -f $b.Name) "Medium privacy pack" $detail "Menu 6"
                } else {
                    Add-Good ("Browser {0}" -f $b.Name) "Default / no Bastion Strict" $detail "Menu 6 to harden"
                }
            }
            if ($strictOrEch) {
                Add-Warn "Encrypted Client Hello (ECH)" "Optional pack" "Never default; only if you chose Yes under Strict for that browser" "Menu 6 > browser > Default clears ECH for that browser"
            } else {
                Add-Good "Encrypted Client Hello (ECH)" "Not forced" "No saved ECH Yes on installed browsers" "Optional under Strict in menu 6"
            }
        }
    } catch { Add-Warn "Browser policies" "Query failed" }

    Write-AuditCategory "Tooling / Safety"
    $wg = Test-WingetSecurityPreflight
    if ($wg.Ok) {
        $short = $wg.Detail
        if ($short.Length -gt 70) { $short = $short.Substring(0, 67) + "..." }
        Add-Good "winget preflight" "OK" $short
    } else {
        Add-Warn "winget preflight" "Blocked" $wg.Detail "Fix sources before installs"
    }
    try {
        $rp = Get-RestorePointStatus
        if ($rp.Ok -and $rp.HasRecent) { Add-Good "System Restore" "Recent point present" }
        elseif ($rp.Ok -and $rp.HasAny) { Add-Warn "System Restore" "No recent 48h point" "" "Menu 13 / R" }
        elseif ($rp.Ok) { Add-Bad "System Restore" "No points found" "" "sysdm.cpl + menu 13 / R" }
        else { Add-Warn "System Restore" "Could not query" $rp.Error "sysdm.cpl > System Protection" }
    } catch { Add-Warn "System Restore" "Query failed" }

    $good = $script:_ag; $warn = $script:_aw; $bad = $script:_ab
    $total = [Math]::Max(1, $good + $warn + $bad)
    $score = [int][Math]::Round(100.0 * $good / $total)
    Write-Host ""
    Write-Host "  ==============================================================" -ForegroundColor DarkCyan
    Write-Host ("  SCORE  {0}/100   Good={1}  Warn={2}  Bad={3}" -f $score, $good, $warn, $bad) -ForegroundColor $(
        if ($bad -gt 0) { "Yellow" } elseif ($warn -gt 0) { "Cyan" } else { "Green" }
    )
    if ($bad -gt 0) { Write-Host "  Verdict: Address Bad items first, then re-run Audit." -ForegroundColor Yellow }
    elseif ($warn -gt 0) { Write-Host "  Verdict: Solid baseline; review Warn hints for optional hardening." -ForegroundColor Cyan }
    else { Write-Host "  Verdict: All sampled checks look hardened." -ForegroundColor Green }
    Write-Host "  Next: Dry Run (1) with your toggles, or Apply (8) after restore point (13)." -ForegroundColor DarkGray
    Write-Host "  ==============================================================" -ForegroundColor DarkCyan
    Wait-ForKey
}


function Select-InstallRootFromVolumes {
    param([string]$PromptTitle = "Select install folder")
    $vols = @(Get-AvailableInstallVolumes)
    if ($vols.Count -eq 0) {
        Write-Host "  No fixed volumes found." -ForegroundColor Red
        return $null
    }
    Write-Host ""
    Write-Host ("  {0}" -f $PromptTitle) -ForegroundColor Cyan
    Write-Host "   0. System default (vendor / Program Files)  [recommended unless you need another drive]" -ForegroundColor Green
    for ($i = 0; $i -lt $vols.Count; $i++) {
        Write-Host ("  {0,2}. {1}  {2}  Free {3} GB  (uses {1}BastionApps)" -f ($i + 1), $vols[$i].Root, $vols[$i].Label, $vols[$i].FreeGB)
    }
    Write-Host ("  {0,2}. Custom path under a listed drive" -f ($vols.Count + 1))
    $valid = @("0") + (1..($vols.Count + 1) | ForEach-Object { "$_" })
    $c = Read-MenuChoice -Prompt "  Choice" -Valid $valid
    $n = [int]$c
    if ($n -eq 0) { return $null }
    if ($n -ge 1 -and $n -le $vols.Count) {
        $suggested = Join-Path ($vols[$n - 1].Root.TrimEnd('\')) "BastionApps"
        $check = Test-SafeInstallRoot -Path $suggested -AllowedVolumes $vols
        if ($check.Ok) { return $check.Path }
        Write-Host ("  Rejected: {0}" -f $check.Reason) -ForegroundColor Red
        return $null
    }
    Write-Host ""
    Write-Host "  Custom path rules:" -ForegroundColor Yellow
    Write-Host "    - Must start with a drive letter on this PC (examples below)" -ForegroundColor DarkGray
    Write-Host "    - Fixed internal disks only (not USB / network UNC paths)" -ForegroundColor DarkGray
    Write-Host "    - Not under Windows, System32, or WindowsApps" -ForegroundColor DarkGray
    Write-Host "    - No illegal characters: < > | ? * or control chars" -ForegroundColor DarkGray
    Write-Host "  Examples:" -ForegroundColor Cyan
    foreach ($v in $vols) {
        Write-Host ("    {0}Apps" -f $v.Root) -ForegroundColor White
        Write-Host ("    {0}BastionApps" -f $v.Root) -ForegroundColor White
    }
    Write-Host "  Tip: folder is created if missing when install runs. Some apps ignore custom locations." -ForegroundColor DarkGray
    Write-Host "  Enter blank line to cancel and return." -ForegroundColor DarkGray
    $attempts = 0
    while ($attempts -lt 5) {
        $attempts++
        try {
            $custom = Read-Host "  Full path"
        } catch {
            Write-Host "  Input error; try again or leave blank to cancel." -ForegroundColor Red
            continue
        }
        if ($null -eq $custom -or [string]::IsNullOrWhiteSpace([string]$custom)) {
            Write-Host "  Empty path - cancelled." -ForegroundColor Yellow
            return $null
        }
        $custom = ([string]$custom).Trim().Trim('"').Trim("'")
        if ($custom.Length -gt 180) {
            Write-Host "  Path too long (max 180 characters). Try a shorter folder." -ForegroundColor Red
            continue
        }
        $check = Test-SafeInstallRoot -Path $custom -AllowedVolumes $vols
        if ($check.Ok) {
            Write-Host ("  Accepted: {0}" -f $check.Path) -ForegroundColor Green
            return $check.Path
        }
        Write-Host ("  Rejected: {0}" -f $check.Reason) -ForegroundColor Red
        Write-Host "  Try again using an example above, pick a listed drive option, or blank to cancel." -ForegroundColor Yellow
    }
    Write-Host "  Too many invalid attempts - cancelled." -ForegroundColor Red
    return $null
}


function Set-LocationsForPendingInstalls {
    $pending = @(Get-SelectedMissingApps)
    if ($pending.Count -eq 0) {
        Write-Host "  No pending installs - location step skipped." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }
    Clear-BastionScreen
    Write-Header "INSTALL LOCATIONS (PENDING ONLY)"
    Write-Host "  Only apps selected and not yet installed:" -ForegroundColor Cyan
    foreach ($p in $pending) { Write-Host ("    - {0}" -f $p) -ForegroundColor White }
    Write-Host ""
    Write-Host "  1 System default   2 One folder for all   3 Per app   0 Cancel"
    $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3")
    switch ($c) {
        "0" { return }
        "1" {
            $script:GlobalInstallRoot = $null
            foreach ($p in $pending) {
                if ($script:ProgramInstallRoots.ContainsKey($p)) { $script:ProgramInstallRoots.Remove($p) }
            }
            Write-Host "  Using vendor defaults for pending installs." -ForegroundColor Green
        }
        "2" {
            $script:GlobalInstallRoot = Select-InstallRootFromVolumes -PromptTitle "Folder for all pending installs"
            foreach ($p in $pending) {
                if ($script:ProgramInstallRoots.ContainsKey($p)) { $script:ProgramInstallRoots.Remove($p) }
            }
        }
        "3" {
            $script:GlobalInstallRoot = $null
            foreach ($app in $pending) {
                $root = Select-InstallRootFromVolumes -PromptTitle ("Folder for {0}" -f $app)
                if ($root) { $script:ProgramInstallRoots[$app] = $root }
                elseif ($script:ProgramInstallRoots.ContainsKey($app)) { $script:ProgramInstallRoots.Remove($app) }
            }
        }
    }
    Clear-StaleInstallRoots
    Save-BastionConfig
    Start-Sleep -Seconds 1
}

function Show-ProgramMenu {
    # Prune stale queue (e.g. apps installed outside Bastion since last session).
    Sync-ProgramInstallQueue
    while ($true) {
        # Re-detect installed/missing every paint so status stays accurate.
        $apps = @(Get-CatalogProgramRows)
        Clear-BastionScreen
        Write-Header "PROGRAMS AND INSTALL PATHS"
        Write-Host "  [X] = queued to INSTALL (missing apps only). Installed apps cannot be checked here." -ForegroundColor DarkGray
        Write-Host "  Status is detected live. Use menu 10 to uninstall catalog apps." -ForegroundColor DarkGray
        Write-Host "  No location chosen => vendor defaults. L sets paths for pending installs only." -ForegroundColor DarkGray
        Write-Host ""
        for ($i = 0; $i -lt $apps.Count; $i++) {
            $a = $apps[$i]
            $manual = $false
            if ($script:ProgramDefs.Contains($a.Name) -and $script:ProgramDefs[$a.Name].ManualInstallOnly) { $manual = $true }
            if ($a.Installed) {
                # Never show install-queue checkmark on software already present.
                Write-Host ("  {0,2}. [ ] {1,-16} installed" -f ($i + 1), $a.Name) -ForegroundColor DarkCyan
            } elseif ($a.Selected) {
                $r = Get-EffectiveInstallRoot -AppName $a.Name
                $hint = $(if ($manual) { " -> manual download" } elseif ($r) { (" -> {0}" -f $r) } else { " -> default" })
                Write-Host ("  {0,2}. [X] {1,-16} missing  (queued){2}" -f ($i + 1), $a.Name, $hint) -ForegroundColor Green
            } else {
                $tag = if ($manual) { "missing (manual)" } else { "missing" }
                Write-Host ("  {0,2}. [ ] {1,-16} {2}" -f ($i + 1), $a.Name, $tag) -ForegroundColor DarkGray
            }
        }
        $pendingCount = @($apps | Where-Object { $_.Selected -and -not $_.Installed }).Count
        $installedCount = @($apps | Where-Object Installed).Count
        $missingCount = @($apps | Where-Object { -not $_.Installed }).Count
        Write-Host ""
        Write-Host ("  Queued install {0} | Missing {1} | Already installed {2} | Global {3}" -f `
            $pendingCount, $missingCount, $installedCount,
            $(if ($script:GlobalInstallRoot) { $script:GlobalInstallRoot } else { "(none)" })) -ForegroundColor Cyan
        # No bulk "select everything" for installs: users opt in app-by-app (safer, clearer).
        Write-Host "  N clear-queue  L locations  C confirm  0 back" -ForegroundColor Yellow
        $valid = @("N","L","C","0","n","l","c") + (1..$apps.Count | ForEach-Object { "$_" })
        $c = Read-MenuChoice -Prompt "  Select" -Valid $valid
        switch ($c.ToUpper()) {
            "0" {
                Sync-ProgramInstallQueue
                return
            }
            "N" {
                $script:SelectedApps.Clear()
                Clear-StaleInstallRoots
            }
            "L" {
                Sync-ProgramInstallQueue
                if (@(Get-SelectedMissingApps).Count -eq 0) {
                    Write-Host "  No missing apps are queued. Select missing apps first, then L." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                } else {
                    Set-LocationsForPendingInstalls
                }
            }
            "C" {
                Sync-ProgramInstallQueue
                Save-BastionConfig
                Write-Host ("  Saved. Queued for install: {0}" -f $(if ($script:SelectedApps.Count) { $script:SelectedApps -join ", " } else { "(none)" })) -ForegroundColor Green
                Start-Sleep -Seconds 1
                return
            }
            default {
                if ($c -match '^\d+$') {
                    $idx = [int]$c - 1
                    if ($idx -ge 0 -and $idx -lt $apps.Count) {
                        $row = $apps[$idx]
                        if ($row.Installed) {
                            Write-Host ("  {0} is already installed. Use menu 10 Uninstall to remove it." -f $row.Name) -ForegroundColor Yellow
                            Start-Sleep -Seconds 2
                        } else {
                            if ($script:SelectedApps -contains $row.Name) {
                                [void]$script:SelectedApps.Remove($row.Name)
                            } else {
                                [void]$script:SelectedApps.Add($row.Name)
                            }
                            Clear-StaleInstallRoots
                        }
                    }
                }
            }
        }
    }
}

function Show-SectionMenu {
    $names = @($script:Sections.Keys)
    while ($true) {
        Clear-BastionScreen
        Write-Header "HARDENING SECTIONS"
        for ($i = 0; $i -lt $names.Count; $i++) {
            $n = $names[$i]
            $mark = if ($script:Sections[$n]) { "[X]" } else { "[ ]" }
            $suffix = ""
            if ($n -eq "DNS") {
                if (-not $script:Sections["DNS"] -or $script:DnsProviderId -eq "None") {
                    $suffix = "  (leave DNS unchanged)"
                } else {
                    $p = Get-BastionDnsProvider
                    $suffix = ("  -> {0}" -f $p.DisplayName)
                }
            }
            Write-Host ("  {0,2}. {1}  {2}{3}" -f ($i + 1), $mark, $n, $suffix) `
                -ForegroundColor $(if ($script:Sections[$n]) { "Green" } else { "DarkGray" })
        }
        Write-Host "  A all  N none  D DNS provider  C confirm  0 back" -ForegroundColor Yellow
        $valid = @("A","N","C","D","0","a","n","c","d") + (1..$names.Count | ForEach-Object { "$_" })
        $c = Read-MenuChoice -Prompt "  Select" -Valid $valid
        switch ($c.ToUpper()) {
            "0" { return }
            "A" {
                foreach ($k in $names) { $script:Sections[$k] = $true }
                if ($script:DnsProviderId -eq "None") { $script:DnsProviderId = "Quad9" }
            }
            "N" { foreach ($k in $names) { $script:Sections[$k] = $false } }
            "D" { Show-DnsProviderMenu; return }
            "C" { Save-BastionConfig; return }
            default {
                if ($c -match '^\d+$') {
                    $idx = [int]$c - 1
                    if ($idx -ge 0 -and $idx -lt $names.Count) {
                        $key = $names[$idx]
                        $script:Sections[$key] = -not $script:Sections[$key]
                        if ($key -eq "DNS") {
                            if ($script:Sections["DNS"]) {
                                if ($script:DnsProviderId -eq "None") { $script:DnsProviderId = "Quad9" }
                            } else {
                                # Section off = do not change DNS; keep last real provider for easy re-enable
                            }
                        }
                    }
                }
            }
        }
    }
}

function Show-DnsProviderMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "DNS RESOLVER"
        Write-Host "  Choose a public recursive DNS provider, or leave adapters unchanged." -ForegroundColor Cyan
        Write-Host "  VPN software may override these settings while a tunnel is connected." -ForegroundColor Yellow
        Write-Host ""
        Write-Host ("  Current: {0}" -f (Get-BastionDnsProviderLabel)) -ForegroundColor White
        Write-Host ("  Section DNS enabled: {0}" -f $(if ($script:Sections["DNS"]) { "Yes" } else { "No" })) -ForegroundColor DarkGray
        Write-Host ""

        $ids = @($script:DnsProviders.Keys)
        for ($i = 0; $i -lt $ids.Count; $i++) {
            $id = $ids[$i]
            $p = $script:DnsProviders[$id]
            $mark = if ($script:DnsProviderId -eq $id -and ($id -eq "None" -or $script:Sections["DNS"])) { ">" } else { " " }
            if ($id -eq "None") {
                $mark = if (-not $script:Sections["DNS"] -or $script:DnsProviderId -eq "None") { ">" } else { " " }
                Write-Host ("  {0} {1,2}. {2}" -f $mark, ($i + 1), $p.DisplayName) -ForegroundColor $(if ($mark -eq ">") { "Green" } else { "White" })
                Write-Host ("         {0}" -f $p.Notes) -ForegroundColor DarkGray
            } else {
                Write-Host ("  {0} {1,2}. {2}" -f $mark, ($i + 1), $p.DisplayName) -ForegroundColor $(if ($mark -eq ">") { "Green" } else { "White" })
                Write-Host ("         Primary {0}  Secondary {1}" -f $p.Primary, $p.Secondary) -ForegroundColor DarkGray
                Write-Host ("         {0}" -f $p.Notes) -ForegroundColor DarkGray
            }
            Write-Host ""
        }
        Write-Host "  0 Back (save)" -ForegroundColor Yellow
        $valid = @("0") + (1..$ids.Count | ForEach-Object { "$_" })
        $c = Read-MenuChoice -Prompt "  Select" -Valid $valid
        if ($c -eq "0") {
            Save-BastionConfig
            return
        }
        if ($c -match '^\d+$') {
            $idx = [int]$c - 1
            if ($idx -ge 0 -and $idx -lt $ids.Count) {
                [void](Set-BastionDnsProviderId -Id $ids[$idx])
                Save-BastionConfig
                Write-Host ("  DNS set to: {0}" -f (Get-BastionDnsProviderLabel)) -ForegroundColor Green
                Start-Sleep -Milliseconds 700
            }
        }
    }
}

function Get-InstalledBastionBrowsers {
    # Only supported browsers that are actually installed (path detect). Never list missing engines.
    $list = [System.Collections.Generic.List[object]]::new()
    $map = @(
        @{ Name = "Firefox"; Test = { Test-Installed -Name "Firefox" -Paths $script:ProgramDefs["Firefox"].Paths }; Set = "Firefox"; GetMode = { Get-FirefoxPolicyModeFromFile } }
        @{ Name = "Chrome";  Test = { Test-Installed -Name "Chrome"  -Paths $script:ProgramDefs["Chrome"].Paths  }; Set = "Chrome";  GetMode = { Get-ChromiumPolicyMode -Browser Chrome } }
        @{ Name = "Brave";   Test = { Test-Installed -Name "Brave"   -Paths $script:ProgramDefs["Brave"].Paths   }; Set = "Brave";   GetMode = { Get-ChromiumPolicyMode -Browser Brave } }
    )
    foreach ($m in $map) {
        $installed = $false
        try { $installed = [bool](& $m.Test) } catch { $installed = $false }
        if (-not $installed) { continue }

        $mode = "Default"
        try { $mode = & $m.GetMode } catch { $mode = "Custom" }
        $saved = if ($script:BrowserPolicyModes.Contains($m.Name)) { $script:BrowserPolicyModes[$m.Name] } else { "Default" }
        # Saved ECH only if explicitly true in state (defaults false).
        $echSaved = $false
        if ($script:BrowserEchLocks.Contains($m.Name) -and $script:BrowserEchLocks[$m.Name] -and $saved -eq "Strict") {
            $echSaved = $true
        }
        $echLive = $false
        try { $echLive = [bool](Test-BrowserEchLockLive -Browser $m.Name) } catch { $echLive = $false }
        [void]$list.Add([PSCustomObject]@{
            Name      = $m.Name
            Mode      = $mode
            SavedMode = $saved
            EchLive   = $echLive
            EchSaved  = $echSaved
            Key       = $m.Set
        })
    }
    return @($list)
}

function Invoke-BastionBrowserPolicy {
    param(
        [Parameter(Mandatory)][ValidateSet("Firefox","Chrome","Brave")][string]$Browser,
        [Parameter(Mandatory)][ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch = $false
    )
    # Refuse to configure a browser that is not installed.
    if (-not $script:ProgramDefs.Contains($Browser)) {
        Write-Status ("{0} is not a supported Bastion browser" -f $Browser) "Failed"
        return $false
    }
    if (-not (Test-Installed -Name $Browser -Paths $script:ProgramDefs[$Browser].Paths)) {
        Write-Status ("{0} is not installed; skipping policy change" -f $Browser) "Skip"
        return $false
    }
    $EnableEch = Resolve-BrowserEchChoice -Mode $Mode -EnableEch:$EnableEch
    switch ($Browser) {
        "Firefox" { return (Set-FirefoxPolicyMode -Mode $Mode -EnableEch:$EnableEch) }
        "Chrome"  { return (Set-ChromePolicyMode -Mode $Mode -EnableEch:$EnableEch) }
        "Brave"   { return (Set-BravePolicyMode -Mode $Mode -EnableEch:$EnableEch) }
    }
    return $false
}

function Show-BrowserPolicyMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "BROWSER PRIVACY POLICIES"
        Write-Host "  Only installed, supported browsers are listed (Firefox, Chrome, Brave)." -ForegroundColor Cyan
        Write-Host "  Configure each one independently. Encrypted Client Hello (ECH) is never applied unless you opt in." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Modes" -ForegroundColor White
        Write-Host "    Default  Remove Bastion policies for that browser only (best-effort revert; backups kept)." -ForegroundColor DarkGray
        Write-Host "    Medium   Privacy baseline (telemetry / tracking / cookies). Usually fewer breakages." -ForegroundColor DarkGray
        Write-Host "    Strict   Medium + HTTPS-Only. Does not enable Encrypted Client Hello (ECH) by itself." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Encrypted Client Hello (ECH) pack (optional)" -ForegroundColor White
        Write-Host "    Offered only after you choose Strict, as a separate Yes/No. Default answer path is No" -ForegroundColor DarkGray
        Write-Host "    unless you type Y. Never enabled for browsers you did not select." -ForegroundColor DarkGray
        Write-Host "    Firefox: locks Encrypted Client Hello (ECH) preferences in policies.json." -ForegroundColor DarkGray
        Write-Host "    Chrome/Brave: ECH intent marker + strongest transport policies Bastion can set" -ForegroundColor DarkGray
        Write-Host "    (HTTPS-Only, DNS-over-HTTPS, optional Chromium ECH policy value if honored)." -ForegroundColor DarkGray
        Write-Host ""
        Write-BrowserStrictDisclaimer -Compact
        Write-Host ("  Saved: {0}" -f (Get-BrowserPolicyModesSummary)) -ForegroundColor DarkGray
        if ($script:BrowserPolicyLastChange) {
            $lc = $script:BrowserPolicyLastChange
            Write-Host ("  Last change: {0}  {1}  {2} -> {3}" -f $lc.Timestamp, $lc.Browser, $lc.ModeBefore, $lc.ModeAfter) -ForegroundColor DarkGray
        }
        Write-Host ""

        $browsers = @(Get-InstalledBastionBrowsers)
        if ($browsers.Count -eq 0) {
            Write-Host "  No supported browsers are installed on this PC." -ForegroundColor Yellow
            Write-Host "  Supported: Firefox, Chrome, Brave (install from Programs, option 5)." -ForegroundColor DarkGray
            Write-Host "  Nothing to configure until one of those is detected." -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  0 Back"
            $c = Read-MenuChoice -Prompt "  Select" -Valid @("0")
            return
        }

        Write-Host "  Detected installed browsers only" -ForegroundColor Cyan
        for ($i = 0; $i -lt $browsers.Count; $i++) {
            $b = $browsers[$i]
            $echL = if ($b.EchLive) { "on" } else { "off" }
            $echS = if ($b.EchSaved) { "on" } else { "off" }
            Write-Host ("    {0}. {1,-10}  live={2,-8}  saved={3,-8}  ECH live={4} saved={5}" -f `
                ($i + 1), $b.Name, $b.Mode, $b.SavedMode, $echL, $echS) -ForegroundColor White
        }
        Write-Host ""
        Write-Host "  Choose a number for one installed browser, then a mode." -ForegroundColor DarkGray
        Write-Host "  A  Same mode for all detected installed browsers (still one ECH Yes/No if Strict)" -ForegroundColor Yellow
        Write-Host "  0  Back"
        $valid = @("0", "A", "a") + (1..$browsers.Count | ForEach-Object { "$_" })
        $c = Read-MenuChoice -Prompt "  Select" -Valid $valid
        if ($c -eq "0") { return }

        $targets = @()
        if ($c.ToUpper() -eq "A") {
            $targets = @($browsers)
        } else {
            $idx = [int]$c - 1
            if ($idx -ge 0 -and $idx -lt $browsers.Count) { $targets = @($browsers[$idx]) }
        }
        if ($targets.Count -eq 0) { continue }

        # Re-verify install before changing anything.
        $targets = @($targets | Where-Object {
            Test-Installed -Name $_.Name -Paths $script:ProgramDefs[$_.Name].Paths
        })
        if ($targets.Count -eq 0) {
            Write-Host "  Selection is no longer installed. List will refresh." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            continue
        }

        Write-Host ""
        Write-Host ("  Target (installed only): {0}" -f (($targets | ForEach-Object { $_.Name }) -join ", ")) -ForegroundColor Cyan
        Write-Host "  1 Default (revert this browser)  2 Medium  3 Strict  0 Cancel"
        $m = Read-MenuChoice -Prompt "  Mode" -Valid @("0", "1", "2", "3")
        if ($m -eq "0") { continue }
        $mode = switch ($m) { "1" { "Default" } "2" { "Medium" } "3" { "Strict" } }

        # ECH never defaults on: stays false unless user explicitly answers Y below.
        $enableEch = $false
        if ($mode -eq "Strict") {
            Write-BrowserStrictDisclaimer
            if ((Read-YesNo -Prompt "  Apply Strict to the selected installed browser(s)? Some sites may fail (Y/N)") -ne "Y") { continue }
            Write-Host ""
            Write-Host "  Encrypted Client Hello (ECH) pack - optional, off unless you choose Yes" -ForegroundColor Yellow
            Write-Host "    Applies only to the browser(s) listed above." -ForegroundColor DarkGray
            Write-Host "    Yes = enable Encrypted Client Hello (ECH) pack for those browsers." -ForegroundColor DarkGray
            Write-Host "    No  = Strict only (no Encrypted Client Hello (ECH) pack)." -ForegroundColor DarkGray
            $echAnswer = Read-YesNo -Prompt "  Enable Encrypted Client Hello (ECH) pack on selected browser(s)? (Y/N)"
            $enableEch = ($echAnswer -eq "Y")
            if (-not $enableEch) {
                Write-Host "  Encrypted Client Hello (ECH) pack will remain off for this apply." -ForegroundColor DarkGray
            }
        }
        if ($mode -eq "Default" -and (Read-YesNo -Prompt "  Remove Bastion policies (and any ECH pack) for selected browser(s) (Y/N)?") -ne "Y") { continue }

        foreach ($t in $targets) {
            if (-not (Test-Installed -Name $t.Name -Paths $script:ProgramDefs[$t.Name].Paths)) {
                Write-Status ("{0} not installed; skipped" -f $t.Name) "Skip"
                continue
            }
            $suffix = if ($mode -eq "Strict" -and $enableEch) { " + Encrypted Client Hello (ECH) pack" } else { "" }
            Write-Host ("  Applying {0} -> {1}{2}..." -f $t.Name, $mode, $suffix) -ForegroundColor White
            [void](Invoke-BastionBrowserPolicy -Browser $t.Key -Mode $mode -EnableEch:$enableEch)
        }
        $script:BrowserPolicyMode = $mode
        Save-BastionConfig
        Save-BrowserPolicyStateFile
        Write-Host "  Restart affected browsers fully (close all windows) so policies load or drop." -ForegroundColor Yellow
        Write-Host "  Revert one browser: menu 6 > that browser > Default." -ForegroundColor DarkGray
        Write-Host ("  State log: {0}" -f (Get-BrowserPolicyStatePath)) -ForegroundColor DarkGray
        Wait-ForKey
    }
}




function Stop-BastionCatalogProcesses {
    param([string]$AppName)
    if (-not $script:ProgramDefs.Contains($AppName)) { return }
    $stopped = @{}
    foreach ($path in @($script:ProgramDefs[$AppName].Paths)) {
        $procName = [System.IO.Path]::GetFileNameWithoutExtension($path)
        if ([string]::IsNullOrWhiteSpace($procName)) { continue }
        try {
            Get-Process -Name $procName -ErrorAction SilentlyContinue | ForEach-Object {
                if ($stopped.ContainsKey($_.Id)) { return }
                try {
                    Stop-Process -Id $_.Id -Force -ErrorAction Stop
                    $stopped[$_.Id] = $true
                    Write-Host ("    Stopped process: {0} (PID {1})" -f $_.ProcessName, $_.Id) -ForegroundColor DarkGray
                } catch {}
            }
        } catch {}
    }
    # PowerToys ships many helpers (Command Palette, FancyZones, Awake, etc.)
    if ($AppName -eq "PowerToys") {
        $patterns = @(
            'PowerToys',
            'PowerToys.',
            'CommandPalette',
            'WindowsCommandPalette'
        )
        try {
            Get-Process -ErrorAction SilentlyContinue | Where-Object {
                $n = $_.ProcessName
                $pathOk = $false
                try { if ($_.Path -and ($_.Path -match 'PowerToys|CommandPalette')) { $pathOk = $true } } catch {}
                $nameOk = $false
                foreach ($pat in $patterns) {
                    if ($n -like ($pat + '*') -or $n -match [regex]::Escape($pat)) { $nameOk = $true; break }
                }
                $nameOk -or $pathOk
            } | ForEach-Object {
                if ($stopped.ContainsKey($_.Id)) { return }
                try {
                    Stop-Process -Id $_.Id -Force -ErrorAction Stop
                    $stopped[$_.Id] = $true
                    Write-Host ("    Stopped PowerToys-related: {0} (PID {1})" -f $_.ProcessName, $_.Id) -ForegroundColor DarkGray
                } catch {
                    Write-Host ("    Could not stop {0} (PID {1}): still locked" -f $_.ProcessName, $_.Id) -ForegroundColor Yellow
                }
            }
        } catch {}
        Start-Sleep -Milliseconds 900
    }
}

function Get-HkcuUninstallCommands {
    param([string]$AppName, [string]$WingetId)
    $results = New-Object System.Collections.Generic.List[object]
    $roots = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $needles = @($AppName, "PowerToys")
    if ($WingetId) { $needles += $WingetId }
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        try {
            Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    $dn = [string]$p.DisplayName
                    if ([string]::IsNullOrWhiteSpace($dn)) { return }
                    $hit = $false
                    foreach ($n in $needles) {
                        if ($dn -like ("*{0}*" -f $n)) { $hit = $true; break }
                    }
                    if (-not $hit) { return }
                    $u = [string]$p.UninstallString
                    $q = [string]$p.QuietUninstallString
                    if (-not $u -and -not $q) { return }
                    [void]$results.Add([PSCustomObject]@{
                        DisplayName = $dn
                        UninstallString = $u
                        QuietUninstallString = $q
                        InstallLocation = [string]$p.InstallLocation
                    })
                } catch {}
            }
        } catch {}
    }
    return @($results)
}

function Invoke-HkcuUninstallString {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    try {
        # Typical: "C:\Path\setup.exe" /uninstall /silent
        if ($CommandLine -match '^\s*"([^"]+)"\s*(.*)$') {
            $exe = $Matches[1]
            $args = $Matches[2]
            if (-not (Test-Path -LiteralPath $exe)) { return $false }
            Write-Host ("    Running HKCU uninstaller: {0} {1}" -f $exe, $args) -ForegroundColor DarkGray
            $proc = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -ErrorAction Stop
            return ($proc.ExitCode -eq 0 -or $null -eq $proc.ExitCode)
        }
        if ($CommandLine -match '^\s*(\S+\.exe)(\s+.*)?$') {
            $exe = $Matches[1]
            $args = if ($Matches[2]) { $Matches[2].Trim() } else { "" }
            if (-not (Test-Path -LiteralPath $exe)) { return $false }
            Write-Host ("    Running HKCU uninstaller: {0} {1}" -f $exe, $args) -ForegroundColor DarkGray
            if ($args) {
                $proc = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -ErrorAction Stop
            } else {
                $proc = Start-Process -FilePath $exe -Wait -PassThru -ErrorAction Stop
            }
            return ($proc.ExitCode -eq 0 -or $null -eq $proc.ExitCode)
        }
        Write-Host ("    HKCU uninstall string not parseable: {0}" -f $CommandLine) -ForegroundColor Yellow
        return $false
    } catch {
        Write-Host ("    HKCU uninstall failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        return $false
    }
}

function Invoke-WingetUninstallCatalog {
    param([string]$AppName, [string]$WingetId)
    $outFile = Join-Path $script:tempDir "wg-un-out.txt"
    $errFile = Join-Path $script:tempDir "wg-un-err.txt"

    function Invoke-One {
        param([string[]]$ExtraArgs)
        $argList = @("uninstall","--id",$WingetId,"-e","--silent","--disable-interactivity") + @($ExtraArgs)
        try { if (Test-Path -LiteralPath $outFile) { Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue } } catch {}
        try { if (Test-Path -LiteralPath $errFile) { Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue } } catch {}
        $proc = Start-Process -FilePath "winget" -ArgumentList $argList `
            -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile -ErrorAction Stop
        $text = ""
        try { if (Test-Path -LiteralPath $outFile) { $text += Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue } } catch {}
        try { if (Test-Path -LiteralPath $errFile) { $text += Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue } } catch {}
        return [PSCustomObject]@{ ExitCode = $proc.ExitCode; Text = [string]$text }
    }

    function Show-WingetSnippet([string]$Text) {
        if (-not $Text -or $Text.Trim().Length -eq 0) { return }
        $snippet = @(($Text -replace '\r','') -split "`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -Last 6)
        foreach ($line in $snippet) {
            Write-Host ("    {0}" -f $line.Trim()) -ForegroundColor DarkGray
        }
    }

    Write-Host ("  Uninstalling {0}..." -f $AppName)
    try { Stop-BastionCatalogProcesses -AppName $AppName } catch {}

    # Prefer user-scope first when elevated (PowerToys and many Store/user installs)
    $attempts = @(
        @{ Label = "scope user"; Args = @("--scope","user") },
        @{ Label = "default scope"; Args = @() },
        @{ Label = "scope machine"; Args = @("--scope","machine") }
    )

    $last = $null
    $userScopeBlocked = $false
    foreach ($attempt in $attempts) {
        Write-Host ("    Trying winget uninstall ({0})..." -f $attempt.Label) -ForegroundColor DarkGray
        try {
            $last = Invoke-One -ExtraArgs $attempt.Args
        } catch {
            Write-Host ("    winget launch error: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            continue
        }
        Show-WingetSnippet $last.Text
        Write-Host ("    Exit {0}" -f $last.ExitCode) -ForegroundColor DarkGray
        if ($last.ExitCode -eq 0) {
            Write-Status ("{0} uninstall requested OK ({1})" -f $AppName, $attempt.Label) "Applied"
            return $true
        }
        if ($last.Text -match 'user scope cannot be uninstalled when running with administrator' -or $last.ExitCode -eq -1978335107) {
            $userScopeBlocked = $true
            # skip repeating the same failure mode; continue list still tries other scopes
            continue
        }
        # "No installed package found" on machine scope is expected for pure user installs - keep going / fall through
    }

    # HKCU uninstall registry fallback (works for many per-user MSI/EXE installs)
    Write-Host "    winget did not complete; trying HKCU uninstall registry..." -ForegroundColor Yellow
    $regs = @(Get-HkcuUninstallCommands -AppName $AppName -WingetId $WingetId)
    if ($regs.Count -eq 0) {
        Write-Host "    No HKCU uninstall entries matched." -ForegroundColor DarkGray
    } else {
        foreach ($reg in $regs) {
            Write-Host ("    Found: {0}" -f $reg.DisplayName) -ForegroundColor DarkGray
            $cmd = $reg.QuietUninstallString
            if ([string]::IsNullOrWhiteSpace($cmd)) { $cmd = $reg.UninstallString }
            if (Invoke-HkcuUninstallString -CommandLine $cmd) {
                Write-Status ("{0} uninstall via HKCU entry OK" -f $AppName) "Applied"
                return $true
            }
        }
    }

    # PowerToys explicit setup path fallback
    if ($AppName -eq "PowerToys") {
        $candidates = @(
            "$env:LOCALAPPDATA\PowerToys\PowerToys.exe",
            "C:\Program Files\PowerToys\PowerToys.exe",
            "C:\Program Files\PowerToys\PowerToysSetup*.exe"
        )
        foreach ($c in $candidates) {
            $files = @()
            if ($c -match '\*') {
                try { $files = @(Get-Item -Path $c -ErrorAction SilentlyContinue) } catch {}
            } elseif (Test-Path -LiteralPath $c) {
                $files = @(Get-Item -LiteralPath $c)
            }
            foreach ($f in $files) {
                try {
                    Write-Host ("    Trying: {0} --uninstall" -f $f.FullName) -ForegroundColor DarkGray
                    $proc = Start-Process -FilePath $f.FullName -ArgumentList @("--uninstall") -Wait -PassThru -ErrorAction Stop
                    if ($proc.ExitCode -eq 0) {
                        Write-Status "PowerToys --uninstall exit 0" "Applied"
                        return $true
                    }
                } catch {}
            }
        }
    }

    Write-Status ("{0} could not be uninstalled from this elevated session." -f $AppName) "Warn"
    Write-Host "    Per-user apps (PowerToys) often require a non-admin winget or Settings." -ForegroundColor Yellow
    Write-Host "    Try in a normal (non-admin) PowerShell:" -ForegroundColor Yellow
    Write-Host ("      winget uninstall -e --id {0} --scope user" -f $WingetId) -ForegroundColor Cyan
    Write-Host "    Or: Settings > Apps > Installed apps > PowerToys > Uninstall" -ForegroundColor Cyan
    try {
        Start-Process "ms-settings:appsfeatures" -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    Opened Settings > Apps for manual uninstall." -ForegroundColor DarkGray
    } catch {}
    return $false
}

function Get-DetectedCatalogInstalls {
    # Only catalog apps whose install paths/binaries are present right now.
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $script:ProgramDefs.Keys) {
        $def = $script:ProgramDefs[$name]
        if (Test-Installed -Name $name -Paths $def.Paths) {
            [void]$list.Add([PSCustomObject]@{
                Name     = $name
                WingetId = $def.WingetId
                Paths    = $def.Paths
            })
        }
    }
    return @($list)
}

function Show-UninstallMenu {
    Clear-BastionScreen
    Write-Header "UNINSTALL"
    $wg = Test-WingetAvailable
    if (-not $wg.Ok) {
        Write-Host ("  {0}" -f $wg.Error) -ForegroundColor Red
        Wait-ForKey
        return
    }

    # Selection is local; always starts empty. Only names that are currently installed may be selected.
    $selectedNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    while ($true) {
        $detected = @(Get-DetectedCatalogInstalls)
        $detectedNames = @{}
        foreach ($d in $detected) { $detectedNames[$d.Name] = $true }

        # Never keep a selection for something not installed right now.
        foreach ($name in @($selectedNames)) {
            if (-not $detectedNames.ContainsKey($name)) {
                [void]$selectedNames.Remove($name)
            }
        }

        $installed = foreach ($d in $detected) {
            [PSCustomObject]@{
                Name     = $d.Name
                WingetId = $d.WingetId
                Paths    = $d.Paths
                Selected = $selectedNames.Contains($d.Name)
            }
        }
        $installed = @($installed)

        if ($installed.Count -eq 0) {
            Clear-BastionScreen
            Write-Header "UNINSTALL"
            Write-Host "  No catalog apps are currently installed (nothing to select or remove)." -ForegroundColor Yellow
            Wait-ForKey
            return
        }

        Clear-BastionScreen
        Write-Header "UNINSTALL"
        Write-Host "  Only apps detected as INSTALLED can be selected or uninstalled." -ForegroundColor DarkGray
        Write-Host "  Missing catalog apps never appear here. [X] = queued to uninstall (starts empty)." -ForegroundColor DarkGray
        Write-Host "  After U, install paths are re-checked to verify removal." -ForegroundColor DarkGray
        Write-Host "  PowerToys is often per-user; elevated uninstall may fail (use Settings > Apps)." -ForegroundColor DarkYellow
        Write-Host ""
        for ($i = 0; $i -lt $installed.Count; $i++) {
            $row = $installed[$i]
            $mark = if ($row.Selected) { "[X]" } else { "[ ]" }
            $suffix = ""
            if ($row.Name -eq "PowerToys") { $suffix = "  (may need Settings > Apps)" }
            $color = if ($row.Selected) { "Yellow" } else { "Gray" }
            Write-Host ("  {0,2}. {1} {2}  installed{3}" -f ($i + 1), $mark, $row.Name, $suffix) -ForegroundColor $color
        }
        $sel = @($installed | Where-Object Selected | ForEach-Object { $_.Name })
        Write-Host ""
        Write-Host ("  Installed (selectable) {0} | Queued uninstall {1}" -f $installed.Count, $sel.Count) -ForegroundColor Cyan
        if ($sel.Count -gt 0) {
            Write-Host ("  Will remove: {0}" -f ($sel -join ", ")) -ForegroundColor Yellow
            Write-Host "  Press U to uninstall selected installed apps." -ForegroundColor Green
        } else {
            Write-Host "  No apps selected yet." -ForegroundColor DarkGray
        }
        Write-Host "  A all-installed  N none  U uninstall selected  0 back" -ForegroundColor Yellow
        $valid = @("A","N","U","0","a","n","u") + (1..$installed.Count | ForEach-Object { "$_" })
        $c = Read-MenuChoice -Prompt "  Select" -Valid $valid
        switch ($c.ToUpper()) {
            "0" { return }
            "A" {
                # Select only currently detected installs.
                $selectedNames.Clear()
                foreach ($row in $installed) {
                    if (Test-Installed -Name $row.Name -Paths $row.Paths) {
                        [void]$selectedNames.Add($row.Name)
                    }
                }
            }
            "N" { $selectedNames.Clear() }
            "U" {
                # Re-verify every target is still installed before acting.
                $targets = [System.Collections.Generic.List[object]]::new()
                foreach ($name in @($selectedNames)) {
                    if (-not $script:ProgramDefs.Contains($name)) {
                        [void]$selectedNames.Remove($name)
                        continue
                    }
                    $paths = $script:ProgramDefs[$name].Paths
                    if (Test-Installed -Name $name -Paths $paths) {
                        [void]$targets.Add([PSCustomObject]@{
                            Name     = $name
                            WingetId = $script:ProgramDefs[$name].WingetId
                            Paths    = $paths
                        })
                    } else {
                        Write-Host ("  Skipping {0}: not installed (deselected)." -f $name) -ForegroundColor DarkGray
                        [void]$selectedNames.Remove($name)
                    }
                }
                $targets = @($targets)
                if ($targets.Count -eq 0) {
                    Write-Host "  Nothing to uninstall. Only currently installed catalog apps can be removed." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }
                Write-Host ""
                Write-Host "  Will uninstall (verified installed):" -ForegroundColor Yellow
                $needsManualHint = $false
                foreach ($t in $targets) {
                    Write-Host ("    - {0} ({1})" -f $t.Name, $t.WingetId)
                    if ($t.Name -eq "PowerToys") { $needsManualHint = $true }
                }
                if ($needsManualHint) {
                    Write-Host "  PowerToys: elevated winget often cannot remove per-user installs." -ForegroundColor Yellow
                    Write-Host "  Prefer: Settings > Apps > Installed apps > PowerToys > Uninstall" -ForegroundColor Yellow
                    Write-Host "  Or non-admin: winget uninstall -e --id Microsoft.PowerToys --scope user" -ForegroundColor DarkGray
                }
                if (-not (Read-ConfirmYes -Prompt "  Type YES to uninstall these installed catalog apps")) { continue }

                $removed = [System.Collections.Generic.List[string]]::new()
                $stillThere = [System.Collections.Generic.List[string]]::new()
                foreach ($t in $targets) {
                    # Final gate: refuse uninstall if detection says absent.
                    if (-not (Test-Installed -Name $t.Name -Paths $t.Paths)) {
                        Write-Status ("{0} is not installed; skipped" -f $t.Name) "Skip"
                        [void]$selectedNames.Remove($t.Name)
                        continue
                    }
                    $defU = $script:ProgramDefs[$t.Name]
                    if ($defU.ManualInstallOnly -or [string]::IsNullOrWhiteSpace($t.WingetId)) {
                        Write-Status ("{0} has no winget uninstall ID" -f $t.Name) "Warn"
                        Write-Host "      Remove it from Settings > Apps, or the vendor uninstaller." -ForegroundColor Yellow
                        if ($defU.ManualUrl) {
                            Write-Host ("      Vendor: {0}" -f $defU.ManualUrl) -ForegroundColor DarkGray
                        }
                        [void]$stillThere.Add($t.Name)
                        continue
                    }
                    $idCheck = Test-CatalogPackageId -AppName $t.Name -WingetId $t.WingetId
                    if (-not $idCheck.Ok) {
                        Write-Status $idCheck.Detail "Failed"
                        Write-Host ("    Catalog ID was: {0}" -f $t.WingetId) -ForegroundColor DarkGray
                        [void]$stillThere.Add($t.Name)
                        continue
                    }
                    try {
                        [void](Invoke-WingetUninstallCatalog -AppName $t.Name -WingetId $t.WingetId)
                    } catch {
                        Write-Status ("{0} uninstall error: {1}" -f $t.Name, $_.Exception.Message) "Failed"
                    }
                    if (Test-Installed -Name $t.Name -Paths $t.Paths) {
                        Write-Status ("{0} still detected after uninstall attempt" -f $t.Name) "Warn"
                        [void]$stillThere.Add($t.Name)
                    } else {
                        Write-Status ("{0} removed (paths no longer detected)" -f $t.Name) "Applied"
                        [void]$removed.Add($t.Name)
                        [void]$selectedNames.Remove($t.Name)
                        if ($script:SelectedApps -contains $t.Name) {
                            [void]$script:SelectedApps.Remove($t.Name)
                        }
                    }
                }
                Write-Host ""
                if ($removed.Count -gt 0) {
                    Write-Host ("  Verified removed: {0}" -f ($removed -join ", ")) -ForegroundColor Green
                }
                if ($stillThere.Count -gt 0) {
                    Write-Host ("  Still present (manual remove may be needed): {0}" -f ($stillThere -join ", ")) -ForegroundColor Yellow
                }
                Sync-ProgramInstallQueue
                Save-BastionConfig
                Write-Host "  List will refresh to currently installed apps only. Press 0 when finished." -ForegroundColor DarkGray
                Wait-ForKey
                continue
            }
            default {
                if ($c -match '^\d+$') {
                    $idx = [int]$c - 1
                    if ($idx -ge 0 -and $idx -lt $installed.Count) {
                        $row = $installed[$idx]
                        # Only allow select if still installed at toggle time.
                        if (-not (Test-Installed -Name $row.Name -Paths $row.Paths)) {
                            Write-Host ("  {0} is not installed; cannot select for uninstall." -f $row.Name) -ForegroundColor Yellow
                            [void]$selectedNames.Remove($row.Name)
                            Start-Sleep -Seconds 1
                        } elseif ($selectedNames.Contains($row.Name)) {
                            [void]$selectedNames.Remove($row.Name)
                        } else {
                            [void]$selectedNames.Add($row.Name)
                        }
                    }
                }
            }
        }
    }
}


function Enable-PrintSpooler {
    if ((Read-YesNo -Prompt "  Re-enable Print Spooler (Y/N)?") -ne "Y") { return }
    try {
        Set-Service -Name Spooler -StartupType Automatic -ErrorAction Stop
        Start-Service -Name Spooler -ErrorAction Stop
        Write-Host "  Spooler is Automatic and running." -ForegroundColor Green
    } catch {
        Write-Host ("  Failed: {0}. Next step: services.msc -> Print Spooler." -f $_.Exception.Message) -ForegroundColor Red
    }
    Wait-ForKey
}

function Invoke-UndoHardening {
    Clear-BastionScreen
    Write-Header "UNDO LAST HARDENING"
    Write-Host "  Best-effort only. System Restore is stronger for full rollback." -ForegroundColor Yellow
    if (-not (Read-ConfirmYes -Prompt "  Type YES to attempt Undo")) { return }
    $undoData = $null
    if (Test-Path -LiteralPath $script:undoFile) {
        try { $undoData = Get-Content -LiteralPath $script:undoFile -Raw | ConvertFrom-Json } catch {}
    }
    try {
        Set-Service Spooler -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service Spooler -ErrorAction SilentlyContinue
    } catch {}
    if ($undoData -and $undoData.DisabledServices) {
        foreach ($entry in @($undoData.DisabledServices)) {
            $name = $entry.Name
            if (-not $name -or $name -eq "Spooler") { continue }
            try {
                if (Get-ServiceState $name) {
                    $st = if ($entry.Original) { [string]$entry.Original } else { "Manual" }
                    if ($st -eq "AutomaticDelayedStart") { $st = "Automatic" }
                    if ($st -notin @("Automatic","Manual","Disabled")) { $st = "Manual" }
                    Set-Service -Name $name -StartupType $st -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }
    if ($undoData -and $undoData.FirewallGroups) {
        foreach ($g in @($undoData.FirewallGroups)) {
            try {
                Get-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue |
                    Where-Object { $_.Direction -eq "Inbound" } |
                    Set-NetFirewallRule -Enabled True -Confirm:$false -ErrorAction SilentlyContinue
            } catch {}
        }
    }
    Write-Host "  Undo finished (partial by design). Next step if issues remain: System Restore." -ForegroundColor Green
    Wait-ForKey
}


function Get-CopilotM365Status {
    $pkgs = @()
    try {
        $pkgs = @(Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match $script:CopilotM365PackageMatch
        } | Select-Object Name, PackageFullName, Version)
    } catch {}
    $prov = @()
    try {
        $prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -match $script:CopilotM365PackageMatch -or $_.PackageName -match $script:CopilotM365PackageMatch
        } | Select-Object DisplayName, PackageName)
    } catch {}
    $policyOff = $false
    try {
        $v = (Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name TurnOffWindowsCopilot -ErrorAction SilentlyContinue).TurnOffWindowsCopilot
        if ($v -eq 1) { $policyOff = $true }
    } catch {}
    try {
        $v2 = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name TurnOffWindowsCopilot -ErrorAction SilentlyContinue).TurnOffWindowsCopilot
        if ($v2 -eq 1) { $policyOff = $true }
    } catch {}
    $buttonHidden = $false
    try {
        $b = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowCopilotButton -ErrorAction SilentlyContinue).ShowCopilotButton
        if ($b -eq 0) { $buttonHidden = $true }
    } catch {}
    $officeC2R = Test-Path -LiteralPath "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe"
    return [PSCustomObject]@{
        UserPackages     = $pkgs
        Provisioned      = $prov
        PolicyOff        = $policyOff
        ButtonHidden     = $buttonHidden
        OfficeClickToRun = $officeC2R
        HasAppx          = ($pkgs.Count -gt 0)
        NeedsWork        = (-not $policyOff) -or (-not $buttonHidden) -or ($pkgs.Count -gt 0)
    }
}

function Invoke-CopilotM365Hardening {
    param([switch]$IncludeProvisioned)
    Write-Host "  [CopilotM365]" -ForegroundColor Cyan
    $status = Get-CopilotM365Status
    if ($status.HasAppx) {
        Write-Host "    Detected user packages:" -ForegroundColor Yellow
        foreach ($p in $status.UserPackages) {
            Write-Host ("      - {0} ({1})" -f $p.Name, $p.Version) -ForegroundColor DarkGray
        }
    } else {
        Write-Host "    No matching Copilot / Office Hub user Appx detected." -ForegroundColor DarkGray
    }
    if ($status.OfficeClickToRun) {
        Write-Host "    Microsoft 365 Click-to-Run is installed (full Office suite)." -ForegroundColor Yellow
        Write-Host "    Apply will NOT uninstall Word/Excel/Outlook. Use Recovery option 4 item 3 for that." -ForegroundColor DarkGray
    }

    # Policy + taskbar
    try {
        foreach ($key in @(
            "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
        )) {
            if (-not (Test-Path $key)) { New-Item $key -Force -ErrorAction Stop | Out-Null }
            $cur = $null
            try { $cur = (Get-ItemProperty $key -Name TurnOffWindowsCopilot -ErrorAction SilentlyContinue).TurnOffWindowsCopilot } catch {}
            if ($cur -eq 1) {
                Write-Status "TurnOffWindowsCopilot already set ($key)" "Already"
            } else {
                New-ItemProperty $key -Name TurnOffWindowsCopilot -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                Write-Status "TurnOffWindowsCopilot set ($key)" "Applied"
            }
        }
    } catch {
        Write-Status ("Copilot policy: {0}" -f $_.Exception.Message) "Warn"
    }
    try {
        $adv = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        if (-not (Test-Path $adv)) { New-Item $adv -Force -ErrorAction Stop | Out-Null }
        $cur = $null
        try { $cur = (Get-ItemProperty $adv -Name ShowCopilotButton -ErrorAction SilentlyContinue).ShowCopilotButton } catch {}
        if ($cur -eq 0) {
            Write-Status "ShowCopilotButton already hidden" "Already"
        } else {
            New-ItemProperty $adv -Name ShowCopilotButton -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Write-Status "ShowCopilotButton hidden (sign-out may be required)" "Applied"
        }
    } catch {
        Write-Status ("Taskbar Copilot button: {0}" -f $_.Exception.Message) "Warn"
    }

    # User Appx removal
    $status2 = Get-CopilotM365Status
    if ($status2.UserPackages.Count -eq 0) {
        Write-Status "No Copilot/Office Hub user Appx to remove" "Already"
    } else {
        foreach ($p in $status2.UserPackages) {
            try {
                Remove-AppxPackage -Package $p.PackageFullName -ErrorAction Stop
                Write-Status ("Removed Appx: {0}" -f $p.Name) "Applied"
            } catch {
                Write-Status ("Could not remove {0}: {1}" -f $p.Name, $_.Exception.Message) "Warn"
            }
        }
    }

    if ($IncludeProvisioned) {
        try {
            $prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -match $script:CopilotM365PackageMatch -or $_.PackageName -match $script:CopilotM365PackageMatch
            })
            foreach ($pp in $prov) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop | Out-Null
                    Write-Status ("Removed provisioned: {0}" -f $pp.DisplayName) "Applied"
                } catch {
                    Write-Status ("Provisioned skip {0}: {1}" -f $pp.DisplayName, $_.Exception.Message) "Warn"
                }
            }
        } catch {
            Write-Status ("Provisioned query failed: {0}" -f $_.Exception.Message) "Warn"
        }
    }

    Write-Host "    Note: Full Microsoft 365 desktop apps are unchanged unless you use Recovery > Office remover." -ForegroundColor DarkGray
}

function Invoke-CopilotM365Removal {
    while ($true) {
        Clear-BastionScreen
        Write-Header "COPILOT / M365 TOOLS"
        $st = Get-CopilotM365Status
        Write-Host "  Detection" -ForegroundColor Cyan
        if ($st.HasAppx) {
            foreach ($p in $st.UserPackages) {
                Write-Host ("    Appx: {0} v{1}" -f $p.Name, $p.Version) -ForegroundColor Yellow
            }
        } else {
            Write-Host "    Appx: no Copilot / MicrosoftOfficeHub packages found" -ForegroundColor Green
        }
        Write-Host ("    Policy TurnOffWindowsCopilot: {0}" -f $(if ($st.PolicyOff) { "ON (Copilot disabled)" } else { "off / not set" })) `
            -ForegroundColor $(if ($st.PolicyOff) { "Green" } else { "Yellow" })
        Write-Host ("    Taskbar ShowCopilotButton hidden: {0}" -f $(if ($st.ButtonHidden) { "yes" } else { "no" })) `
            -ForegroundColor $(if ($st.ButtonHidden) { "Green" } else { "Yellow" })
        Write-Host ("    Office Click-to-Run present: {0}" -f $(if ($st.OfficeClickToRun) { "yes (full M365 possible)" } else { "no" })) `
            -ForegroundColor $(if ($st.OfficeClickToRun) { "Yellow" } else { "DarkGray" })
        Write-Host ""
        Write-Host "  1  Apply policy + hide Copilot taskbar button" -ForegroundColor Green
        Write-Host "  2  Remove Copilot / Office Hub Appx (user)" -ForegroundColor Green
        Write-Host "  3  Remove provisioned Copilot / Office Hub packages" -ForegroundColor Yellow
        Write-Host "  4  Official Office Click-to-Run uninstall (FULL M365 - destructive)" -ForegroundColor Red
        Write-Host "  5  Run all safe steps (1+2+3, not full Office uninstall)" -ForegroundColor Cyan
        Write-Host "  0  Back" -ForegroundColor DarkGray
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3","4","5")
        switch ($c) {
            "0" { return }
            "1" {
                try {
                    foreach ($key in @(
                        "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot",
                        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
                    )) {
                        if (-not (Test-Path $key)) { New-Item $key -Force | Out-Null }
                        New-ItemProperty $key -Name TurnOffWindowsCopilot -Value 1 -PropertyType DWord -Force | Out-Null
                    }
                    $adv = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                    if (-not (Test-Path $adv)) { New-Item $adv -Force | Out-Null }
                    New-ItemProperty $adv -Name ShowCopilotButton -Value 0 -PropertyType DWord -Force | Out-Null
                    Write-Host "  Policy applied. Sign out may be required for taskbar." -ForegroundColor Green
                } catch {
                    Write-Host ("  Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                }
                Wait-ForKey "Press any key to return to the Copilot / M365 menu..."
            }
            "2" {
                $st2 = Get-CopilotM365Status
                if ($st2.UserPackages.Count -eq 0) {
                    Write-Host "  Nothing to remove." -ForegroundColor Green
                } else {
                    foreach ($p in $st2.UserPackages) {
                        try {
                            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction Stop
                            Write-Host ("  Removed: {0}" -f $p.Name) -ForegroundColor Green
                        } catch {
                            Write-Host ("  Failed {0}: {1}" -f $p.Name, $_.Exception.Message) -ForegroundColor Red
                        }
                    }
                }
                Wait-ForKey "Press any key to return to the Copilot / M365 menu..."
            }
            "3" {
                try {
                    $prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {
                        $_.DisplayName -match $script:CopilotM365PackageMatch -or $_.PackageName -match $script:CopilotM365PackageMatch
                    })
                    if ($prov.Count -eq 0) {
                        Write-Host "  No matching provisioned packages." -ForegroundColor Green
                    } else {
                        foreach ($pp in $prov) {
                            try {
                                Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop | Out-Null
                                Write-Host ("  Removed provisioned: {0}" -f $pp.DisplayName) -ForegroundColor Green
                            } catch {
                                Write-Host ("  Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                            }
                        }
                    }
                } catch {
                    Write-Host ("  Query failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                }
                Wait-ForKey "Press any key to return to the Copilot / M365 menu..."
            }
            "4" {
                Write-Host "  This launches Microsoft's Office Click-to-Run uninstall for the FULL suite." -ForegroundColor Red
                Write-Host "  Create a restore point first (main menu 13 / R)." -ForegroundColor Yellow
                if ((Read-ConfirmYes -Prompt "  Type YES to launch Office uninstall") -ne $true) {
                    Write-Host "  Cancelled." -ForegroundColor Yellow
                    Wait-ForKey "Press any key to return to the Copilot / M365 menu..."
                    continue
                }
                $c2r = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe"
                if (Test-Path -LiteralPath $c2r) {
                    try {
                        Start-Process -FilePath $c2r -ArgumentList "scenario=install scenariosubtype=ARP sourcetype=None productstoremove=AllProducts displaylevel=True" -Wait
                        Write-Host "  Office remover finished (check Programs and Features)." -ForegroundColor Green
                    } catch {
                        Write-Host ("  Launch failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                    }
                } else {
                    Write-Host "  Office Click-to-Run not found." -ForegroundColor Yellow
                }
                Wait-ForKey "Press any key to return to the Copilot / M365 menu..."
            }
            "5" {
                Invoke-CopilotM365Hardening -IncludeProvisioned
                Wait-ForKey "Press any key to return to the Copilot / M365 menu..."
            }
        }
    }
}


function Show-RecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "RECOVERY / FIX"
        Write-Host "  1 Undo last hardening (services / firewall groups from last Apply)"
        Write-Host "  2 Re-enable Print Spooler"
        Write-Host "  3 Browser policies (per browser; Default reverts Bastion policies)"
        Write-Host "  4 Copilot / M365 tools"
        Write-Host "  5 Restore Widgets / Suggestions defaults" -ForegroundColor Green
        Write-Host "  0 Back"
        Write-Host ""
        Write-Host "  Note: Appx bloat removal is not reinstallable here - use System Restore or Microsoft Store." -ForegroundColor DarkGray
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3","4","5")
        switch ($c) {
            "0" { return }
            "1" { Invoke-UndoHardening }
            "2" { Enable-PrintSpooler }
            "3" { Show-BrowserPolicyMenu }
            "4" { Invoke-CopilotM365Removal }
            "5" {
                Write-Host ""
                if ((Read-YesNo -Prompt "  Restore Widgets/Suggestions registry defaults (Y/N)?") -eq "Y") {
                    Restore-SuggestionDefaults
                }
                Wait-ForKey
            }
        }
    }
}

function Show-Help {
    function Read-HelpNav {
        param([int]$Page, [int]$Total)
        while ($true) {
            try { $width = Get-BastionConsoleWidth } catch { $width = 78 }
            $rule = "-" * [Math]::Min(64, [Math]::Max(40, $width - 4))
            Write-Host ("  " + $rule) -ForegroundColor DarkCyan
            Write-Host ("  Documentation  |  page {0} of {1}" -f $Page, $Total) -ForegroundColor DarkGray
            Write-Host "  How to move (Help keys only - not the main menu):" -ForegroundColor Yellow
            Write-Host "    Enter   Next page" -ForegroundColor White
            Write-Host "    B       Back to Help and Reports" -ForegroundColor White
            Write-Host "    Q       Quit documentation" -ForegroundColor White
            try { $k = (Read-Host "  Press Enter, B, or Q").Trim() } catch { $k = "" }
            if ([string]::IsNullOrWhiteSpace($k)) { return "next" }
            if ($k -match '^[Nn]$') { return "next" }
            if ($k -match '^[Bb]$') { return "back" }
            if ($k -match '^[Qq]$') { return "quit" }
            if ($k -match '^\d+$') {
                Write-Host "  Those numbers are for the MAIN menu after you leave Help." -ForegroundColor Red
                Write-Host "  In documentation use Enter, B, or Q only." -ForegroundColor Red
                continue
            }
            Write-Host "  Please press Enter (next), B (back), or Q (quit)." -ForegroundColor Red
        }
    }

    function Show-LineChunks {
        param(
            [string]$Title,
            [string[]]$DisplayLines,
            [int]$Page,
            [int]$Total
        )
        # Fit content to the visible window so the user always starts at the top
        $height = Get-BastionConsoleHeight
        $chunkSize = [Math]::Max(8, $height - 14)
        if ($null -eq $DisplayLines) { $DisplayLines = @() }
        if ($DisplayLines.Count -eq 0) { $DisplayLines = @("  (No content)") }
        $offset = 0
        while ($offset -lt $DisplayLines.Count) {
            Clear-BastionScreen
            Write-Header $Title
            Write-Host ""
            $end = [Math]::Min($offset + $chunkSize - 1, $DisplayLines.Count - 1)
            for ($i = $offset; $i -le $end; $i++) {
                $line = $DisplayLines[$i]
                if ($null -eq $line) { Write-Host ""; continue }
                if ($line -match '^\s*\[[^\]]+\]\s*$') {
                    Write-Host $line -ForegroundColor Cyan
                } elseif ($line -match '^\s*(Why|Apply does|You may notice|How to undo|Good to know)\s*$') {
                    Write-Host $line -ForegroundColor DarkCyan
                } else {
                    Write-Host $line -ForegroundColor White
                }
            }
            $offset = $end + 1
            if ($offset -lt $DisplayLines.Count) {
                Write-Host ""
                Write-Host ("  --- more on this page ({0} lines left) ---" -f ($DisplayLines.Count - $offset)) -ForegroundColor DarkGray
                try { [void](Read-Host "  Press Enter to continue from the top of the next section of this page") } catch {}
            }
        }
        Write-Host ""
        return (Read-HelpNav -Page $Page -Total $Total)
    }

    function Show-HelpPage {
        param([string]$Title, [string[]]$Lines, [int]$Page, [int]$Total)
        $display = New-Object System.Collections.Generic.List[string]
        foreach ($line in $Lines) {
            if ($null -eq $line) { continue }
            if ($line -match '^\s*$') { [void]$display.Add(""); continue }
            if ($line -match '^\s*##\s+(.*)$') {
                [void]$display.Add("")
                foreach ($wl in @(Get-WrappedLines -Text $Matches[1] -Indent 2)) {
                    [void]$display.Add($wl)
                }
                continue
            }
            foreach ($wl in @(Get-WrappedLines -Text $line.TrimEnd() -Indent 2)) {
                [void]$display.Add($wl)
            }
        }
        return (Show-LineChunks -Title $Title -DisplayLines @($display) -Page $Page -Total $Total)
    }

    function Show-HelpSectionDocs {
        param([string[]]$Keys, [string]$Title, [int]$Page, [int]$Total)
        $display = New-Object System.Collections.Generic.List[string]
        [void]$display.Add((Get-WrappedLines -Text "Each block explains why the section exists, what Apply does, what you may notice, and how to undo it." -Indent 2)[0])
        [void]$display.Add("")
        foreach ($key in $Keys) {
            if (-not $script:SectionDocs.Contains($key)) { continue }
            $d = $script:SectionDocs[$key]
            [void]$display.Add(("  [{0}]" -f $key))
            foreach ($pair in @(
                @{ L = "Why"; B = $d.Intent },
                @{ L = "Apply does"; B = $d.Changes },
                @{ L = "You may notice"; B = $d.Impact },
                @{ L = "How to undo"; B = $d.Revert },
                @{ L = "Good to know"; B = $d.Notes }
            )) {
                [void]$display.Add(("  {0}" -f $pair.L))
                foreach ($wl in @(Get-WrappedLines -Text $pair.B -Indent 4)) {
                    [void]$display.Add($wl)
                }
            }
            [void]$display.Add("")
        }
        return (Show-LineChunks -Title $Title -DisplayLines @($display) -Page $Page -Total $Total)
    }

    $total = 13

    $r = Show-HelpPage -Title "HELP 1/13 - WHAT BASTION IS" -Page 1 -Total $total -Lines @(
        "## Purpose",
        "Bastion is a selective, state-aware hardening assistant for a single Windows PC you administer.",
        "It helps you measure risk, choose sections, apply changes with logging, and recover common side effects.",
        "## What it is",
        "A guided toolkit: Dry Run, Security Audit, section toggles, catalog app installs, browser policy modes, Recovery, and documentation.",
        "State-aware means Apply and Dry Run detect live Windows state (services, firewall, registry, features) so repeats stay calm.",
        "Bastion JSON files remember your menu choices and last Apply undo data. They do not fake that Apply already ran.",
        "The data directory path is shown on the main menu. Help page 12 lists every Bastion file and folder and when it is created.",
        "Encrypted Client Hello (ECH) is never on by default - see Help page 7.",
        "## What it is not",
        "Not an antivirus product, not enterprise MDM, not a guarantee against zero-days, and not an automated GPU or BIOS flasher.",
        "## Safety model",
        "System Restore is the real safety net. Use main menu 13 or R before major changes. Undo covers tracked services and firewall groups from the last Apply only.",
        "Irreversible or hard-to-reverse items (BloatApps, OneDrive removal) stay off until you opt in and are called out explicitly."
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpPage -Title "HELP 2/13 - RECOMMENDED WORKFLOW" -Page 2 -Total $total -Lines @(
        "## First-time flow",
        "0. First elevated launch (Bastion-Hardening.bat) creates a writable data directory and seeds Bastion-Config.json with defaults.",
        "   No Bastion-LastApply.json is written until you actually Apply - Dry Run still reads live Windows state.",
        "1. Main menu 13 or R - create a named System Restore Point.",
        "2. Option 1 Dry Run - read Would change vs Already OK with your current toggles.",
        "3. Option 2 Security audit - posture sample (firewall, DNS, Defender, browsers, winget, restore points).",
        "4. Option 4 Sections - enable only what you understand; leave BloatApps and BrowserPolicies off until ready.",
        "5. Option 5 Programs - queue missing catalog apps only if you want installs (none pre-selected).",
        "6. Option 6 Browser policies (optional) - only installed Firefox/Chrome/Brave. Pick mode per browser; Encrypted Client Hello (ECH) is a separate Yes/No under Strict and never default.",
        "7. Option 7 Quick Harden or 8 Apply - confirm restore-point gate, then type YES.",
        "8. Reboot if LSA Protection or optional features require it, then Dry Run again.",
        "## Everyday flow",
        "Change one area at a time, Dry Run, Apply, verify. Use Recovery for Spooler, per-browser Default (revert), Suggestions, or Undo.",
        "If you delete the Bastion data folder, the next launch re-seeds defaults and re-detects the live system - it does not invent a prior Apply.",
        "## If something goes wrong",
        "Recovery menu first. For browser breakage after Strict or Encrypted Client Hello (ECH): menu 6 > that browser > Default. For deep failure: Safe Mode then System Restore."
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpPage -Title "HELP 3/13 - MAIN MENU MAP" -Page 3 -Total $total -Lines @(
        "## REVIEW",
        "1 Dry Run - preview only, no changes. Shows Would change, Already OK, or Skipped per section.",
        "2 Audit - live posture sample with a simple scoreboard.",
        "3 Hardware - GPU, board, BIOS detection and official vendor links only.",
        "## CONFIGURE",
        "4 Sections - toggle each hardening area on or off.",
        "5 Programs and paths - choose catalog apps and optional install roots.",
        "6 Browser policies - Firefox/Chrome/Brave independently. Strict is optional; Encrypted Client Hello (ECH) pack is a second Yes/No per browser. See help page 7.",
        "D DNS resolver - Quad9, Cloudflare, Cloudflare security, Google, OpenDNS, or do not change DNS.",
        "## EXECUTE",
        "7 Quick Harden - safe preset, restore-point gate, then Apply.",
        "8 Apply - runs every enabled section with logging and undo tracking.",
        "## MAINTAIN AND SAFETY",
        "9 Recovery - Undo, Spooler, browser policies, Copilot/M365 tools, Suggestions restore.",
        "10 Uninstall - remove catalog apps via winget with confirmation.",
        "13 or R - create or name a System Restore Point anytime (recommended before Apply).",
        "11 Help and reports - this documentation, last Apply JSON, HTML export.",
        "12 Reset Bastion config - clears Bastion toggles only, not Windows itself.",
        "0 Exit",
        "## Aliases",
        "Q Quick Harden, A Apply, H Help, D DNS resolver. Numbers typed inside Help documentation are ignored on purpose."
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpSectionDocs -Title "HELP 4/13 - NETWORK AND SERVICES" -Page 4 -Total $total -Keys @(
        "Firewall","HighRiskServices","SMBv1","OneDrive","DeliveryOptimization","DNS"
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpSectionDocs -Title "HELP 5/13 - DEFENDER AND OS HARDENING" -Page 5 -Total $total -Keys @(
        "Defender","PowerShellAuditing","ExploitProtection","LSAProtection","ScheduledTasks","XboxGaming"
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpSectionDocs -Title "HELP 6/13 - APPS AND UI SURFACES" -Page 6 -Total $total -Keys @(
        "Programs","BrowserPolicies","BloatApps","Suggestions","CopilotM365"
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpPage -Title "HELP 7/13 - BROWSERS, STRICT MODE, AND ECH" -Page 7 -Total $total -Lines @(
        "## Where to configure",
        "Main menu 6 (or Recovery > 3). Only installed supported browsers appear: Firefox, Chrome, Brave.",
        "Missing browsers are never listed, so you cannot change settings for an engine you do not have.",
        "Pick one installed browser (or all detected), then Default / Medium / Strict for that selection only.",
        "## Encrypted Client Hello (ECH) is never automatic",
        "Installing Bastion, installing a browser, or choosing Strict alone does not enable Encrypted Client Hello (ECH).",
        "If you choose Strict, Bastion asks a separate Yes/No for the Encrypted Client Hello (ECH) pack on only the browsers you selected.",
        "Answer No (or skip Strict) and no ECH pack is written. Defaults and fresh configs keep ECH off for every browser.",
        "## Modes",
        "Default - remove Bastion policies and any ECH pack for that browser only (best-effort revert; backups kept).",
        "Medium - privacy baseline (telemetry / tracking / cookies). Usually fewer breakages than Strict.",
        "Strict - Medium plus HTTPS-Only. Does not include Encrypted Client Hello (ECH) unless you answer Yes next.",
        "## Encrypted Client Hello (ECH) pack (optional)",
        "Encrypted Client Hello (ECH) is a TLS feature. Without it, the Client Hello can expose the destination hostname to passive observers on the path.",
        "With Encrypted Client Hello (ECH), supporting clients and servers can encrypt that material so observers learn less about which site you open (when the path cooperates).",
        "First-run seed, Dry Run, Audit, and Strict alone never write an ECH pack. Only an explicit Yes under Strict for selected installed browsers does.",
        "Firefox + ECH Yes: locks network.dns.echconfig.enabled and related prefs in policies.json. Bastion never sets DisableEncryptedClientHello (that turns ECH off).",
        "Chrome/Brave + ECH Yes: not the same as Firefox prefs; Bastion sets BastionEchLock intent marker and the strongest transport policies it can via enterprise registry.",
        "You may enable Encrypted Client Hello (ECH) on any mix of installed browsers, or on none. Wanted Yes is stored in Bastion-Config.json; live on/off is detected each Dry Run and session snapshot.",
        "## Why some sites break",
        "HTTPS-Only: plain HTTP, mixed content, captive portals, and misconfigured HTTPS hosts may fail.",
        "Encrypted Client Hello (ECH): some networks or middleboxes mishandle it; use another browser or set that browser to Default.",
        "Tracking and cookie limits: some SSO, banks, embeds, and older payment widgets need looser settings.",
        "## Dry Run and Security audit",
        "Dry Run compares live mode and ECH on/off to your saved intent for each installed browser only.",
        "Security audit lists each installed browser with live/saved mode and Encrypted Client Hello (ECH) status.",
        "## Revert and logging",
        "Per browser: menu 6 > that browser > Default. Session log, Bastion-BrowserPolicies-State.json, and browser-policy-backups support best-effort recovery.",
        "System Restore (menu 13 / R) remains the bulletproof rollback."
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpPage -Title "HELP 8/13 - DRY RUN, APPLY, VERIFY" -Page 8 -Total $total -Lines @(
        "## Dry Run",
        "Reads the live system and compares it to enabled sections. It never changes configuration.",
        "Would change means Apply would still do work. Already OK means detection believes the goal is met. Skipped means the section toggle is off.",
        "BrowserPolicies (when enabled): for each installed Firefox/Chrome/Brave, compares live mode and Encrypted Client Hello (ECH) on/off to saved intent. ECH want is Yes only if you previously chose Yes under Strict.",
        "BrowserPolicies (when skipped): reports how many supported browsers are installed; menu 6 still works independently of the section toggle.",
        "## Apply",
        "Runs enabled sections in a fixed order, writes a log under the Bastion data directory, updates Bastion-LastApply.json for tracked undo data, and prints Applied / Already / Failed counts.",
        "BrowserPolicies Apply only touches installed browsers and only applies Encrypted Client Hello (ECH) when saved as Yes for that browser.",
        "You must pass the restore-point gate (or create a point when prompted).",
        "## Security audit (option 2)",
        "Scoreboard of firewall, DNS, services, Defender, each installed browser (mode + ECH), winget, and System Restore status. It does not change settings.",
        "## Verify",
        "Run Dry Run again after Apply. Run Audit for a compact scoreboard. Browsers: about:policies / chrome://policy / brave://policy after a full restart."
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpPage -Title "HELP 9/13 - INSTALL SECURITY" -Page 9 -Total $total -Lines @(
        "## Why installs are locked down",
        "Supply-chain risk is real. Bastion only installs IDs that appear in its built-in catalog.",
        "## Rules enforced",
        "1. Catalog allow-list only - unknown names are rejected.",
        "2. winget uses exact -e --id; IDs must match the catalog string exactly.",
        "3. --ignore-security-hash is never used.",
        "4. Preflight checks that winget exists and trusted sources (winget, msstore) are present.",
        "5. Optional custom install paths must sit on fixed local volumes and outside system directories.",
        "6. After install, Bastion checks known paths; some vendors still ignore --location.",
        "## Uninstall",
        "Menu 10 lists detected catalog apps only, selection starts empty, confirms with YES, then uninstalls and re-checks paths."
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpPage -Title "HELP 10/13 - HARDWARE GUIDANCE" -Page 10 -Total $total -Lines @(
        "## Design choice",
        "Bastion detects hardware and opens official support pages. It does not download or flash GPU drivers or BIOS images.",
        "## What you get",
        "Computer model, CPU, motherboard string, BIOS version/date, GPUs with driver versions, and links for NVIDIA, AMD, Intel when applicable.",
        "Motherboard vendor support links appear when the board string matches Gigabyte, ASUS, MSI, ASRock, Dell, HP, or Lenovo.",
        "## BIOS safety",
        "Update BIOS only from the board or OEM vendor, on AC power, and never interrupt a flash. Third-party driver booster tools are out of scope and discouraged."
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpPage -Title "HELP 11/13 - RECOVERY AND SAFE MODE" -Page 11 -Total $total -Lines @(
        "## Recovery menu (option 9)",
        "1 Undo last hardening - services and firewall groups tracked in Bastion-LastApply.json.",
        "2 Re-enable Print Spooler - when HighRiskServices disabled printing.",
        "3 Browser policies - only installed Firefox/Chrome/Brave. Default/Medium/Strict per browser; Encrypted Client Hello (ECH) only if you opt in. Default reverts that browser (best-effort; System Restore is bulletproof).",
        "4 Copilot / M365 tools - optional removal helpers.",
        "5 Restore Widgets/Suggestions defaults - reverses Suggestions registry work where possible.",
        "## System Restore",
        "Preferred full rollback. Create points from menu 13 or R. If Windows will not log on normally: hold Shift while selecting Restart, open Troubleshoot > Advanced > Startup Settings > Restart, then Safe Mode, then rstrui.exe.",
        "## Honest limits of Undo",
        "Undo does not reinstall Appx bloat or OneDrive, and does not remove winget-installed programs (use Uninstall)."
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpPage -Title "HELP 12/13 - FILES AND LOGS" -Page 12 -Total $total -Lines @(
        ("## Directory (this session): {0}" -f $script:Config.LogDirectory),
        "Created automatically on first elevated launch. Prefer durable paths over wipeable temp.",
        "Resolve order for existing state: C:\Temp\Bastion, legacy C:\Temp, %ProgramData%\Bastion, %LOCALAPPDATA%\Bastion, then %TEMP%\Bastion (last).",
        "New installs prefer C:\Temp\Bastion, then ProgramData, then LocalAppData, then legacy flat C:\Temp. %TEMP%\Bastion is last-resort only.",
        "Bastion-Config.json - section toggles, selected apps, install roots, per-browser wanted modes and ECH Yes/No flags, DNS provider (seeded on first run; ECH defaults off).",
        "Bastion-Session.json - rewritten every launch: live browser posture vs wanted modes; proves the store is real. Not Apply history.",
        "Bastion-BrowserPolicies-State.json - wanted + live browser modes, ECH live/wanted, last policy change summary.",
        "browser-policy-backups/ - snapshots taken before Bastion overwrites browser policies (menu 6).",
        "Bastion-LastApply.json - only after a real Apply: timestamp, sections run, tracked undo data. Missing = no Bastion Apply undo yet.",
        "Bastion-Log-*.txt - session transcript lines for support and review.",
        "Bastion-Report-*.html - optional HTML snapshot from Help and Reports.",
        "BastionInstallers/ - staging folder under the data directory for optional install work.",
        "## Outside this directory (only when you choose features)",
        "Firefox distribution\\policies.json; Chrome/Brave HKLM policy keys; services/firewall/DNS/Defender/AppX on Apply; System Restore points you create.",
        "Encrypted Client Hello (ECH) policy material is written only after an explicit Yes under Strict - never on first-run seed.",
        "Deleting the data directory does not un-harden Windows or remove browser enterprise policies; next run re-seeds Bastion defaults and detects live state again.",
        ("Windows Event Log Application source: {0}" -f $script:Config.EventSource),
        "Repo docs (when present beside the script): docs\\DATA-DIRECTORY.md and docs\\BROWSER-POLICIES-AND-ECH.md.",
        "Optional Bastion-Banner.utf8.txt beside the script supplies a Unicode logo; ASCII fallback is built in."
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpPage -Title "HELP 13/13 - LIMITS AND EXPECTATIONS" -Page 13 -Total $total -Lines @(
        "## Expected behaviors",
        "VPN DNS while connected may differ from the chosen public resolver on the physical adapter. That is normal.",
        "Menu D lets you pick Quad9, Cloudflare, Cloudflare security, Google Public DNS, Cisco OpenDNS, or leave DNS unchanged.",
        "Browser Strict (HTTPS-Only) and an optional Encrypted Client Hello (ECH) pack can break some sites or networks; ECH is never applied unless you choose Yes. Use different modes per installed browser if needed.",
        "Optional HKLM policy values for News/Interests may be denied by Windows even when elevated; that is a Soft skip, not a hard failure.",
        "Some installers ignore custom --location after path validation succeeds.",
        "## Known issue (games / ExploitProtection)",
        "Older Bastion builds enabled system-wide StrictHandle (strict handle checks). That can crash World of Warcraft at Play or Wow.exe with Eidolon and Crash.txt summary INVALID_HANDLE in Wow_loader.dll.",
        "Workaround: elevated Set-ProcessMitigation -System -Disable StrictHandle then reboot. Current Bastion does not enable StrictHandle and turns it off on ExploitProtection Apply. See GitHub issue #18.",
        "## Deliberate non-goals",
        "No aggressive system-wide exploit mitigation sets that previously caused black-screen logons on some hardware.",
        "No system-wide StrictHandle (breaks some game loaders such as WoW).",
        "No automatic NVIDIA App or BIOS flashing from winget.",
        "No claim of complete malware prevention - Bastion reduces exposure and improves visibility.",
        "## Version",
        ("You are reading documentation for Bastion v{0}. Measure with Dry Run, protect with a restore point, then Apply." -f $script:Config.ScriptVersion)
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    Write-Host ""
    Write-Host "  End of documentation." -ForegroundColor Green
    Write-Host "  Return to the main menu to Dry Run, Apply, or open Recovery." -ForegroundColor DarkGray
    Wait-ForKey
}




function Show-HelpReportsMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "HELP AND REPORTS"
        Write-Host ""
        Write-Host "  1  Full documentation (12 pages)" -ForegroundColor White
        Write-Host "  2  Last Apply report" -ForegroundColor White
        Write-Host "  3  Export HTML snapshot" -ForegroundColor White
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3")
        switch ($c) {
            "0" { return }
            "1" { Show-Help }
            "2" {
                Write-Host ""
                $i = Get-LastApplyInfo
                if ($i) {
                    Write-Host ("  When    : {0}" -f $i.Timestamp) -ForegroundColor White
                    Write-Host ("  Version : {0}" -f $i.ScriptVersion) -ForegroundColor White
                    Write-Host ("  Sections: {0}" -f ($i.SectionsRun -join ", ")) -ForegroundColor DarkGray
                    Write-Host ""
                    if ((Read-YesNo -Prompt "  Open JSON in Notepad (Y/N)?") -eq "Y") {
                        try { Start-Process notepad.exe $script:undoFile } catch {
                            Write-Host ("  Could not open Notepad: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
                        }
                    }
                } else {
                    Write-Host "  No Last Apply data yet. Run Apply first." -ForegroundColor Yellow
                }
                Wait-ForKey
            }
            "3" {
                Write-Host ""
                if (-not (Ensure-BastionPaths)) {
                    Write-Host "  Cannot create log directory." -ForegroundColor Red
                    Wait-ForKey
                    continue
                }
                $dir = $script:Config.LogDirectory
                $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
                $path = Join-Path $dir ("Bastion-Report-{0}.html" -f $stamp)
                $n = 0
                while (Test-Path -LiteralPath $path) {
                    $n++
                    $path = Join-Path $dir ("Bastion-Report-{0}-{1}.html" -f $stamp, $n)
                }
                $rows = ($script:Sections.Keys | ForEach-Object {
                    $state = if ($script:Sections[$_]) { "On" } else { "Off" }
                    "<li><b>$($_)</b> : $state</li>"
                }) -join "`n"
                $html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Bastion Report</title></head>
<body style="background:#0b1220;color:#eee;font-family:Segoe UI,sans-serif;padding:24px">
<h1>Bastion $($script:Config.ScriptVersion)</h1>
<p>Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
<h2>Sections</h2>
<ul>
$rows
</ul>
</body></html>
"@
                try {
                    $html | Out-File -FilePath $path -Encoding utf8 -ErrorAction Stop
                    Write-Host "  Export OK." -ForegroundColor Green
                    Write-Host ("  File: {0}" -f $path) -ForegroundColor Cyan
                } catch {
                    Write-Host ("  Export failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                    Write-Host ("  Next step: ensure you can write to {0}" -f $dir) -ForegroundColor Yellow
                }
                Wait-ForKey
            }
        }
    }
}


function Reset-ToDefaults {
    if (-not (Read-ConfirmYes -Prompt "  Type YES to reset Bastion config only (not Windows)")) { return }
    foreach ($k in @($script:DefaultSections.Keys)) {
        $script:Sections[$k] = [bool]$script:DefaultSections[$k]
    }
    $script:SelectedApps.Clear()
    $script:GlobalInstallRoot = $null
    $script:ProgramInstallRoots = @{}
    $script:BrowserPolicyMode = "Default"
    foreach ($k in @($script:BrowserPolicyModes.Keys)) { $script:BrowserPolicyModes[$k] = "Default" }
    foreach ($k in @($script:BrowserEchLocks.Keys)) { $script:BrowserEchLocks[$k] = $false }
    $script:BrowserPolicyLastChange = $null
    $script:DnsProviderId = "Quad9"
    Save-BastionConfig
    Save-BrowserPolicyStateFile
    Write-BastionSessionSnapshot
    Write-Host "  Bastion config reset. Windows hardening state unchanged." -ForegroundColor Green
    Write-Host "  Note: browser enterprise policies already on disk stay until you set that browser to Default in menu 6." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}

function Invoke-QuickHardening {
    Clear-BastionScreen
    Write-Header "QUICK HARDEN"
    Write-Host "  Safe preset (list below). BloatApps / Xbox stay off unless you enable them later." -ForegroundColor Cyan
    Write-Host ""
    foreach ($s in $script:QuickSections) { Write-Host ("  * {0}" -f $s) -ForegroundColor Green }
    Write-Host ""
    Write-Host "  Note: HighRiskServices can disable the Print Spooler (printing will stop)." -ForegroundColor Yellow
    Write-Host ""
    if ((Read-YesNo -Prompt "  Continue with this preset (Y/N)?") -ne "Y") { return }
    foreach ($k in @($script:Sections.Keys)) { $script:Sections[$k] = $false }
    foreach ($s in $script:QuickSections) {
        if ($script:Sections.Contains($s)) { $script:Sections[$s] = $true }
    }
    # Explicit Spooler choice for Quick Harden (common support issue)
    $script:SkipSpoolerThisApply = $false
    Write-Host ""
    Write-Host "  DNS: set a public recursive resolver, or leave adapter DNS unchanged." -ForegroundColor Cyan
    if ((Read-YesNo -Prompt "  Change DNS on eligible adapters during Quick Harden (Y/N)?") -eq "Y") {
        if ($script:DnsProviderId -eq "None" -or -not $script:DnsProviders.Contains($script:DnsProviderId)) {
            $script:DnsProviderId = "Quad9"
        }
        $script:Sections["DNS"] = $true
        Write-Host ""
        Write-Host "  Pick a resolver for this run:" -ForegroundColor Cyan
        $pickIds = @($script:DnsProviders.Keys | Where-Object { $_ -ne "None" })
        for ($i = 0; $i -lt $pickIds.Count; $i++) {
            $p = $script:DnsProviders[$pickIds[$i]]
            Write-Host ("    {0}. {1}  ({2})" -f ($i + 1), $p.DisplayName, $p.Primary) -ForegroundColor White
        }
        $validDns = 1..$pickIds.Count | ForEach-Object { "$_" }
        $dc = Read-MenuChoice -Prompt "  DNS choice" -Valid $validDns
        $didx = [int]$dc - 1
        if ($didx -ge 0 -and $didx -lt $pickIds.Count) {
            [void](Set-BastionDnsProviderId -Id $pickIds[$didx])
        }
        Write-Host ("  Will set DNS to: {0}" -f (Get-BastionDnsProviderLabel)) -ForegroundColor Green
    } else {
        $script:Sections["DNS"] = $false
        Write-Host "  DNS adapters will be left unchanged." -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "  Print Spooler: disabling is better for security (PrintNightmare surface)," -ForegroundColor Cyan
    Write-Host "  but you will not be able to print until it is re-enabled." -ForegroundColor Cyan
    if ((Read-YesNo -Prompt "  Keep Print Spooler ENABLED so this PC can print (Y/N)?") -eq "Y") {
        $script:SkipSpoolerThisApply = $true
        Write-Host "  Spooler will be left alone for this Quick Harden run." -ForegroundColor Green
    } else {
        Write-Host "  Spooler will be disabled with other high-risk services." -ForegroundColor Yellow
    }
    Save-BastionConfig

    if (-not (Confirm-RestorePointBeforeApply -ActionLabel "Quick Harden")) {
        $script:SkipSpoolerThisApply = $false
        Write-Host "  Quick Harden cancelled." -ForegroundColor Yellow
        Start-Sleep -Seconds 1
        return
    }
    if (-not (Read-ConfirmYes -Prompt "  Type YES to apply Quick Harden now")) {
        $script:SkipSpoolerThisApply = $false
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }
    try {
        Invoke-ApplyHardening -SkipRestorePrompt
    } finally {
        $script:SkipSpoolerThisApply = $false
    }
}

function Invoke-ApplyHardening {
    param([switch]$SkipRestorePrompt)

    $script:Stats = @{
        AlreadyConfigured = 0; Applied = 0; Failed = 0
        ProgramsInstalled = 0; ServicesDisabled = 0
    }
    $script:ApplyFailures = [System.Collections.Generic.List[string]]::new()
    $disabledServices = [System.Collections.Generic.List[object]]::new()
    $undoTrack = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
        ScriptVersion = $script:Config.ScriptVersion
        SectionsRun = @()
        DisabledServices = @()
        FirewallGroups = @()
        ProgramsInstalledList = @()
        BrowserPolicyMode = $script:BrowserPolicyMode
        BrowserPolicyModes = [ordered]@{}
        BrowserEchLocks = [ordered]@{}
        DnsProviderId = $script:DnsProviderId
    }
    foreach ($bk in $script:BrowserPolicyModes.Keys) {
        $undoTrack.BrowserPolicyModes[$bk] = [string]$script:BrowserPolicyModes[$bk]
    }
    foreach ($ek in $script:BrowserEchLocks.Keys) {
        $undoTrack.BrowserEchLocks[$ek] = [bool]$script:BrowserEchLocks[$ek]
    }

    Clear-BastionScreen
    Write-Header "APPLY HARDENING"
    foreach ($k in $script:Sections.Keys) {
        if ($script:Sections[$k]) { $undoTrack.SectionsRun += $k }
    }
    if ($undoTrack.SectionsRun.Count -eq 0) {
        Write-Host "  No sections enabled. Enable some under option 4." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }

    Show-ApplyPreview

    if (-not $SkipRestorePrompt) {
        if (-not (Confirm-RestorePointBeforeApply -ActionLabel "Apply")) {
            Write-Host "  Apply cancelled." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            return
        }
        if (-not (Read-ConfirmYes -Prompt "  Type YES to begin Apply")) {
            Write-Host "  Apply cancelled." -ForegroundColor Yellow
            return
        }
    }

    Clear-BastionScreen
    Write-Header "APPLYING"
    Write-Log "Apply start"

    if ($script:Sections["Firewall"]) {
        Write-Host "  [Firewall]" -ForegroundColor Cyan
        try {
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True `
                -DefaultInboundAction Block -DefaultOutboundAction Allow -Confirm:$false -ErrorAction Stop
            Write-Status "Profiles: Enabled, Inbound=Block, Outbound=Allow" "Applied"
        } catch {
            Write-Status ("Firewall profile failed: {0}. Next step: wf.msc" -f $_.Exception.Message) "Failed"
        }
        foreach ($g in $script:FirewallGroups) {
            try {
                $rules = @(Get-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.Direction -eq "Inbound" -and (
                            $_.Enabled -eq $true -or $_.Enabled -eq "True"
                        )
                    })
                if ($rules.Count -eq 0) {
                    Write-Status ("Already off / no enabled inbound rules: {0}" -f $g) "Already"
                } else {
                    foreach ($rule in $rules) {
                        try {
                            Set-NetFirewallRule -InputObject $rule -Enabled False -Confirm:$false -ErrorAction Stop
                        } catch {
                            Write-Status ("Rule fail in {0} : {1}" -f $g, $rule.DisplayName) "Warn"
                        }
                    }
                    Write-Status ("Disabled {0} inbound rule(s) in {1}" -f $rules.Count, $g) "Applied"
                    $undoTrack.FirewallGroups += $g
                }
            } catch {
                Write-Status ("Firewall group '{0}' error: {1}" -f $g, $_.Exception.Message) "Warn"
            }
        }
    }

    if ($script:Sections["HighRiskServices"]) {
        Write-Host "  [HighRiskServices]" -ForegroundColor Cyan
        foreach ($s in (Get-HighRiskServicesForApply)) {
            $entry = Disable-BastionService -Name $s
            if ($entry) { [void]$disabledServices.Add($entry) }
        }
    }

    if ($script:Sections["SMBv1"]) {
        Write-Host "  [SMBv1]" -ForegroundColor Cyan
        try {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
            if ($feat -and $feat.State -eq "Enabled") {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
                Write-Status "SMB1Protocol disabled (reboot may finish removal)" "Applied"
            } else {
                Write-Status "SMB1 already disabled or not present" "Already"
            }
        } catch {
            Write-Status ("SMB1 failed: {0}. Next step: OptionalFeatures.exe" -f $_.Exception.Message) "Failed"
        }
    }

    if ($script:Sections["OneDrive"]) {
        Write-Host "  [OneDrive]" -ForegroundColor Cyan
        Remove-BastionOneDrive
    }

    if ($script:Sections["XboxGaming"]) {
        Write-Host "  [XboxGaming]" -ForegroundColor Cyan
        foreach ($s in $script:XboxServiceList) {
            $entry = Disable-BastionService -Name $s
            if ($entry) { [void]$disabledServices.Add($entry) }
        }
    }

    if ($script:Sections["LSAProtection"]) {
        Write-Host "  [LSAProtection]" -ForegroundColor Cyan
        try {
            $current = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
            if ($current -eq 1) {
                Write-Status "RunAsPPL already 1" "Already"
            } else {
                New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                Write-Status "RunAsPPL enabled (reboot required to enforce)" "Applied"
            }
        } catch {
            Write-Status ("LSA failed: {0}" -f $_.Exception.Message) "Failed"
        }
    }

    if ($script:Sections["ScheduledTasks"]) {
        Write-Host "  [ScheduledTasks]" -ForegroundColor Cyan
        foreach ($t in @(
            "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
        )) {
            try {
                $task = Get-ScheduledTask -TaskPath (Split-Path $t -Parent) -TaskName (Split-Path $t -Leaf) -ErrorAction SilentlyContinue
                if (-not $task) {
                    Write-Status ("Absent {0}" -f (Split-Path $t -Leaf)) "Already"
                    continue
                }
                if ($task.State -eq "Disabled") {
                    Write-Status ("Already disabled {0}" -f $task.TaskName) "Already"
                } else {
                    Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
                    Write-Status ("Disabled {0}" -f $task.TaskName) "Applied"
                }
            } catch {
                Write-Status ("Task {0}: {1}" -f (Split-Path $t -Leaf), $_.Exception.Message) "Warn"
            }
        }
    }

    if ($script:Sections["DeliveryOptimization"]) {
        Write-Host "  [DeliveryOptimization]" -ForegroundColor Cyan
        try {
            $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
            if (-not (Test-Path $key)) { New-Item $key -Force | Out-Null }
            $cur = (Get-ItemProperty $key -Name DODownloadMode -ErrorAction SilentlyContinue).DODownloadMode
            if ($cur -eq 0) {
                Write-Status "Already HTTP only (0)" "Already"
            } else {
                New-ItemProperty $key -Name DODownloadMode -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                Write-Status "DODownloadMode=0 (HTTP only)" "Applied"
            }
        } catch {
            Write-Status ("Delivery Optimization failed: {0}" -f $_.Exception.Message) "Failed"
        }
    }

    if ($script:Sections["DNS"] -and $script:DnsProviderId -ne "None") {
        $prov = Get-BastionDnsProvider
        Write-Host ("  [DNS] {0}" -f $prov.DisplayName) -ForegroundColor Cyan
        if (-not $prov.Primary) {
            Write-Status "No DNS provider selected; leaving adapters unchanged" "Already"
        } else {
            $servers = @([string]$prov.Primary)
            if ($prov.Secondary) { $servers += [string]$prov.Secondary }
            $adapters = @(Get-BastionDnsAdapters)
            if ($adapters.Count -eq 0) {
                Write-Status "No eligible adapters found" "Warn"
            }
            foreach ($a in $adapters) {
                try {
                    if (Test-AdapterDnsMatchesProvider -InterfaceIndex $a.ifIndex) {
                        Write-Status ("{0} already {1}-first" -f $a.Name, $prov.DisplayName) "Already"
                    } else {
                        Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers -ErrorAction Stop
                        Write-Status ("{0} -> {1}" -f $prov.DisplayName, $a.Name) "Applied"
                    }
                } catch {
                    Write-Status ("DNS fail on {0}: {1}" -f $a.Name, $_.Exception.Message) "Failed"
                }
            }
        }
    }

    if ($script:Sections["Defender"]) {
        Write-Host "  [Defender]" -ForegroundColor Cyan
        try {
            Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
            Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
            Write-Status "Network Protection + CFA requested" "Applied"
            Add-CfaAllowPaths
        } catch {
            Write-Status ("Defender failed: {0}" -f $_.Exception.Message) "Failed"
        }
    }

    if ($script:Sections["PowerShellAuditing"]) {
        Write-Host "  [PowerShellAuditing]" -ForegroundColor Cyan
        try {
            $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            if (-not (Test-Path $path)) { New-Item $path -Force | Out-Null }
            Set-ItemProperty $path -Name EnableScriptBlockLogging -Value 1 -ErrorAction Stop
            Set-ItemProperty $path -Name EnableScriptBlockInvocationLogging -Value 1 -ErrorAction SilentlyContinue
            Write-Status "Script Block Logging enabled" "Applied"
        } catch {
            Write-Status ("PS auditing failed: {0}" -f $_.Exception.Message) "Failed"
        }
    }

    if ($script:Sections["ExploitProtection"]) {
        Write-Host "  [ExploitProtection]" -ForegroundColor Cyan
        try {
            $already = $false
            try {
                $mit = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
                $depOn = ($mit.DEP.Enable -eq "ON" -or "$($mit.DEP.Enable)" -eq "ON")
                if ($depOn) { $already = $true }
            } catch {}
            # StrictHandle intentionally omitted: system-wide strict handle checks break some game
            # loaders (e.g. WoW Wow_loader.dll -> INVALID_HANDLE / Eidolon). See GitHub issue #18.
            Set-ProcessMitigation -System -Enable DEP,SEHOP,BottomUp,HighEntropy -ErrorAction Stop
            # Best-effort: if a prior Bastion (or other tool) left StrictHandle on, turn it off so
            # re-Apply heals affected gaming PCs without a manual one-liner.
            try {
                Set-ProcessMitigation -System -Disable StrictHandle -ErrorAction SilentlyContinue
            } catch {}
            if ($already) {
                Write-Status "Mild system mitigations already present (re-applied; StrictHandle not enabled)" "Already"
            } else {
                Write-Status "Mild system mitigations applied (DEP/SEHOP/ASLR; StrictHandle off)" "Applied"
            }
        } catch {
            Write-Status ("Exploit Protection failed: {0}. Next step: Windows Security > App and browser control." -f $_.Exception.Message) "Failed"
        }
    }

    if ($script:Sections["BrowserPolicies"]) {
        Write-Host ("  [BrowserPolicies] {0}" -f (Get-BrowserPolicyModesSummary)) -ForegroundColor Cyan
        Write-Host "    Only installed browsers. Encrypted Client Hello (ECH) only if previously saved as Yes (never assumed)." -ForegroundColor Yellow
        Write-Host "    Prefer menu 6 for interactive control (Strict and ECH are separate choices)." -ForegroundColor DarkGray
        $browsers = @(Get-InstalledBastionBrowsers)
        if ($browsers.Count -eq 0) {
            Write-Status "No supported browsers installed; nothing to change" "Skip"
        } else {
            foreach ($b in $browsers) {
                $want = if ($script:BrowserPolicyModes.Contains($b.Name)) { $script:BrowserPolicyModes[$b.Name] } else { "Default" }
                # ECH: only explicit saved true + Strict. Never invent Yes from Strict alone.
                $ech = $false
                if ($want -eq "Strict" -and $script:BrowserEchLocks.Contains($b.Name) -and $script:BrowserEchLocks[$b.Name]) {
                    $ech = $true
                }
                Write-Host ("    {0}: mode={1} ECH pack={2} (live mode was {3})" -f $b.Name, $want, $(if ($ech) { "Yes" } else { "No" }), $b.Mode) -ForegroundColor DarkGray
                [void](Invoke-BastionBrowserPolicy -Browser $b.Key -Mode $want -EnableEch:$ech)
            }
        }
        Save-BrowserPolicyStateFile
    }

    if ($script:Sections["BloatApps"]) {
        Write-Host "  [BloatApps]" -ForegroundColor Cyan
        $targets = @(Get-BloatAppxStatus)
        if ($targets.Count -eq 0) {
            Write-Status "No curated bloat packages detected" "Already"
        }
        foreach ($app in $targets) {
            foreach ($pkg in @($app.UserPkgs)) {
                try {
                    Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
                    Write-Status ("Removed {0}" -f $pkg.Name) "Applied"
                } catch {
                    if ($_.Exception.Message -match 'cannot find the path|not found') {
                        Write-Status ("Already gone {0}" -f $pkg.Name) "Already"
                    } else {
                        try {
                            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                            Write-Status ("Removed (AllUsers) {0}" -f $pkg.Name) "Applied"
                        } catch {
                            Write-Status ("Fail {0}: {1}" -f $pkg.Name, $_.Exception.Message) "Failed"
                        }
                    }
                }
            }
            foreach ($prov in @($app.Provisioned)) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
                    Write-Status ("Provisioned removed {0}" -f $prov.DisplayName) "Applied"
                } catch {
                    if ($_.Exception.Message -match 'cannot find the path|not found') {
                        Write-Status ("Provisioned already gone {0}" -f $prov.DisplayName) "Already"
                    } else {
                        Write-Status ("Provisioned fail {0}" -f $prov.DisplayName) "Failed"
                    }
                }
            }
        }
    }

    if ($script:Sections["Suggestions"]) {
        Write-Host "  [Suggestions]" -ForegroundColor Cyan
        foreach ($item in $script:SuggestionRegistry) {
            $soft = $false
            if ($item.ContainsKey("Soft")) { $soft = [bool]$item.Soft }
            [void](Set-RegistryValueSafe -Path $item.Path -Name $item.Name -Value $item.Value -Type $item.Type -Desc $item.Desc -Soft:$soft)
        }
    }

    if ($script:Sections["CopilotM365"]) {
        try {
            Invoke-CopilotM365Hardening -IncludeProvisioned
        } catch {
            Write-Status ("CopilotM365 section failed: {0}" -f $_.Exception.Message) "Failed"
        }
    }

    if ($script:Sections["Programs"]) {
        Write-Host "  [Programs]" -ForegroundColor Cyan
        Sync-ProgramInstallQueue
        if ($script:SelectedApps.Count -eq 0) {
            Write-Status "No missing programs queued for install" "Skip"
        } else {
            $pre = Test-WingetSecurityPreflight
            if (-not $pre.Ok) {
                Write-Status ("All installs blocked: {0}" -f $pre.Detail) "Failed"
            } else {
                Write-Host ("    {0}" -f $pre.Detail) -ForegroundColor DarkGray
                foreach ($appName in @($script:SelectedApps)) {
                    if (-not $script:ProgramDefs.Contains($appName)) {
                        Write-Status ("Skipping non-catalog name: {0}" -f $appName) "Failed"
                        continue
                    }
                    $loc = $null
                    $root = Get-EffectiveInstallRoot -AppName $appName
                    if ($root) {
                        $vols = @(Get-AvailableInstallVolumes)
                        $check = Test-SafeInstallRoot -Path $root -AllowedVolumes $vols
                        if ($check.Ok) {
                            $loc = Join-Path $check.Path $appName
                            try {
                                if (-not (Test-Path -LiteralPath $check.Path)) {
                                    New-Item -ItemType Directory -Path $check.Path -Force -ErrorAction Stop | Out-Null
                                }
                            } catch {
                                Write-Status ("Could not create {0}; using default location" -f $check.Path) "Warn"
                                $loc = $null
                            }
                        }
                    }
                    if (Install-BastionCatalogApp -AppName $appName -LocationPath $loc) {
                        $undoTrack.ProgramsInstalledList += $appName
                    }
                }
                # Drop successfully installed names from the queue for next session.
                Sync-ProgramInstallQueue
            }
        }
    }

    $undoTrack.DisabledServices = @($disabledServices)
    Save-UndoData $undoTrack
    Save-BastionConfig

    Write-Host ""
    Write-Header "SUMMARY"
    Write-Host ("  Already {0} | Applied {1} | Failed {2} | Apps {3}" -f `
        $script:Stats.AlreadyConfigured, $script:Stats.Applied, $script:Stats.Failed, $script:Stats.ProgramsInstalled)
    if ($script:ApplyFailures.Count -gt 0) {
        Write-Host "  Failures:" -ForegroundColor Red
        foreach ($f in $script:ApplyFailures) { Write-Host ("    - {0}" -f $f) -ForegroundColor Red }
    }
    Write-Log ("Apply finished Applied={0} Failed={1}" -f $script:Stats.Applied, $script:Stats.Failed)
    Write-Host "  Reboot recommended if LSA or optional features changed." -ForegroundColor Yellow
    if ((Read-YesNo -Prompt "  Run security audit now (Y/N)?") -eq "Y") {
        Invoke-SelfTest
    } else {
        Wait-ForKey
    }
}

function Show-MainMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Banner
        Write-Host ("  Data directory: {0}" -f $script:Config.LogDirectory) -ForegroundColor DarkGray
        if ($script:FirstRunSeeded -and -not $script:HadPriorConfig) {
            Write-Host "  First run (or wiped store): defaults seeded. No prior Bastion config was found." -ForegroundColor Cyan
        } elseif ($script:ConfigLoaded) {
            Write-Host "  Config loaded from previous session." -ForegroundColor DarkGray
        } else {
            Write-Host "  Config: using in-memory defaults (file missing or unreadable)." -ForegroundColor Yellow
        }
        $last = Get-LastApplyInfo
        if ($last) {
            Write-Host ("  Last Bastion Apply: {0} (v{1})" -f $last.Timestamp, $last.ScriptVersion) -ForegroundColor DarkGray
        } else {
            Write-Host "  No Bastion Apply recorded yet (live OS detection still drives Dry Run / Apply)." -ForegroundColor DarkGray
        }
        Write-Host ("  Browser policies: {0}" -f (Get-BrowserPolicyModesSummary)) -ForegroundColor DarkGray
        Write-Host ("  DNS resolver:   {0}" -f (Get-BastionDnsProviderLabel)) -ForegroundColor DarkGray

        Write-MenuGroup "REVIEW"
        Write-Host "   1    Dry Run"
        Write-Host "   2    Security audit"
        Write-Host "   3    Hardware and driver guidance"

        Write-MenuGroup "CONFIGURE"
        Write-Host "   4    Hardening sections"
        Write-Host "   5    Programs and install paths"
        Write-Host "   6    Browser privacy policies"
        Write-Host "   D    DNS resolver (or leave unchanged)"

        Write-MenuGroup "EXECUTE"
        Write-Host "   7    Quick Harden" -ForegroundColor Green
        Write-Host "   8    Apply Hardening" -ForegroundColor Yellow

        Write-MenuGroup "MAINTAIN"
        Write-Host "   9    Recovery / fix"
        Write-Host "  10    Uninstall programs"

        Write-MenuGroup "SAFETY (do this first)"
        Write-Host "  13    Create / name a System Restore Point" -ForegroundColor Green
        Write-Host "   R    Same as 13 (shortcut)" -ForegroundColor Green

        Write-MenuGroup "SYSTEM"
        Write-Host "  11    Help and reports"
        Write-Host "  12    Reset Bastion config only"
        Write-Host "   0    Exit"
        Write-Host ""
        Write-Host "  --------------------------------------------------------------" -ForegroundColor DarkRed
        try {
            $rpStatus = Get-RestorePointStatus
        } catch {
            $rpStatus = [PSCustomObject]@{ Ok = $false; HasAny = $false; HasRecent = $false; RecentPoints = @() }
        }
        if ($rpStatus.Ok -and $rpStatus.HasRecent) {
            $top = $rpStatus.RecentPoints | Select-Object -First 1
            $when = if ($top -and $top.CreationTime) { $top.CreationTime.ToString("yyyy-MM-dd HH:mm") } else { "recent" }
            Write-Host ("  Restore status: recent point OK ({0})" -f $when) -ForegroundColor Green
            Write-Host "  Tip: still create a fresh point with 13 / R before major Apply runs." -ForegroundColor DarkGray
        } elseif ($rpStatus.Ok -and $rpStatus.HasAny) {
            Write-Host "  Restore status: points exist, but none in the last 48 hours." -ForegroundColor Yellow
            Write-Host "  Action: press 13 or R to create a named point before Apply / Quick Harden." -ForegroundColor Yellow
        } elseif ($rpStatus.Ok) {
            Write-Host "  Restore status: NONE found on this PC." -ForegroundColor Red
            Write-Host "  Action: press 13 or R BEFORE Apply, Quick Harden, or BloatApps." -ForegroundColor Red
        } else {
            Write-Host "  Restore status: could not query System Restore." -ForegroundColor Yellow
            Write-Host "  Check System Protection is on for the system drive (sysdm.cpl > System Protection)." -ForegroundColor Yellow
        }
        Write-Host "  Installs: catalog IDs only; winget hash enforced; no hash bypass." -ForegroundColor Yellow
        Write-Host "  GPU/BIOS: option 3 guidance only (no automated installs)." -ForegroundColor Yellow
        Write-Host "  --------------------------------------------------------------" -ForegroundColor DarkRed
        Write-Host ("  Programs queued to install: {0}" -f $(if ($script:SelectedApps.Count) { $script:SelectedApps -join ", " } else { "None" })) -ForegroundColor White
        Write-Host ""

        $choice = Read-MenuChoice -Prompt "  Select" -Valid @(
            "0","1","2","3","4","5","6","7","8","9","10","11","12","13","Q","q","A","a","H","h","R","r","D","d"
        )

        switch ($choice.ToUpper()) {
            "1" { Invoke-DryRun }
            "2" { Invoke-SelfTest }
            "3" { Show-HardwareDriverGuide }
            "4" { Show-SectionMenu }
            "5" { Show-ProgramMenu }
            "6" { Show-BrowserPolicyMenu }
            "D" { Show-DnsProviderMenu }
            "7" { Invoke-QuickHardening }
            "Q" { Invoke-QuickHardening }
            "8" { Invoke-ApplyHardening }
            "A" { Invoke-ApplyHardening }
            "9" { Show-RecoveryMenu }
            "10" { Show-UninstallMenu }
            "11" { Show-HelpReportsMenu }
            "H" { Show-HelpReportsMenu }
            "12" { Reset-ToDefaults }
            "13" { Show-RestorePointMenu }
            "R" { Show-RestorePointMenu }
            "0" {
                Write-Host ("  Exiting Bastion. Files under: {0}" -f $script:Config.LogDirectory) -ForegroundColor Cyan
                return
            }
        }
    }
}

try {
    if (-not (Ensure-BastionPaths)) {
        Write-Host ("Cannot initialize {0}. Exiting." -f $script:Config.LogDirectory) -ForegroundColor Red
        exit 1
    }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:Config.EventSource)) {
            New-EventLog -LogName Application -Source $script:Config.EventSource -ErrorAction SilentlyContinue
        }
    } catch {}
    # Maximize early so menus/help use full readable width (soft-fail if host disallows).
    Maximize-BastionConsole
    # Create/load durable store, seed defaults only when missing, rewrite live session snapshot.
    if (-not (Initialize-BastionDataStore)) {
        Write-Host ("Cannot prepare Bastion data store under {0}. Exiting." -f $script:Config.LogDirectory) -ForegroundColor Red
        exit 1
    }
    Write-Log ("Bastion v{0} FINAL started | data={1}" -f $script:Config.ScriptVersion, $script:Config.LogDirectory)
    Show-MainMenu
} catch {
    Write-Host ("FATAL: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Log ("FATAL: {0}" -f $_.Exception.Message) -Level Error
    Wait-ForKey "Press any key to exit..."
    exit 1
}
