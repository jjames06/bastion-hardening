# Bastion.Menus.ps1 - modular domain (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.

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

function Show-ProgramMenu {
    # Prune stale queue (e.g. apps installed outside Bastion since last session).
    Sync-ProgramInstallQueue
    while ($true) {
        # Re-detect installed/missing every paint so status stays accurate.
        $apps = @(Get-CatalogProgramRows)
        Clear-BastionScreen
        Write-Header "PROGRAMS AND INSTALL PATHS"
        Write-AppliesWhen -Mode MainMenu8 -Extra "Queue missing apps here. Installs run only when you Apply (main menu 8). Uninstall is menu 10 (runs now)."
        Write-Host "  [X] = queued to install (missing apps only). Installed apps stay [ ] here." -ForegroundColor DarkGray
        Write-Host "  No custom path => vendor defaults. L sets paths for the current queue only." -ForegroundColor DarkGray
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
        Write-Host "  N clear queue   L install locations   C save and back   0 back" -ForegroundColor Yellow
        Write-Host "  Tip: number keys toggle a missing app into the queue. Nothing installs until main menu 8." -ForegroundColor DarkGray
        $valid = @("N","L","C","0","n","l","c") + (1..$apps.Count | ForEach-Object { "$_" })
        $c = Read-MenuChoice -Prompt "  Select" -Valid $valid
        switch ($c.ToUpper()) {
            "0" {
                Sync-ProgramInstallQueue
                Save-BastionConfig
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
                Write-Host ("  Queue saved: {0}" -f $(if ($script:SelectedApps.Count) { $script:SelectedApps -join ", " } else { "(none)" })) -ForegroundColor Green
                Write-Host "  Installs still need main menu 8 (Apply Hardening)." -ForegroundColor Yellow
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
        Write-AppliesWhen -Mode MainMenu8 -Extra "Toggles here only choose what Apply will run. Windows is not hardened until you leave and press 8."
        Write-Host ""
        Write-Host "  [X] = included in next Apply   [ ] = skipped" -ForegroundColor DarkGray
        Write-Host ""
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
            } elseif ($n -eq "RdpHostLock") {
                $suffix = "  (opt-in: deny OS RDP host)"
            }
            Write-Host ("  {0,2}. {1}  {2}{3}" -f ($i + 1), $mark, $n, $suffix) `
                -ForegroundColor $(if ($script:Sections[$n]) { "Green" } else { "DarkGray" })
        }
        Write-Host ""
        Write-Host "  A all on   N all off   D DNS provider menu   C save and back   0 back" -ForegroundColor Yellow
        Write-Host "  Tip: number keys toggle one section. DNS provider is chosen under D (or main menu D)." -ForegroundColor DarkGray
        $valid = @("A","N","C","D","0","a","n","c","d") + (1..$names.Count | ForEach-Object { "$_" })
        $c = Read-MenuChoice -Prompt "  Select" -Valid $valid
        switch ($c.ToUpper()) {
            "0" { Save-BastionConfig; return }
            "A" {
                foreach ($k in $names) { $script:Sections[$k] = $true }
                if ($script:DnsProviderId -eq "None") { $script:DnsProviderId = "Quad9" }
                Save-BastionConfig
            }
            "N" {
                foreach ($k in $names) { $script:Sections[$k] = $false }
                Save-BastionConfig
            }
            "D" { Show-DnsProviderMenu; return }
            "C" {
                Save-BastionConfig
                Write-Host "  Sections saved. Run main menu 8 (Apply) when you want them on Windows." -ForegroundColor Yellow
                Start-Sleep -Milliseconds 1000
                return
            }
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
                        Save-BastionConfig
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
        Write-AppliesWhen -Mode PreferenceOrApply -Extra "VPN software may override DNS while a tunnel is connected."
        Write-Host ""
        Write-Host "  Status" -ForegroundColor Cyan
        Write-Host ("    Preferred provider:  {0}" -f (Get-BastionDnsProviderLabel)) -ForegroundColor White
        Write-Host ("    DNS section for Apply 8: {0}" -f $(if ($script:Sections["DNS"] -and $script:DnsProviderId -ne "None") { "ON" } else { "OFF (will not change DNS on full Apply)" })) -ForegroundColor DarkGray
        Write-Host "    Live Windows adapters right now:" -ForegroundColor Cyan
        foreach ($line in @(Get-BastionLiveDnsSummaryLines)) {
            Write-Host $line -ForegroundColor White
        }
        Write-Host ""
        Write-Host "  Pick a preferred provider (saves preference only)" -ForegroundColor Cyan
        Write-Host "  > marks the current preference" -ForegroundColor DarkGray
        Write-Host ""

        $ids = @($script:DnsProviders.Keys)
        for ($i = 0; $i -lt $ids.Count; $i++) {
            $id = $ids[$i]
            $p = $script:DnsProviders[$id]
            $mark = if ($script:DnsProviderId -eq $id -and ($id -eq "None" -or $script:Sections["DNS"])) { ">" } else { " " }
            if ($id -eq "None") {
                $mark = if (-not $script:Sections["DNS"] -or $script:DnsProviderId -eq "None") { ">" } else { " " }
                Write-Host ("  {0} {1,2}. {2}" -f $mark, ($i + 1), $p.DisplayName) -ForegroundColor $(if ($mark -eq ">") { "Green" } else { "White" })
                Write-Host ("         Leave Windows DNS as-is  |  {0}" -f $p.Notes) -ForegroundColor DarkGray
            } else {
                $wire = if ($p.WireDoH) { "DNS-over-HTTPS on Apply (Settings Encrypted)" } else { "classic DNS only" }
                Write-Host ("  {0} {1,2}. {2}" -f $mark, ($i + 1), $p.DisplayName) -ForegroundColor $(if ($mark -eq ">") { "Green" } else { "White" })
                Write-Host ("         {0} / {1}  |  {2}" -f $p.Primary, $p.Secondary, $wire) -ForegroundColor DarkGray
                if (-not [string]::IsNullOrWhiteSpace($p.Notes)) {
                    Write-Host ("         {0}" -f $p.Notes) -ForegroundColor DarkGray
                }
            }
            Write-Host ""
        }
        Write-Host "  Actions" -ForegroundColor Cyan
        Write-Host "  A  Apply preferred DNS to Windows NOW (snapshot + servers + DoH)" -ForegroundColor Yellow
        Write-Host "  0  Back (keep preference; Windows unchanged until you Apply)" -ForegroundColor White
        Write-Host ""
        Write-Host "  Tip: choosing 1-6 only saves. Press A here, or later main menu 8, to change adapters." -ForegroundColor DarkGray
        $valid = @("0", "A", "a") + (1..$ids.Count | ForEach-Object { "$_" })
        $c = Read-MenuChoice -Prompt "  Select" -Valid $valid
        if ($c -eq "0") {
            Save-BastionConfig
            Write-Host "  Preference saved. Windows DNS unchanged until A (this menu) or main menu 8." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 900
            return
        }
        if ($c.ToUpper() -eq "A") {
            Save-BastionConfig
            if (-not $script:Sections["DNS"] -or $script:DnsProviderId -eq "None") {
                Write-Host "  Choose a real provider first (numbers 1-5), not 'Do not change DNS'." -ForegroundColor Yellow
                Wait-ForKey
                continue
            }
            Write-Host ""
            Write-AppliesWhen -Mode Now -Extra "This is the same DNS work main menu 8 would do for the DNS section."
            [void](Invoke-BastionDnsSectionApply)
            Wait-ForKey
            continue
        }
        if ($c -match '^\d+$') {
            $idx = [int]$c - 1
            if ($idx -ge 0 -and $idx -lt $ids.Count) {
                [void](Set-BastionDnsProviderId -Id $ids[$idx])
                Save-BastionConfig
                Write-Host ""
                Write-Host ("  Saved preference: {0}" -f (Get-BastionDnsProviderLabel)) -ForegroundColor Green
                if ($script:DnsProviderId -eq "None" -or -not $script:Sections["DNS"]) {
                    Write-Host "  DNS section is off / leave-unchanged - full Apply (8) will not touch adapter DNS." -ForegroundColor Yellow
                } else {
                    Write-Host "  Windows adapters are still on the LIVE list above until you Apply." -ForegroundColor Yellow
                    Write-Host "  Next: press A here to apply now, or main menu 8 later." -ForegroundColor Yellow
                }
                Start-Sleep -Milliseconds 1400
            }
        }
    }
}

function Show-BrowserPolicyMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "BROWSER PRIVACY POLICIES"
        Write-AppliesWhen -Mode Now -Extra "Unlike sections/DNS, a confirmed mode is written immediately. You do not need main menu 8."
        Write-Host "  Only installed Firefox / Chrome / Brave are listed. ECH is never on unless you opt in under Strict." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Modes" -ForegroundColor White
        Write-UxBullets -Items @(
            "Default - remove Bastion policies for that browser (best-effort; backups kept)"
            "Medium  - privacy baseline (telemetry / tracking / cookies); usually fewer breakages"
            "Strict  - Medium + HTTPS-Only; does not enable ECH by itself"
        ) -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Encrypted Client Hello (ECH) pack" -ForegroundColor White
        Write-UxBullets -Items @(
            "Asked only after you pick Strict, as a separate Y/N (default path is No)"
            "Applies only to the browser(s) you selected on this screen"
            "Firefox: preference locks in policies.json"
            "Chrome/Brave: strongest transport policies Bastion can set (+ ECH marker)"
        ) -ForegroundColor DarkGray
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
            Write-Host "  Install Firefox, Chrome, or Brave from Programs (main menu 5), then Apply (8) if queued." -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  0 Back"
            $c = Read-MenuChoice -Prompt "  Select" -Valid @("0")
            return
        }

        Write-Host "  Installed browsers" -ForegroundColor Cyan
        for ($i = 0; $i -lt $browsers.Count; $i++) {
            $b = $browsers[$i]
            $echL = if ($b.EchLive) { "on" } else { "off" }
            $echS = if ($b.EchSaved) { "on" } else { "off" }
            Write-Host ("    {0}. {1,-10}  live={2,-8}  saved={3,-8}  ECH live={4} saved={5}" -f `
                ($i + 1), $b.Name, $b.Mode, $b.SavedMode, $echL, $echS) -ForegroundColor White
        }
        Write-Host ""
        Write-Host "  Next: pick a browser number (or A for all), then a mode. Policies write on confirm." -ForegroundColor DarkGray
        Write-Host "  A  Same mode for all listed browsers (one ECH Y/N if Strict)" -ForegroundColor Yellow
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
        Write-UxDivider
        Write-Host "  Policies were written NOW (no main menu 8 needed)." -ForegroundColor Green
        Write-Host "  Fully quit the browser (all windows), then reopen so policies load or drop." -ForegroundColor Yellow
        Write-Host "  Revert later: this menu > that browser > Default." -ForegroundColor DarkGray
        Wait-ForKey
    }
}

function Show-UninstallMenu {
    Clear-BastionScreen
    Write-Header "UNINSTALL"
    Write-AppliesWhen -Mode Now -Extra "Uninstall runs from this menu after YES confirm. It does not wait for main menu 8."
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

function Show-Help {
    # Display lines use a one-char type prefix so headings/body stay color-coded after wrap:
    # H=heading  L=label  S=section tag  B=body  U=url  E=empty  M=muted tip
    function Read-HelpNav {
        param([int]$Page, [int]$Total)
        while ($true) {
            try { $width = Get-BastionConsoleWidth } catch { $width = 78 }
            $rule = "-" * [Math]::Min(64, [Math]::Max(40, $width - 4))
            Write-Host ""
            Write-Host ("  " + $rule) -ForegroundColor DarkCyan
            Write-Host ("  Documentation  |  page {0} of {1}" -f $Page, $Total) -ForegroundColor DarkGray
            Write-Host "  Navigation (Help only - not the main menu):" -ForegroundColor Yellow
            Write-Host "    Enter   Next page" -ForegroundColor Green
            Write-Host "    B       Back to Help and Reports" -ForegroundColor Cyan
            Write-Host "    Q       Quit documentation" -ForegroundColor DarkYellow
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

    function Write-HelpDisplayLine {
        param([string]$Line)
        if ($null -eq $Line -or $Line -eq "" -or $Line -eq "E|") {
            Write-Host ""
            return
        }
        $type = "B"
        $text = $Line
        if ($Line.Length -ge 2 -and $Line[1] -eq [char]'|') {
            $type = $Line.Substring(0, 1)
            $text = $Line.Substring(2)
        }
        switch ($type) {
            "H" {
                # Section heading (from ## in help source)
                Write-Host ""
                Write-Host ("  {0}" -f $text) -ForegroundColor Yellow
            }
            "L" {
                # Field label: Why / Apply does / ...
                Write-Host ("  {0}" -f $text) -ForegroundColor Cyan
            }
            "S" {
                # Section name tag [Firewall]
                Write-Host ("  {0}" -f $text) -ForegroundColor Green
            }
            "U" {
                # URLs / paths
                Write-Host ("  {0}" -f $text) -ForegroundColor DarkCyan
            }
            "M" {
                # Muted tips / less important body
                Write-Host ("  {0}" -f $text) -ForegroundColor DarkGray
            }
            "B" {
                # Normal body
                Write-Host ("  {0}" -f $text) -ForegroundColor Gray
            }
            default {
                Write-Host ("  {0}" -f $text) -ForegroundColor Gray
            }
        }
    }

    function Show-LineChunks {
        param(
            [string]$Title,
            [string[]]$DisplayLines,
            [int]$Page,
            [int]$Total
        )
        $height = Get-BastionConsoleHeight
        $chunkSize = [Math]::Max(8, $height - 14)
        if ($null -eq $DisplayLines) { $DisplayLines = @() }
        if ($DisplayLines.Count -eq 0) { $DisplayLines = @("M|(No content)") }
        $offset = 0
        while ($offset -lt $DisplayLines.Count) {
            Clear-BastionScreen
            Write-Header $Title
            Write-Host ""
            $end = [Math]::Min($offset + $chunkSize - 1, $DisplayLines.Count - 1)
            for ($i = $offset; $i -le $end; $i++) {
                Write-HelpDisplayLine -Line $DisplayLines[$i]
            }
            $offset = $end + 1
            if ($offset -lt $DisplayLines.Count) {
                Write-Host ""
                Write-Host ("  --- more on this page ({0} lines left) ---" -f ($DisplayLines.Count - $offset)) -ForegroundColor DarkYellow
                try { [void](Read-Host "  Press Enter to continue this page") } catch {}
            }
        }
        Write-Host ""
        return (Read-HelpNav -Page $Page -Total $Total)
    }

    function Add-HelpWrapped {
        param(
            [System.Collections.Generic.List[string]]$List,
            [string]$Type,
            [string]$Text,
            [int]$Indent = 0
        )
        if ([string]::IsNullOrWhiteSpace($Text)) {
            [void]$List.Add("E|")
            return
        }
        $pad = ""
        if ($Indent -gt 0) { $pad = (" " * $Indent) }
        foreach ($wl in @(Get-WrappedLines -Text $Text -Indent 0)) {
            $body = $wl.TrimStart()
            if ([string]::IsNullOrWhiteSpace($body)) {
                [void]$List.Add("E|")
            } else {
                [void]$List.Add(("{0}|{1}{2}" -f $Type, $pad, $body))
            }
        }
    }

    function Show-HelpPage {
        param([string]$Title, [string[]]$Lines, [int]$Page, [int]$Total)
        $display = New-Object System.Collections.Generic.List[string]
        foreach ($line in $Lines) {
            if ($null -eq $line) { continue }
            if ($line -match '^\s*$') { [void]$display.Add("E|"); continue }
            if ($line -match '^\s*##\s+(.*)$') {
                [void]$display.Add("E|")
                Add-HelpWrapped -List $display -Type "H" -Text $Matches[1].Trim()
                continue
            }
            # Numbered workflow steps stay slightly brighter body (still Gray via B)
            $t = $line.TrimEnd()
            if ($t -match 'https?://') {
                Add-HelpWrapped -List $display -Type "U" -Text $t
            } elseif ($t -match '^\s*\d+[\.\)]\s') {
                Add-HelpWrapped -List $display -Type "B" -Text $t
            } else {
                Add-HelpWrapped -List $display -Type "B" -Text $t
            }
        }
        return (Show-LineChunks -Title $Title -DisplayLines @($display) -Page $Page -Total $Total)
    }

    function Show-HelpSectionDocs {
        param([string[]]$Keys, [string]$Title, [int]$Page, [int]$Total)
        $display = New-Object System.Collections.Generic.List[string]
        Add-HelpWrapped -List $display -Type "M" -Text "Each block explains why the section exists, what Apply does, what you may notice, and how to undo it."
        [void]$display.Add("E|")
        foreach ($key in $Keys) {
            if (-not $script:SectionDocs.Contains($key)) { continue }
            $d = $script:SectionDocs[$key]
            [void]$display.Add(("S|[{0}]" -f $key))
            foreach ($pair in @(
                @{ L = "Why"; B = $d.Intent },
                @{ L = "Apply does"; B = $d.Changes },
                @{ L = "You may notice"; B = $d.Impact },
                @{ L = "How to undo"; B = $d.Revert },
                @{ L = "Good to know"; B = $d.Notes }
            )) {
                [void]$display.Add(("L|{0}" -f $pair.L))
                Add-HelpWrapped -List $display -Type "B" -Text $pair.B -Indent 2
            }
            [void]$display.Add("E|")
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
        "Recovery hubs (Services, Network, Browsers, Apps/UI, Security mitigations) reverse most Bastion effects with live status - without bloating the main menu.",
        "Irreversible or hard-to-reverse items (BloatApps, OneDrive removal) stay off until you opt in and are called out explicitly.",
        "License: GNU GPLv3. Free to use and share; if you distribute a modified Bastion, you must keep it GPLv3 and provide source. See LICENSE and NOTICE beside the script.",
        "## Official site and downloads",
        "Product site (download, docs, support): https://www.operationlockedin.com",
        "Recommended download: https://www.operationlockedin.com/bastion/download (same GitHub Latest zip).",
        "Source and issues: https://github.com/jjames06/bastion-hardening"
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpPage -Title "HELP 2/13 - RECOMMENDED WORKFLOW" -Page 2 -Total $total -Lines @(
        "## First-time flow",
        "0. Prefer the official site download: https://www.operationlockedin.com/bastion/download (or GitHub Releases Latest).",
        "   First elevated launch (Bastion-Hardening.bat) creates a writable data directory and seeds Bastion-Config.json with defaults.",
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
        "Change one area at a time, Dry Run, Apply, verify. Use Recovery hubs for targeted reverse (Services, Network, Browsers, Apps/UI, Security mitigations) or Undo.",
        "If you delete the Bastion data folder, the next launch re-seeds defaults and re-detects the live system - it does not invent a prior Apply.",
        "## If something goes wrong",
        "Recovery hubs first. Browsers: menu 6 or Recovery > 4 > Default. Network/RDP/DNS: Recovery > 3. Games/StrictHandle: Recovery > 6 (disable system StrictHandle, reboot, report path on GitHub #18; other titles may lack exceptions). Deep failure: Safe Mode then System Restore."
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
        "9 Recovery - modular hubs: Undo, Services, Network, Browser policies, Apps and UI, Security mitigations (no main-menu bloat).",
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
        "7. Preflight and Audit do not print the full winget binary path (avoids echoing a user-profile path in logs and screenshots).",
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
        "## Recovery design (option 9) - modular, not bloated",
        "Main menu still has a single Recovery entry. Inside are six hubs with live status and targeted reverse. Prefer a hub over full Undo when you know what broke.",
        "## Recovery hubs",
        "1 Undo last hardening - services, firewall groups, encrypted DNS snapshot (when present), and RDP host prior (when RdpHostLock was applied). Partial by design.",
        "2 Services - Print Spooler, HighRiskServices stack (file share, UPnP, Remote Registry, ...), Xbox services. Enable one, all present, or re-disable Bastion-style.",
        "3 Network - Remote access (RDP/Assistance/WinRM + optional fDenyTSConnections/TermService), LAN/discovery, DNS reset to DHCP, restore prior DNS from last Apply snapshot (encrypted).",
        "4 Browser policies - same as main menu 6 for installed Firefox/Chrome/Brave. Default reverts that browser (best-effort).",
        "5 Apps and UI - Copilot/M365 tools, Widgets/Suggestions restore, Game Bar / ms-gamingoverlay silence or reverse.",
        "6 Security mitigations - StrictHandle (disable / refresh exceptions / re-enable), Defender NP/CFA, policies/tasks (DO, PowerShell logging, LSA, CEIP tasks).",
        "## Honesty rules shared by hubs",
        "Status is live from Windows. Enabling services or OPEN firewall groups increases attack surface; LOCKED/DISABLED is the safer default after harden.",
        "Firewall hubs only toggle named groups (not profile Inbound=Block). DNS: option 3 = DHCP; option 4 = restore snapshot when available. Menu D intent may re-apply on next DNS Apply. VPN may override DNS.",
        "RDP triad: firewall Remote Desktop group + system fDenyTSConnections + TermService. Optional section RdpHostLock denies the host switch on Apply (off by default). Windows Home may not host RDP like Pro.",
        "StrictHandle: World of Warcraft is one documented example (now auto-excepted). Other programs may break with no exception until reported and we ship one. Disable system StrictHandle + reboot, report, wait for update, then re-enable.",
        "Softening Defender reduces blocking strength. Appx bloat and OneDrive are not reinstallable here - System Restore or vendor installers.",
        "## System Restore",
        "Preferred full rollback. Create points from menu 13 or R. If Windows will not log on normally: hold Shift while selecting Restart, open Troubleshoot > Advanced > Startup Settings > Restart, then Safe Mode, then rstrui.exe.",
        "## Honest limits of Undo",
        "Undo does not reinstall Appx/OneDrive and does not clear browser enterprise policies (use Recovery > 4 Default). DNS snapshot restore is best-effort if adapters changed. DPAPI protects the snapshot for the elevating Windows user; a full compromise of that account can still decrypt. Hubs work even when Bastion-LastApply.json is missing."
    )
    if ($r -eq "back" -or $r -eq "quit") { return }

    $r = Show-HelpPage -Title "HELP 12/13 - FILES AND LOGS" -Page 12 -Total $total -Lines @(
        ("## Directory (this session): {0}" -f $script:Config.LogDirectory),
        "Created automatically on first elevated launch. Prefer durable paths over wipeable temp.",
        "Resolve order for existing state: C:\Temp\Bastion, legacy C:\Temp, %ProgramData%\Bastion, %LOCALAPPDATA%\Bastion, then %TEMP%\Bastion (last).",
        "New installs prefer C:\Temp\Bastion, then ProgramData, then LocalAppData, then legacy flat C:\Temp. %TEMP%\Bastion is last-resort only.",
        "Bastion-Config.json - section toggles, selected apps, install roots, per-browser wanted modes and ECH Yes/No flags, DNS provider, optional WowInstallRoots and StrictHandleExceptionPaths for custom game paths (seeded on first run; ECH defaults off).",
        "Bastion-Session.json - rewritten every launch: live browser posture vs wanted modes; proves the store is real. Not Apply history.",
        "Bastion-BrowserPolicies-State.json - wanted + live browser modes, ECH live/wanted, last policy change summary.",
        "browser-policy-backups/ - snapshots taken before Bastion overwrites browser policies (menu 6).",
        "Bastion-LastApply.json - only after a real Apply: timestamp, sections run, tracked undo (services, firewall groups). DNS snapshot and RDP host prior are DPAPI-encrypted (DnsSnapshotProtected / RdpHostPriorProtected), not plaintext. File ACL: SYSTEM + Administrators when Bastion can set it. Missing file = no Bastion Apply undo yet.",
        "DPAPI honesty: blobs use Windows DPAPI CurrentUser for the account that elevates Bastion, plus optional Bastion entropy. Bastion can decrypt on the same user session. A full compromise of that Windows account can still decrypt. A different user or offline copy of the file alone is not enough. This is not a password vault.",
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
        "VPN DNS while connected may differ from the chosen public resolver. That is normal.",
        "Browser Strict and optional Encrypted Client Hello (ECH) can break some sites; ECH is never applied unless you choose Yes.",
        "Some HKLM suggestion policies may be denied even when elevated (Soft skip). Some installers ignore custom --location.",
        "## Games / StrictHandle (honest summary)",
        "ExploitProtection turns system StrictHandle ON. That hardens most apps. Some programs can fail to start until they have a per-app exception.",
        "World of Warcraft is a documented example that broke under system StrictHandle; Bastion now auto-excepts discovered Wow*.exe. CS2 was tested OK.",
        "Other games or programs may still break. No exception in Bastion means you may need to reverse until we add one after a report.",
        "If something breaks: Recovery > 6 > StrictHandle > disable system StrictHandle, reboot, confirm it works. Or add the full .exe path under StrictHandleExceptionPaths in Bastion-Config.json and refresh exceptions.",
        "Then report name + full .exe path on GitHub issue #18 or Discussions #23. Wait for a Bastion update that includes the exception, then re-Apply or Recovery > 6 option 3 to restore system StrictHandle with exceptions.",
        "Details: docs/KNOWN-ISSUES.md. Prefer Recovery over guessing raw PowerShell.",
        "## License (GPLv3)",
        "Bastion is free software under the GNU General Public License v3.0. You may run and modify it.",
        "If you distribute a modified version, you must license that distribution under GPLv3 and provide the complete corresponding source. That blocks closed proprietary forks of Bastion.",
        "GPLv3 does not ban selling GPL-compliant copies that include source; it bans keeping distributed modifications secret and proprietary. See LICENSE and NOTICE.",
        "Older published release zips that still contain an MIT LICENSE file remain under those artifact terms.",
        "## Deliberate non-goals",
        "No aggressive mitigation sets that caused black-screen logons on some hardware. No automatic GPU/BIOS flashing. Not a complete malware guarantee.",
        "## Version",
        ("Bastion v{0}. Measure with Dry Run, protect with a restore point, then Apply." -f $script:Config.ScriptVersion)
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
        Write-Host "  Choose a topic" -ForegroundColor Yellow
        Write-Host "  1  Full documentation (13 pages)" -ForegroundColor Cyan
        Write-Host "  2  Last Apply report" -ForegroundColor Cyan
        Write-Host "  3  Export HTML snapshot" -ForegroundColor Cyan
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
            $snapNote = if ($last.HasDnsSnapshot) { "; encrypted DNS snapshot available" } else { "" }
            $rdpNote = if ($last.RdpHostLocked) { "; RDP host prior saved" } else { "" }
            Write-Host ("  Last Bastion Apply: {0} (v{1}){2}{3}" -f $last.Timestamp, $last.ScriptVersion, $snapNote, $rdpNote) -ForegroundColor DarkGray
        } else {
            Write-Host "  No Bastion Apply recorded yet (live OS detection still drives Dry Run / Apply)." -ForegroundColor DarkGray
        }
        Write-Host ("  Browser policies: {0}" -f (Get-BrowserPolicyModesSummary)) -ForegroundColor DarkGray
        Write-Host ("  DNS resolver:   {0}" -f (Get-BastionDnsProviderLabel)) -ForegroundColor DarkGray

        Write-MenuGroup "REVIEW (no changes)"
        Write-Host "   1    Dry Run (preview only)"
        Write-Host "   2    Security audit"
        Write-Host "   3    Hardware and driver guidance"

        Write-MenuGroup "CONFIGURE (save choices; Windows not changed yet)"
        Write-Host "   4    Hardening sections"
        Write-Host "   5    Programs and install paths"
        Write-Host "   6    Browser privacy policies (applies NOW to chosen browsers)"
        Write-Host "   D    DNS resolver (preference; Apply via A inside D, or 8)"

        Write-MenuGroup "EXECUTE (makes system changes)"
        Write-Host "   7    Quick Harden (guided preset + Apply)" -ForegroundColor Green
        Write-Host "   8    Apply Hardening (run enabled sections + install queue)" -ForegroundColor Yellow

        Write-MenuGroup "MAINTAIN (actions run NOW)"
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
        Write-Host "  Flow: configure (4/5/D) -> Dry Run (1) optional -> restore point (13) -> Apply (8)." -ForegroundColor Yellow
        Write-Host "  Exception: menu 6 browser policies apply as soon as you confirm a mode." -ForegroundColor Yellow
        Write-Host "  Installs: catalog IDs only; winget hash enforced. GPU/BIOS: option 3 is guidance only." -ForegroundColor DarkGray
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
