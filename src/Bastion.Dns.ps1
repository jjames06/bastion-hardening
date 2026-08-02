# Bastion.Dns.ps1 - modular domain (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.

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

function Format-BastionInterfaceGuid {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $g = $Raw.Trim()
    if ($g -notmatch '^\{') { $g = "{$g}" }
    if ($g -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') { return $null }
    # Windows stores InterfaceSpecificParameters GUIDs lowercase; normalize for stable paths.
    return $g.ToLowerInvariant()
}

function Get-BastionDnsKnownDohTemplate {
    param([Parameter(Mandatory)][string]$Server)
    $ip = $Server.Trim()
    if ($script:DnsKnownDohTemplates.Contains($ip)) {
        return [string]$script:DnsKnownDohTemplates[$ip]
    }
    try {
        $row = Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue
        if ($row -and $row.DohTemplate) { return [string]$row.DohTemplate }
    } catch {}
    return $null
}

function Get-BastionInterfaceDohEntries {
    param([string]$InterfaceGuid)
    $out = @()
    $guid = Format-BastionInterfaceGuid -Raw $InterfaceGuid
    if (-not $guid) { return @($out) }
    $base = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings\Doh"
    if (-not (Test-Path -LiteralPath $base)) { return @($out) }
    foreach ($child in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
        try {
            $p = Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction Stop
            $tpl = ""
            $flags = 0
            try { $tpl = [string]$p.DohTemplate } catch {}
            try { $flags = [int]$p.DohFlags } catch { $flags = 0 }
            $out += [ordered]@{
                Server      = [string]$child.PSChildName
                DohTemplate = $tpl
                DohFlags    = $flags
            }
        } catch {}
    }
    return @($out)
}

function Clear-BastionInterfaceDohEntries {
    param([string]$InterfaceGuid)
    $guid = Format-BastionInterfaceGuid -Raw $InterfaceGuid
    if (-not $guid) { return }
    $base = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings\Doh"
    if (-not (Test-Path -LiteralPath $base)) { return }
    foreach ($child in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
        try { Remove-Item -LiteralPath $child.PSPath -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
}

function Set-BastionInterfaceDohEntry {
    param(
        [Parameter(Mandatory)][string]$InterfaceGuid,
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$DohTemplate,
        [int]$DohFlags = $script:BastionDnsDohInterfaceFlags
    )
    $guid = Format-BastionInterfaceGuid -Raw $InterfaceGuid
    $ip = $Server.Trim()
    if (-not $guid -or [string]::IsNullOrWhiteSpace($ip) -or [string]::IsNullOrWhiteSpace($DohTemplate)) { return $false }
    $ok = $false
    try {
        # 1) Global DoH list via DnsClient module (known server + auto-upgrade, no UDP fallback).
        #    Mirrors Settings: DNS over HTTPS On (automatic template), Fallback to plaintext Off.
        try {
            $exist = Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue
            if (-not $exist) {
                Add-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $DohTemplate `
                    -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop | Out-Null
            } else {
                Set-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $DohTemplate `
                    -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue | Out-Null
            }
            $ok = $true
        } catch {
            Write-Log ("DoH module register {0}: {1}" -f $ip, $_.Exception.Message) -Level Warning
        }
        # 2) netsh encryption table (autoupgrade = use DoH when this server is configured).
        try {
            $null = & netsh.exe dns set encryption "server=$ip" "dohtemplate=$DohTemplate" autoupgrade=yes udpfallback=no 2>&1
            if ($LASTEXITCODE -ne 0) {
                $null = & netsh.exe dns add encryption "server=$ip" "dohtemplate=$DohTemplate" autoupgrade=yes udpfallback=no 2>&1
            }
            if ($LASTEXITCODE -eq 0) { $ok = $true }
        } catch {
            Write-Log ("DoH netsh {0}: {1}" -f $ip, $_.Exception.Message) -Level Warning
        }
        # 3) Per-interface DoH keys - required for Settings "Encrypted" badge (same path Edit DNS saves).
        #    Windows writes DohFlags as REG_QWORD (not DWORD). Value 17 = On automatic template, no plaintext fallback.
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings\Doh\$ip"
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        }
        # Drop wrong property kinds so QWord/String land cleanly (legacy Bastion wrote DWORD 5).
        try {
            $item = Get-Item -LiteralPath $path -ErrorAction Stop
            try {
                if ($item.GetValueKind("DohFlags") -ne [Microsoft.Win32.RegistryValueKind]::QWord) {
                    Remove-ItemProperty -LiteralPath $path -Name DohFlags -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        } catch {}
        New-ItemProperty -LiteralPath $path -Name DohTemplate -PropertyType String -Value $DohTemplate -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -LiteralPath $path -Name DohFlags -PropertyType QWord -Value ([uint64]$DohFlags) -Force -ErrorAction Stop | Out-Null
        $ok = $true
        return $ok
    } catch {
        Write-Log ("DoH interface set {0}/{1}: {2}" -f $guid, $ip, $_.Exception.Message) -Level Warning
        return $false
    }
}

function Enable-BastionDnsOverHttpsForAdapter {
    param(
        [string]$InterfaceGuid,
        [string[]]$Servers,
        [object[]]$DohEntries = @()
    )
    $guid = Format-BastionInterfaceGuid -Raw $InterfaceGuid
    if (-not $guid) { return 0 }
    $n = 0
    $want = @{}
    # Prefer explicit snapshot entries (prior encryption state).
    foreach ($e in @($DohEntries)) {
        try {
            $srv = [string]$e.Server
            $tpl = [string]$e.DohTemplate
            if ([string]::IsNullOrWhiteSpace($srv) -or [string]::IsNullOrWhiteSpace($tpl)) { continue }
            $flags = $script:BastionDnsDohInterfaceFlags
            try { if ($null -ne $e.DohFlags -and [int]$e.DohFlags -gt 0) { $flags = [int]$e.DohFlags } } catch {}
            if (Set-BastionInterfaceDohEntry -InterfaceGuid $guid -Server $srv -DohTemplate $tpl -DohFlags $flags) {
                $want[$srv] = $true
                $n++
            }
        } catch {}
    }
    # Fill known templates for active servers not already covered.
    foreach ($s in @($Servers)) {
        $ip = [string]$s
        if ([string]::IsNullOrWhiteSpace($ip) -or $want.ContainsKey($ip)) { continue }
        $tpl = Get-BastionDnsKnownDohTemplate -Server $ip
        if (-not $tpl) { continue }
        if (Set-BastionInterfaceDohEntry -InterfaceGuid $guid -Server $ip -DohTemplate $tpl) {
            $want[$ip] = $true
            $n++
        }
    }
    # Drop interface DoH keys for servers no longer configured on this adapter.
    $base = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings\Doh"
    if (Test-Path -LiteralPath $base) {
        foreach ($child in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $ip = [string]$child.PSChildName
            if (-not $want.ContainsKey($ip) -and ($Servers -notcontains $ip)) {
                try { Remove-Item -LiteralPath $child.PSPath -Recurse -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
    }
    return $n
}

function Get-BastionDnsSnapshot {
    $adapters = @()
    foreach ($a in @(Get-BastionDnsAdapters)) {
        try {
            $servers = @(Get-AdapterDnsServers -InterfaceIndex $a.ifIndex)
            $guid = ""
            try { $guid = [string]$a.InterfaceGuid } catch { $guid = "" }
            $doh = @(Get-BastionInterfaceDohEntries -InterfaceGuid $guid)
            # If registry has no per-interface DoH yet, still record known templates for current servers
            # so a later restore can re-enable Encrypted mode after a plain Set-DnsClientServerAddress.
            if ($doh.Count -eq 0 -and $servers.Count -gt 0) {
                foreach ($s in $servers) {
                    $tpl = Get-BastionDnsKnownDohTemplate -Server ([string]$s)
                    if ($tpl) {
                        $doh += [ordered]@{
                            Server      = [string]$s
                            DohTemplate = $tpl
                            DohFlags    = $script:BastionDnsDohInterfaceFlags
                            Inferred    = $true
                        }
                    }
                }
            }
            $adapters += [ordered]@{
                Name           = [string]$a.Name
                InterfaceIndex = [int]$a.ifIndex
                InterfaceGuid  = $guid
                Servers        = @($servers | ForEach-Object { [string]$_ })
                WasEmpty       = ($servers.Count -eq 0)
                DohEntries     = @($doh)
            }
        } catch {}
    }
    return [ordered]@{
        CapturedAt = (Get-Date -Format "o")
        Version    = 2
        Adapters   = $adapters
    }
}

function Restore-BastionDnsFromSnapshot {
    param($Snapshot)
    if ($null -eq $Snapshot) {
        Write-Status "No DNS snapshot available to restore" "Warn"
        return $false
    }
    $list = @()
    try {
        if ($Snapshot.Adapters) { $list = @($Snapshot.Adapters) }
    } catch {}
    if ($list.Count -eq 0) {
        Write-Status "DNS snapshot is empty" "Warn"
        return $false
    }
    $now = @(Get-BastionDnsAdapters)
    $n = 0
    foreach ($row in $list) {
        $name = [string]$row.Name
        $guid = [string]$row.InterfaceGuid
        $match = $null
        if ($guid) {
            $match = $now | Where-Object { [string]$_.InterfaceGuid -eq $guid } | Select-Object -First 1
        }
        if (-not $match -and $name) {
            $match = $now | Where-Object { [string]$_.Name -eq $name } | Select-Object -First 1
        }
        if (-not $match) {
            Write-Status ("DNS restore skipped (adapter not found): {0}" -f $name) "Warn"
            continue
        }
        try {
            $servers = @()
            try {
                if ($null -eq $row.Servers) { $servers = @() }
                elseif ($row.Servers -is [string]) { $servers = @([string]$row.Servers) }
                else { $servers = @($row.Servers | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
            } catch { $servers = @() }
            $wasEmpty = $false
            try { $wasEmpty = [bool]$row.WasEmpty } catch {}
            $dohEntries = @()
            try {
                if ($row.DohEntries) { $dohEntries = @($row.DohEntries) }
            } catch { $dohEntries = @() }
            $matchGuid = ""
            try { $matchGuid = [string]$match.InterfaceGuid } catch { $matchGuid = $guid }
            if ($wasEmpty -or $servers.Count -eq 0) {
                Set-DnsClientServerAddress -InterfaceIndex $match.ifIndex -ResetServerAddresses -ErrorAction Stop
                Clear-BastionInterfaceDohEntries -InterfaceGuid $matchGuid
                Write-Status ("{0}: prior DNS was automatic/empty; reset to DHCP" -f $match.Name) "Applied"
            } else {
                Set-DnsClientServerAddress -InterfaceIndex $match.ifIndex -ServerAddresses $servers -ErrorAction Stop
                $dohN = Enable-BastionDnsOverHttpsForAdapter -InterfaceGuid $matchGuid -Servers $servers -DohEntries $dohEntries
                if ($dohN -gt 0) {
                    Write-Status ("{0}: restored prior DNS ({1}) + DNS-over-HTTPS for {2} server(s)" -f $match.Name, ($servers -join ", "), $dohN) "Applied"
                } else {
                    Write-Status ("{0}: restored prior DNS ({1}) (classic only; no DoH template)" -f $match.Name, ($servers -join ", ")) "Applied"
                }
            }
            $n++
        } catch {
            Write-Status ("DNS restore failed on {0}: {1}" -f $match.Name, $_.Exception.Message) "Failed"
        }
    }
    try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
    Write-UxDivider
    Write-Host "  Restore finished (this menu already applied it - no main menu 8)." -ForegroundColor Green
    Write-Host "  Menu D preference was not changed. VPN may still override DNS while connected." -ForegroundColor DarkGray
    Write-Host "  Settings Encrypted = DNS-over-HTTPS on the wire (re-open Settings if the badge was already open)." -ForegroundColor DarkGray
    if ($n -eq 0) {
        Write-Host "  No adapters were restored (renamed/removed since snapshot, or snapshot empty)." -ForegroundColor Yellow
    }
    Write-Log ("Restore-BastionDnsFromSnapshot restored={0}" -f $n) -NoConsole
    return ($n -gt 0)
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

function Get-BastionLiveDnsSummaryLines {
    $lines = [System.Collections.Generic.List[string]]::new()
    $adapters = @(Get-BastionDnsAdapters)
    if ($adapters.Count -eq 0) {
        [void]$lines.Add("  Live adapters: (none eligible)")
        return @($lines)
    }
    foreach ($a in $adapters) {
        $dns = @(Get-AdapterDnsServers -InterfaceIndex $a.ifIndex)
        $s = if ($dns.Count) { $dns -join ", " } else { "(automatic/DHCP or empty)" }
        [void]$lines.Add(("  Live {0}: {1}" -f $a.Name, $s))
    }
    return @($lines)
}

function Invoke-BastionDnsSectionApply {
    <#
      Applies menu D provider to eligible adapters (IPs + DoH).
      Writes Bastion-LastApply.json undo with DNS snapshot when changes are needed.
      Returns $true if at least one adapter was touched successfully.
    #>
    param([switch]$SkipRestorePrompt)
    $prov = Get-BastionDnsProvider
    if (-not $prov -or -not $prov.Primary -or $script:DnsProviderId -eq "None" -or -not $script:Sections["DNS"]) {
        Write-Status "DNS section off or no provider selected; nothing to apply" "Warn"
        return $false
    }
    $servers = @([string]$prov.Primary)
    if ($prov.Secondary) { $servers += [string]$prov.Secondary }
    $adapters = @(Get-BastionDnsAdapters)
    if ($adapters.Count -eq 0) {
        Write-Status "No eligible adapters found" "Warn"
        return $false
    }

    if (-not $SkipRestorePrompt) {
        if (-not (Confirm-RestorePointBeforeApply -ActionLabel "DNS Apply")) {
            Write-Host "  DNS Apply cancelled." -ForegroundColor Yellow
            return $false
        }
        if (-not (Read-ConfirmYes -Prompt "  Type YES to set adapter DNS to the selected provider now")) {
            Write-Host "  Cancelled." -ForegroundColor Yellow
            return $false
        }
    }

    $undoTrack = @{
        Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm"
        ScriptVersion   = $script:Config.ScriptVersion
        SectionsRun     = @("DNS")
        DisabledServices = @()
        FirewallGroups  = @()
        ProgramsInstalledList = @()
        BrowserPolicyMode = $script:BrowserPolicyMode
        BrowserPolicyModes = [ordered]@{}
        BrowserEchLocks = [ordered]@{}
        DnsProviderId   = $script:DnsProviderId
        HasDnsSnapshot  = $false
        RdpHostLocked   = $false
        RdpHostPrior    = $null
    }
    foreach ($bk in $script:BrowserPolicyModes.Keys) {
        $undoTrack.BrowserPolicyModes[$bk] = [string]$script:BrowserPolicyModes[$bk]
    }
    foreach ($ek in $script:BrowserEchLocks.Keys) {
        $undoTrack.BrowserEchLocks[$ek] = [bool]$script:BrowserEchLocks[$ek]
    }

    Write-Host ("  [DNS] Applying {0} ..." -f $prov.DisplayName) -ForegroundColor Cyan
    $needSnap = $false
    foreach ($a in $adapters) {
        try {
            if (-not (Test-AdapterDnsMatchesProvider -InterfaceIndex $a.ifIndex)) { $needSnap = $true; break }
        } catch { $needSnap = $true; break }
    }
    if ($needSnap) {
        $undoTrack.DnsSnapshot = Get-BastionDnsSnapshot
        Write-Status ("Captured DNS snapshot for {0} eligible adapter(s) (stored DPAPI-encrypted on save)" -f @($undoTrack.DnsSnapshot.Adapters).Count) "Applied"
    }

    $changed = 0
    foreach ($a in $adapters) {
        try {
            $guid = ""
            try { $guid = [string]$a.InterfaceGuid } catch {}
            if (Test-AdapterDnsMatchesProvider -InterfaceIndex $a.ifIndex) {
                $dohN = Enable-BastionDnsOverHttpsForAdapter -InterfaceGuid $guid -Servers $servers
                if ($dohN -gt 0) {
                    Write-Status ("{0} already {1}-first; DoH re-confirmed" -f $a.Name, $prov.DisplayName) "Already"
                } else {
                    Write-Status ("{0} already {1}-first" -f $a.Name, $prov.DisplayName) "Already"
                }
            } else {
                Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers -ErrorAction Stop
                $dohN = Enable-BastionDnsOverHttpsForAdapter -InterfaceGuid $guid -Servers $servers
                if ($dohN -gt 0) {
                    Write-Status ("{0} -> {1} (IPs set; DoH enabled for {2} server(s))" -f $a.Name, $prov.DisplayName, $dohN) "Applied"
                } else {
                    Write-Status ("{0} -> {1} (IPs set; classic DNS only)" -f $a.Name, $prov.DisplayName) "Applied"
                }
                $changed++
            }
        } catch {
            Write-Status ("DNS fail on {0}: {1}" -f $a.Name, $_.Exception.Message) "Failed"
        }
    }
    try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
    if ($needSnap -or $changed -gt 0) {
        # Preserve non-DNS undo from last Apply when present (merge DNS snapshot into last file).
        $prior = Read-BastionUndoData
        if ($prior) {
            try {
                if ($prior.DisabledServices) { $undoTrack.DisabledServices = @($prior.DisabledServices) }
                if ($prior.FirewallGroups) { $undoTrack.FirewallGroups = @($prior.FirewallGroups) }
                if ($prior.RdpHostLocked) {
                    $undoTrack.RdpHostLocked = $true
                    if ($prior.RdpHostPriorProtected) {
                        $undoTrack.RdpHostPriorProtected = $prior.RdpHostPriorProtected
                    } elseif ($prior.RdpHostPrior) {
                        $undoTrack.RdpHostPrior = $prior.RdpHostPrior
                    }
                }
                if ($prior.SectionsRun) {
                    $sr = [System.Collections.Generic.List[string]]::new()
                    foreach ($s in @($prior.SectionsRun)) { if ($s -and -not $sr.Contains([string]$s)) { [void]$sr.Add([string]$s) } }
                    if (-not $sr.Contains("DNS")) { [void]$sr.Add("DNS") }
                    $undoTrack.SectionsRun = @($sr)
                }
            } catch {}
        }
        Save-UndoData $undoTrack
    }
    Write-UxDivider
    Write-Host "  DNS Apply finished (this run already changed Windows - no extra main menu 8 for DNS)." -ForegroundColor Green
    Write-Host "  Preference and live adapters should match above (VPN may still override while connected)." -ForegroundColor DarkGray
    Write-Host "  Settings Encrypted = DoH on the wire. Re-open Settings if that page was already open." -ForegroundColor DarkGray
    return ($changed -gt 0 -or -not $needSnap)
}

function Reset-BastionDnsToAutomatic {
    $adapters = @(Get-BastionDnsAdapters)
    if ($adapters.Count -eq 0) {
        Write-Status "No eligible adapters found for DNS reset" "Warn"
        return $false
    }
    $n = 0
    foreach ($a in $adapters) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction Stop
            try { Clear-BastionInterfaceDohEntries -InterfaceGuid ([string]$a.InterfaceGuid) } catch {}
            Write-Status ("{0}: DNS reset to automatic (DHCP/system)" -f $a.Name) "Applied"
            $n++
        } catch {
            Write-Status ("DNS reset failed on {0}: {1}" -f $a.Name, $_.Exception.Message) "Failed"
        }
    }
    try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
    Write-UxDivider
    Write-Host "  DHCP reset done (this menu already applied it - no main menu 8)." -ForegroundColor Green
    Write-Host "  Menu D preference was not changed. VPN may still override DNS while connected." -ForegroundColor DarkGray
    Write-Log ("Reset-BastionDnsToAutomatic adapters={0}" -f $n) -NoConsole
    return ($n -gt 0)
}
