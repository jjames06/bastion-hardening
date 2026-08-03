# Bastion.Dns.ps1 - modular domain (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.
#
# Role in modular architecture:
#   Eligible-adapter DNS preference (menu D), IPv4 server assignment, DNS-over-HTTPS
#   (DoH) registration, prior-DNS snapshot/restore, and dedicated DNS Apply without
#   requiring full main-menu Apply for every DNS change.
#
# Load-order position: 7 of 11 (after Browsers, before Harden).
#   Order: Init, Core, Config, Programs, Services, Browsers, Dns, Harden, Apply, Recovery, Menus.
#
# Dependencies on $script: state:
#   $script:DnsProviderId              - selected provider key (or None)
#   $script:DnsProviders               - catalog of DisplayName/Primary/Secondary
#   $script:DnsKnownDohTemplates       - IP -> DoH template URL map
#   $script:BastionDnsDohInterfaceFlags - DoH registry flags (default 17; Settings Encrypted)
#   $script:Sections["DNS"]            - section toggle (synced by Set-BastionDnsProviderId)
#   Config/undo helpers: Save-UndoData, Read-BastionUndoData, Confirm-RestorePointBeforeApply
#
# Honesty (DoH / DohFlags=17):
#   Value 17 is a Windows Settings compatibility constant: automatic DoH template and
#   no plaintext fallback on the interface key. Changing it casually breaks the
#   Encrypted badge and prior-snapshot restore semantics. Bastion DPAPI on undo
#   snapshots encrypts prior DNS on disk; that is separate from DoH on the wire.
#   VPN adapters are excluded from eligible lists and may still override DNS while up.

function Get-BastionDnsProvider {
    <#
      Purpose:
        Resolve a provider id to the DnsProviders catalog entry (defaults Quad9).

      When called:
        Dry Run, Apply, Audit, menu D labels, DNS Apply path.

      Side effects:
        None.

      Undo implications:
        None. Preference id is stored in config; live adapter DNS is separate.
    #>
    param([string]$Id = $script:DnsProviderId)
    if ([string]::IsNullOrWhiteSpace($Id)) { $Id = "Quad9" }
    if ($script:DnsProviders.Contains($Id)) { return $script:DnsProviders[$Id] }
    return $script:DnsProviders["Quad9"]
}

function Get-BastionDnsProviderLabel {
    <#
      Purpose:
        Human label for menus: "Do not change DNS" or "Name (primary IP)".

      When called:
        Main menu / DNS menu status lines.

      Side effects:
        None. Honors Sections["DNS"] and DnsProviderId None.
    #>
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
    <#
      Purpose:
        Unified eligible-adapter filter so Dry Run, Audit, Apply, and Recovery stay consistent.
        Up adapters only; excludes loopback, virtual, WSL, Docker, and common VPN descriptions.

      When called:
        Every DNS read/write path that must not touch VPN virtual NICs by design.

      Side effects:
        Get-NetAdapter query only.

      Undo implications:
        None. Adapters missing from snapshot later are skipped on restore (renamed/removed).
    #>
    # Unified filter for Dry Run, Audit, and Apply so results stay consistent.
    return @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq "Up" -and
        $_.InterfaceDescription -notmatch "Loopback|Bluetooth|Virtual|Hyper-V|vEthernet|WSL|Docker|VPN|TAP|TUN|WireGuard|Mullvad|OpenVPN|Cisco AnyConnect|NordLynx"
    })
}

function Get-AdapterDnsServers {
    <#
      Purpose:
        List IPv4 DNS server addresses for an interface index (empty if DHCP/unset).

      When called:
        Match tests, snapshots, live summary, Dry Run / Audit.

      Side effects:
        Get-DnsClientServerAddress only.
    #>
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
    <#
      Purpose:
        Normalize InterfaceGuid strings to lowercase {guid} form for stable registry paths.

      When called:
        Before any InterfaceSpecificParameters DoH path read/write.

      Side effects:
        None (string formatting). Invalid input returns $null.
    #>
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $g = $Raw.Trim()
    if ($g -notmatch '^\{') { $g = "{$g}" }
    if ($g -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') { return $null }
    # Windows stores InterfaceSpecificParameters GUIDs lowercase; normalize for stable paths.
    return $g.ToLowerInvariant()
}

function Get-BastionDnsKnownDohTemplate {
    <#
      Purpose:
        Map a DNS server IP to a DoH template URL from Bastion catalog or OS DoH list.

      When called:
        When enabling DoH for provider IPs or inferring snapshot DoH entries.

      Side effects:
        May call Get-DnsClientDohServerAddress (read).

      Honesty:
        Unknown public IPs without a template get classic DNS only; Bastion does not invent templates.
    #>
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
    <#
      Purpose:
        Read per-interface DoH child keys under Dnscache InterfaceSpecificParameters.

      When called:
        Snapshot capture and diagnostics.

      Side effects / Windows objects touched:
        Reads HKLM:\...\Dnscache\InterfaceSpecificParameters\<guid>\DohInterfaceSettings\Doh\*
        (DohTemplate, DohFlags). No writes.
    #>
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
    <#
      Purpose:
        Remove all per-interface DoH server subkeys for a NIC (used on DHCP reset / empty restore).

      When called:
        Reset-BastionDnsToAutomatic and restore when prior DNS was empty/automatic.

      Side effects / Windows objects touched:
        Deletes HKLM InterfaceSpecificParameters DoH children for that GUID.

      Undo implications:
        Encryption badges clear for that adapter until DoH is re-enabled. Global DoH list
        entries (Add-DnsClientDohServerAddress) are not removed by this function.
    #>
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
    <#
      Purpose:
        Register one DNS server for DoH three ways so Settings shows Encrypted:
        (1) DnsClient DoH server list, (2) netsh dns encryption, (3) per-interface registry.

      When called:
        Enable-BastionDnsOverHttpsForAdapter during Apply / DNS Apply / restore.

      Side effects / Windows objects touched:
        - Add/Set-DnsClientDohServerAddress (AllowFallbackToUdp false, AutoUpgrade true)
        - netsh.exe dns set/add encryption
        - HKLM ...\Doh\<ip>: DohTemplate (String), DohFlags (QWord, default 17)

      Undo implications:
        Snapshot stores prior DohEntries; restore re-applies them. Clearing interface keys
        without snapshot loses prior Encrypted state for that NIC.

      Honesty (DohFlags=17):
        Windows Settings writes DohFlags as REG_QWORD. Value 17 means automatic template
        On with no plaintext fallback (not legacy Bastion DWORD 5). Wrong type is removed
        before rewrite. DoH is best-effort: module/netsh failures log Warning but registry
        may still succeed. "Encrypted" in Settings is DoH on the wire, not Bastion DPAPI.
    #>
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
    <#
      Purpose:
        Apply DoH for all servers on one adapter from snapshot entries and/or known
        templates; prune interface DoH keys for IPs no longer configured.

      When called:
        After Set-DnsClientServerAddress on Apply / DNS Apply / restore, and when
        already provider-first (re-confirm DoH).

      Side effects:
        Multiple Set-BastionInterfaceDohEntry calls; may delete stale DoH children.

      Undo implications:
        Prefer snapshot DohEntries so prior templates/flags return on restore.
    #>
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
    <#
      Purpose:
        Capture eligible adapters' IPv4 DNS servers, GUIDs, and DoH entries (version 2).
        If registry has no DoH yet, infer known templates so restore can re-enable Encrypted.

      When called:
        Before DNS changes in full Apply or Invoke-BastionDnsSectionApply when mismatch exists.

      Side effects:
        Read-only network/registry queries. Snapshot object is later DPAPI-encrypted when
        Save-UndoData persists Bastion-LastApply data.

      Undo implications:
        Essential for Recovery DNS restore. Without snapshot, Bastion cannot return prior
        servers/DoH accurately.
    #>
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
    <#
      Purpose:
        Re-apply prior per-adapter DNS servers and DoH from a snapshot object (Recovery).

      When called:
        Recovery DNS restore path with undo snapshot. Immediate apply (no main menu 8).

      Side effects / Windows objects touched:
        - Set-DnsClientServerAddress or ResetServerAddresses
        - Enable-BastionDnsOverHttpsForAdapter or Clear-BastionInterfaceDohEntries
        - Clear-DnsClientCache

      Undo implications:
        This IS the undo for Bastion DNS Apply. Does not change menu D preference
        (DnsProviderId). VPN may still override while connected.

      Honesty:
        Missing adapters are skipped with Warn. Classic-only restore if no DoH template.
        Settings Encrypted badge may need Settings reopened.
    #>
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
    <#
      Purpose:
        True when the adapter's first IPv4 DNS equals the selected provider Primary.

      When called:
        Dry Run, Apply, DNS Apply (skip rewrite if already first).

      Side effects:
        Read-only. Secondary/DoH state is not required for "match."
    #>
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
    <#
      Purpose:
        Set preference id and keep Sections["DNS"] in sync (false when None).

      When called:
        Menu D selection and Quick Harden DNS pick. Preference only until Apply/DNS Apply.

      Side effects:
        Mutates $script:DnsProviderId and $script:Sections["DNS"]. No adapter changes.

      Undo implications:
        None for live DNS. Changing preference alone does not restore prior servers.
    #>
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
    <#
      Purpose:
        Console-ready lines listing live eligible adapter DNS for menus.

      When called:
        DNS menu status display.

      Side effects:
        Read-only queries.
    #>
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
      Purpose:
        Apply menu D provider to eligible adapters (IPs + DoH). Writes Bastion undo with
        DNS snapshot when changes are needed. Merges non-DNS fields from prior undo when present.

      When called:
        DNS menu "apply now" path. Immediate Windows changes (no extra main menu 8).
        Also conceptually mirrors the DNS block inside Invoke-ApplyHardening.

      Side effects / Windows objects touched:
        - Optional restore-point confirm (unless SkipRestorePrompt)
        - Get-BastionDnsSnapshot + Set-DnsClientServerAddress + DoH enable
        - Clear-DnsClientCache
        - Save-UndoData (DPAPI-protected snapshot fields)

      Undo implications:
        Recovery can Restore-BastionDnsFromSnapshot from saved undo. Menu D preference
        stays as user left it.

      Honesty (DoH / DohFlags=17):
        Same DoH path as full Apply. Already-matching adapters only re-confirm DoH.
        VPN may still override. Settings Encrypted may need a Settings reopen.
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
    <#
      Purpose:
        Reset eligible adapters to DHCP/system DNS and clear per-interface DoH keys.

      When called:
        Recovery / DNS menu DHCP reset. Immediate apply (no main menu 8).

      Side effects:
        Set-DnsClientServerAddress -ResetServerAddresses; Clear-BastionInterfaceDohEntries;
        Clear-DnsClientCache.

      Undo implications:
        Does not restore Bastion snapshot; it forces automatic. Menu D preference unchanged.
        Prior Bastion snapshot remains on disk until overwritten by a later Apply.
    #>
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
