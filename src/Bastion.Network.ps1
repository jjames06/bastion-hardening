# =============================================================================
# Bastion.Network.ps1 - LAN hygiene (generic) + optional home-gateway probe
# =============================================================================
#
# PURPOSE
#   Workstation-side LAN leak and NIC power-save hardening that works on any
#   personal Windows 10/11 PC. Optional Recovery helper fingerprints the
#   default gateway over HTTP; vendor-specific CPE actions run ONLY when the
#   live banner matches a known family (currently Sagemcom Fast GUI, used by
#   some ISP skins). Never assumes a brand or 192.168.2.1. Never stores CPE passwords.
#
# LOAD ORDER
#   After Bastion.Dns.ps1, before Bastion.Harden.ps1.
#
# DO NOT
#   - Enable LanHygiene by default in Quick Harden (printers / mDNS / NetBIOS).
#   - Drive unknown routers, "smart" APs, or mesh kits.
#   - Log or write CPE admin passwords, Wi-Fi PSKs, or PPPoE secrets.
#   - Lock NIC speed (2.5G vs 1G) on Apply; that is cable/PHY specific.
#   - Treat this module as antivirus or as a replacement for a real firewall.
# =============================================================================

function Get-BastionDefaultGatewayIpv4 {
    <#
      Purpose: IPv4 next hop for 0.0.0.0/0 (dynamic; not a hardcoded LAN IP).
    #>
    try {
        $r = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
            Where-Object { $_.NextHop -and $_.NextHop -ne "0.0.0.0" } |
            Sort-Object RouteMetric, ifMetric |
            Select-Object -First 1
        if ($r) { return [string]$r.NextHop }
    } catch {}
    return $null
}

function Get-BastionLanHygieneStatus {
    <#
      Purpose: Live detection for Dry Run / Audit / Apply (no writes).
    #>
    $st = [ordered]@{
        LlmnrOff     = $false
        WpadOverride = $false
        MdnsOff      = $false
        NetbiosOff   = $false
        NicPowerOk   = $true
        NicNotes     = @()
        LinkNotes    = @()
    }
    try {
        $v = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
        $st.LlmnrOff = ($v -eq 0)
    } catch {}
    try {
        $w = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name WpadOverride -ErrorAction SilentlyContinue).WpadOverride
        $st.WpadOverride = ($w -eq 1)
    } catch {}
    try {
        $m = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableMDNS -ErrorAction SilentlyContinue).EnableMDNS
        $st.MdnsOff = ($m -eq 0)
    } catch {}
    try {
        $nb = @(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
            Where-Object { $_.IPEnabled -and $_.TcpipNetbiosOptions -ne 2 })
        $st.NetbiosOff = ($nb.Count -eq 0)
    } catch {}
    try {
        foreach ($nic in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" })) {
            foreach ($kw in @("Green Ethernet", "Gigabit Lite", "Energy-Efficient Ethernet", "Power Saving Mode")) {
                $p = Get-NetAdapterAdvancedProperty -Name $nic.Name -DisplayName $kw -ErrorAction SilentlyContinue
                if ($p -and "$($p.DisplayValue)" -match "Enabled") {
                    $st.NicPowerOk = $false
                    $st.NicNotes += ("{0}: {1}={2}" -f $nic.Name, $kw, $p.DisplayValue)
                }
            }
            $spd = [string]$nic.LinkSpeed
            if ($spd -match "2\.5" -or $spd -match "2500") {
                $st.LinkNotes += ("{0} is {1}. Long or marginal cables can retrain and look like disconnects; Bastion does not lock speed." -f $nic.Name, $spd)
            }
        }
    } catch {}
    return $st
}

function Invoke-BastionLanHygiene {
    <#
      Purpose:
        Apply workstation LAN hygiene: LLMNR off, WPAD autodetect override,
        mDNS off, NetBIOS-over-TCP off on IP-enabled adapters, Realtek-style
        NIC power-save properties Disabled when present. Optional outbound
        UDP 137/138/5353 block rules.

      Honesty:
        Does not change default-gateway firmware. Does not set Speed & Duplex.
        VPN adapters may still override DNS. Some printers/NAS discovery break.
    #>
    param([switch]$DryRun)
    $st = Get-BastionLanHygieneStatus
    $need = @()
    if (-not $st.LlmnrOff) { $need += "LLMNR policy off" }
    if (-not $st.WpadOverride) { $need += "WPAD override" }
    if (-not $st.MdnsOff) { $need += "mDNS off" }
    if (-not $st.NetbiosOff) { $need += "NetBIOS off" }
    if (-not $st.NicPowerOk) { $need += ("NIC power-save: {0}" -f ($st.NicNotes -join "; ")) }
    if ($DryRun) {
        if ($need.Count -eq 0) {
            $extra = if ($st.LinkNotes.Count) { (" Already OK. Note: {0}" -f ($st.LinkNotes -join " ")) } else { "" }
            Show-DryItem "LanHygiene" "Already OK" ("LLMNR/WPAD/mDNS/NetBIOS/NIC power-save look hardened.{0}" -f $extra)
        } else {
            $note = if ($st.LinkNotes.Count) { (" Note: {0}" -f ($st.LinkNotes -join " ")) } else { "" }
            Show-DryItem "LanHygiene" "Would change" (("{0}.{1}" -f ($need -join "; "), $note).Trim())
        }
        return
    }

    Write-Host "  [LanHygiene]" -ForegroundColor Cyan
    try {
        $dnsPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $dnsPol)) { New-Item $dnsPol -Force | Out-Null }
        New-ItemProperty $dnsPol -Name EnableMulticast -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Status "LLMNR multicast disabled (policy)" "Applied"
    } catch { Write-Status ("LLMNR policy: {0}" -f $_.Exception.Message) "Failed" }
    try {
        $wpad = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
        if (-not (Test-Path $wpad)) { New-Item $wpad -Force | Out-Null }
        New-ItemProperty $wpad -Name WpadOverride -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Status "WPAD autodetect override set" "Applied"
    } catch { Write-Status ("WPAD: {0}" -f $_.Exception.Message) "Failed" }
    try {
        $mdns = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        if (-not (Test-Path $mdns)) { New-Item $mdns -Force | Out-Null }
        New-ItemProperty $mdns -Name EnableMDNS -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Status "mDNS disabled (DNS cache)" "Applied"
    } catch { Write-Status ("mDNS: {0}" -f $_.Exception.Message) "Failed" }
    try {
        $n = 0
        foreach ($cfg in @(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled })) {
            try {
                $r = Invoke-CimMethod -InputObject $cfg -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 }
                if ($r.ReturnValue -eq 0) { $n++ }
            } catch {}
        }
        Write-Status ("NetBIOS-over-TCP disabled on {0} IP adapter(s)" -f $n) "Applied"
    } catch { Write-Status ("NetBIOS: {0}" -f $_.Exception.Message) "Failed" }
    try {
        $changed = 0
        foreach ($nic in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" })) {
            foreach ($kw in @("Green Ethernet", "Gigabit Lite", "Energy-Efficient Ethernet", "Advanced EEE", "Power Saving Mode")) {
                $p = Get-NetAdapterAdvancedProperty -Name $nic.Name -DisplayName $kw -ErrorAction SilentlyContinue
                if ($p -and "$($p.DisplayValue)" -match "Enabled" -and ($p.ValidDisplayValues -contains "Disabled")) {
                    try {
                        Set-NetAdapterAdvancedProperty -Name $nic.Name -DisplayName $kw -DisplayValue "Disabled" -NoRestart -ErrorAction Stop
                        $changed++
                    } catch {}
                }
            }
            try { Set-NetAdapterPowerManagement -Name $nic.Name -SelectiveSuspend Disabled -ErrorAction SilentlyContinue } catch {}
        }
        if ($changed -gt 0) {
            Write-Status ("Disabled {0} NIC power-save propert(y/ies) (no speed lock)" -f $changed) "Applied"
        } else {
            Write-Status "NIC power-save properties already off or not present" "Already"
        }
    } catch { Write-Status ("NIC properties: {0}" -f $_.Exception.Message) "Warn" }
    foreach ($rule in @(
            @{ N = "Bastion Block NBNS UDP 137"; P = 137 },
            @{ N = "Bastion Block NBDS UDP 138"; P = 138 },
            @{ N = "Bastion Block mDNS UDP 5353"; P = 5353 }
        )) {
        try {
            if (-not (Get-NetFirewallRule -DisplayName $rule.N -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $rule.N -Direction Outbound -Action Block -Protocol UDP -RemotePort $rule.P -Profile Any -ErrorAction Stop | Out-Null
                Write-Status ("Firewall outbound block {0}" -f $rule.N) "Applied"
            } else {
                Write-Status ("Firewall rule exists: {0}" -f $rule.N) "Already"
            }
        } catch { Write-Status ("Firewall {0}: {1}" -f $rule.N, $_.Exception.Message) "Warn" }
    }
    foreach ($n in @($st.LinkNotes)) {
        Write-Host ("    Note: {0}" -f $n) -ForegroundColor DarkGray
    }
}

function Get-BastionGatewayFingerprint {
    <#
      Purpose:
        Read-only HTTP GET of the IPv4 default gateway. Classify generically.
        Never logs body secrets. Timeouts are short so a dead CPE cannot hang Apply.
    #>
    $gw = Get-BastionDefaultGatewayIpv4
    $info = [ordered]@{
        Gateway    = $gw
        Family     = "unknown"
        Detail     = ""
        Reachable  = $false
    }
    if (-not $gw) {
        $info.Detail = "No IPv4 default gateway on this PC."
        return [pscustomobject]$info
    }
    $url = "http://{0}/" -f $gw
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 4 -MaximumRedirection 2 -ErrorAction Stop
        $info.Reachable = $true
        $body = [string]$r.Content
        $hdr = ""
        try { $hdr = [string]$r.Headers["TPL_VER"] } catch {}
        if ($body -match "sagemcom|Sagem Communications|TPL_VER|jquery-1\.8\.3" -or $hdr) {
            $info.Family = "sagemcom-fast"
            $info.Detail = ("HTTP 200 from {0}; Sagemcom Fast-style GUI (TPL={1}). Actions below are optional and CPE-specific." -f $gw, $(if ($hdr) { $hdr } else { "n/a" }))
        } elseif ($body -match "tplink|TP-Link") {
            $info.Family = "other-cpe"
            $info.Detail = ("HTTP 200 from {0}; looks like TP-Link. Bastion will not drive this firmware." -f $gw)
        } elseif ($body -match "netgear|NETGEAR") {
            $info.Family = "other-cpe"
            $info.Detail = ("HTTP 200 from {0}; looks like NETGEAR. Bastion will not drive this firmware." -f $gw)
        } elseif ($body -match "asus|ASUS") {
            $info.Family = "other-cpe"
            $info.Detail = ("HTTP 200 from {0}; looks like ASUS. Bastion will not drive this firmware." -f $gw)
        } else {
            $info.Family = "generic-http"
            $info.Detail = ("HTTP 200 from {0}; unknown CPE UI. Use the vendor admin page. Bastion will not send CPE commands." -f $gw)
        }
    } catch {
        $info.Detail = ("Gateway {0} did not serve a usable HTTP admin page ({1})." -f $gw, $_.Exception.Message)
    }
    return [pscustomobject]$info
}

function Show-HomeGatewayRecoveryMenu {
    <#
      Purpose:
        Recovery-only. Identify the live default gateway. If it fingerprints as
        Sagemcom Fast (some ISP skins), offer optional Wi-Fi-radio / UPnP /
        USB-SMB toggles. Any other CPE: identify only. Never part of Apply
        or Quick Harden. Most homes will not match.
    #>
    Clear-BastionScreen
    Write-Header "HOME GATEWAY (OPTIONAL)"
    Write-AppliesWhen -Mode Now -Extra "Read-only probe of THIS PC's default gateway. Vendor commands run only after a matching fingerprint AND a Yes."
    Write-Host ""
    Write-Host "  Bastion does not assume a brand or LAN IP. Most homes are not a Bell Giga Hub." -ForegroundColor Yellow
    Write-Host "  Wrong firmware commands can drop Wi-Fi, IPTV, or the admin UI. Prefer the vendor page." -ForegroundColor Yellow
    Write-Host ""
    $fp = Get-BastionGatewayFingerprint
    Write-Host ("  Default gateway: {0}" -f $(if ($fp.Gateway) { $fp.Gateway } else { "(none)" })) -ForegroundColor White
    Write-Host ("  Family:          {0}" -f $fp.Family) -ForegroundColor White
    Write-Host ("  {0}" -f $fp.Detail) -ForegroundColor DarkGray
    Write-Host ""
    if ($fp.Family -ne "sagemcom-fast") {
        Write-Host "  No Sagemcom Fast GUI detected. Nothing to apply here." -ForegroundColor Cyan
        Write-Host "  Open the vendor admin UI in a browser if you need CPE settings." -ForegroundColor DarkGray
        Wait-ForKey "Press any key to return to Network recovery..."
        return
    }
    Write-Host "  Optional Sagemcom Fast actions (session only; password is never saved):" -ForegroundColor Cyan
    Write-Host "  1  Disable Wi-Fi radios (wired-only homes; can break IPTV Wi-Fi boxes)" -ForegroundColor White
    Write-Host "  2  Disable UPnP IGD + USB/SMB file sharing if those objects exist" -ForegroundColor White
    Write-Host "  0  Back (recommended unless you know this CPE)" -ForegroundColor DarkGray
    Write-Host ""
    $c = Read-MenuChoice -Prompt "  Select" -Valid @("0", "1", "2")
    if ($c -eq "0") { return }
    Write-Host ""
    Write-Host "  These JSON calls are CPE-specific. A failed xpath is a no-op, not a brick guarantee." -ForegroundColor Yellow
    if ((Read-YesNo -Prompt "  Continue against the detected Sagemcom Fast GUI (Y/N)?") -ne "Y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        Wait-ForKey "Press any key..."
        return
    }
    $pass = Read-Host "  CPE admin password (not logged; Enter to cancel)"
    if ([string]::IsNullOrWhiteSpace($pass)) {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        Wait-ForKey "Press any key..."
        return
    }
    try {
        Invoke-BastionSagemcomOptionalHardening -Gateway $fp.Gateway -Password $pass -Mode $c
    } catch {
        Write-Status ("CPE action failed: {0}" -f $_.Exception.Message) "Failed"
    } finally {
        $pass = $null
    }
    Wait-ForKey "Press any key to return to Network recovery..."
}

function Get-BastionSha512Hex {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA512]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally { $sha.Dispose() }
}

function Invoke-BastionSagemcomJson {
    param(
        [string]$Gateway,
        [string]$HashPass,
        [string]$Nonce,
        [string]$SessionId,
        [int]$ReqId,
        [string]$ActionsJson,
        [bool]$Priority
    )
    $cnonce = Get-Random -Maximum 2147483647
    $ha1 = Get-BastionSha512Hex ("admin:{0}:{1}" -f $Nonce, $HashPass)
    $auth = Get-BastionSha512Hex ("{0}:{1}:{2}:JSON:/cgi/json-req" -f $ha1, $ReqId, $cnonce)
    $pri = if ($Priority) { "true" } else { "false" }
    $req = "{`"request`":{`"id`":$ReqId,`"session-id`":`"$SessionId`",`"priority`":$pri,`"actions`":$ActionsJson,`"cnonce`":$cnonce,`"auth-key`":`"$auth`"}}"
    $uri = "http://{0}/cgi/json-req" -f $Gateway
    return (Invoke-WebRequest -Uri $uri -Method POST -Body @{ req = $req } -TimeoutSec 20 -UseBasicParsing).Content
}

function Invoke-BastionSagemcomOptionalHardening {
    <#
      Purpose: Best-effort Sagemcom Fast JSON after fingerprint match.
      Honesty: xpaths may 16777219 (unknown) on other skins; those are skipped.
    #>
    param(
        [string]$Gateway,
        [string]$Password,
        [string]$Mode
    )
    $hash = Get-BastionSha512Hex $Password
    $login = '[{"id":0,"method":"logIn","parameters":{"user":"admin","persistent":"true","session-options":{"nss":[{"name":"gtw","uri":"http://sagemcom.com/gateway-data"}],"context-flags":{"get-content-name":true},"capability-depth":0,"capability-flags":{"name":true},"time-format":"ISO_8601"}}}]'
    $lr = Invoke-BastionSagemcomJson -Gateway $Gateway -HashPass $hash -Nonce "" -SessionId "0" -ReqId 0 -ActionsJson $login -Priority $true
    if ($lr -notmatch '"nonce"') {
        Write-Status "CPE login failed (wrong password or different auth)." "Failed"
        return
    }
    $j = $lr | ConvertFrom-Json
    $sess = [string]$j.reply.actions[0].callbacks[0].parameters.id
    $nonce = [string]$j.reply.actions[0].callbacks[0].parameters.nonce
    Write-Status "CPE session opened (not stored)" "Applied"
    $actions = $null
    if ($Mode -eq "1") {
        $actions = '[{"id":0,"method":"setValue","xpath":"Device/WiFi/Radios/Radio[@uid=''1'']/Enable","parameters":{"value":false}},{"id":1,"method":"setValue","xpath":"Device/WiFi/Radios/Radio[@uid=''2'']/Enable","parameters":{"value":false}},{"id":2,"method":"setValue","xpath":"Device/WiFi/Radios/Radio[@uid=''3'']/Enable","parameters":{"value":false}}]'
    } else {
        $actions = '[{"id":0,"method":"setValue","xpath":"Device/UPnP/Device/UPnPIGD","parameters":{"value":false}},{"id":1,"method":"setValue","xpath":"Device/UPnP/Device/Enable","parameters":{"value":false}},{"id":2,"method":"setValue","xpath":"Device/Services/StorageServices/StorageService[@uid=''1'']/NetworkServer/SMBEnable","parameters":{"value":false}}]'
    }
    $sr = Invoke-BastionSagemcomJson -Gateway $Gateway -HashPass $hash -Nonce $nonce -SessionId $sess -ReqId 1 -ActionsJson $actions -Priority $false
    if ($sr -match "XMO_NO_ERR") {
        Write-Status "CPE setValue completed (unknown xpaths on other skins are ignored by the CPE)" "Applied"
    } else {
        Write-Status "CPE setValue returned errors; GUI may differ. Use the vendor page." "Warn"
    }
    try {
        [void](Invoke-BastionSagemcomJson -Gateway $Gateway -HashPass $hash -Nonce $nonce -SessionId $sess -ReqId 2 -ActionsJson '[{"id":0,"method":"logOut"}]' -Priority $true)
    } catch {}
    Write-Host "  Password discarded. Re-probe if you need another action." -ForegroundColor DarkGray
}

function Invoke-BastionUndoLanHygieneFirewall {
    <#
      Purpose: Recovery helper to remove Bastion outbound 137/138/5353 rules.
    #>
    $names = @(
        "Bastion Block NBNS UDP 137",
        "Bastion Block NBDS UDP 138",
        "Bastion Block mDNS UDP 5353"
    )
    foreach ($n in $names) {
        try {
            $r = Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
            if ($r) {
                Remove-NetFirewallRule -DisplayName $n -ErrorAction Stop
                Write-Status ("Removed {0}" -f $n) "Applied"
            } else {
                Write-Status ("Absent {0}" -f $n) "Already"
            }
        } catch { Write-Status ("Remove {0}: {1}" -f $n, $_.Exception.Message) "Failed" }
    }
}
