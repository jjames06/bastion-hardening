# =============================================================================
# Bastion.Recovery.ps1 - modular domain (v15.9.0)
# =============================================================================
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.
#
# Role of this module
#   Targeted reverse / re-open / re-harden paths under main menu 9. Actions run
#   NOW (no main menu 8). Prefer a specific hub over full Undo when the user
#   knows what broke. Hubs paint live Windows status before offering changes.
#
# Hub map (Show-RecoveryMenu)
#   1 Undo last Apply (partial: services, firewall groups, DNS snap, RDP prior)
#   2 Services (Spooler, HighRisk stack, Xbox)
#   3 Network (remote access, LAN discovery, DNS DHCP / snapshot restore)
#   4 Browser policies (delegates to Show-BrowserPolicyMenu)
#   5 Apps and UI (Copilot, Widgets/Suggestions, Game Bar)
#   6 Security mitigations (StrictHandle, Defender NP/CFA, policies/tasks)
#
# Honesty rules
#   Opening remote/LAN paths or re-enabling services increases attack surface.
#   Appx bloat / OneDrive are not reinstallable here. System Restore is stronger
#   than Undo. Comments use ASCII punctuation only.
# =============================================================================

# -----------------------------------------------------------------------------
# Invoke-UndoHardening
#   Recovery hub 1. Best-effort restore from Bastion-LastApply.json only:
#   Spooler force-on, tracked DisabledServices, FirewallGroups re-enabled,
#   encrypted DNS snapshot, RDP host prior when RdpHostLocked was stored.
#   Does not reinstall Appx/OneDrive or clear browser enterprise policies.
# -----------------------------------------------------------------------------
function Invoke-UndoHardening {
    Clear-BastionScreen
    Write-Header "UNDO LAST HARDENING"
    Write-AppliesWhen -Mode Now -Extra "Best-effort from last Apply only. System Restore (menu 13 / R) is stronger for full rollback."
    Write-Host ""
    Write-Host "  Will try to restore (when saved):" -ForegroundColor White
    Write-UxBullets -Items @(
        "Tracked services Bastion disabled"
        "Firewall groups Bastion locked"
        "Prior DNS snapshot (if a DNS Apply stored one)"
        "RDP host prior (if RdpHostLock ran)"
    )
    Write-Host ""
    Write-Host "  Will NOT: reinstall Appx/OneDrive, or reverse every registry tweak." -ForegroundColor DarkGray
    Write-Host ""
    if (-not (Read-ConfirmYes -Prompt "  Type YES to attempt Undo")) { return }
    $undoData = Read-BastionUndoData
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
    if (Test-BastionUndoHasDnsSnapshot -UndoData $undoData) {
        Write-Host "  [DNS] Restoring prior DNS from encrypted snapshot..." -ForegroundColor Cyan
        $snap = Get-BastionDnsSnapshotFromUndo -UndoData $undoData
        if ($snap) {
            [void](Restore-BastionDnsFromSnapshot -Snapshot $snap)
        }
    }
    if ($undoData -and $undoData.RdpHostLocked) {
        $prior = Get-BastionRdpHostPriorFromUndo -UndoData $undoData
        if ($prior) {
            Write-Host "  [RDP host] Restoring prior system RDP / TermService state..." -ForegroundColor Cyan
            try {
                $deny = 1
                try { $deny = [int]$prior.fDenyTSConnections } catch { $deny = 1 }
                $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
                Set-ItemProperty -Path $path -Name fDenyTSConnections -Value $deny -Type DWord -Force -ErrorAction Stop
                Write-Status ("fDenyTSConnections restored to {0}" -f $deny) "Applied"
                $st = "Manual"
                try { $st = [string]$prior.ServiceStartType } catch {}
                if ($st -notin @("Automatic","Manual","Disabled")) { $st = "Manual" }
                Set-Service -Name TermService -StartupType $st -ErrorAction SilentlyContinue
                if ($deny -eq 0 -and $st -eq "Automatic") {
                    Start-Service -Name TermService -ErrorAction SilentlyContinue
                }
                Write-Status ("TermService start type restored to {0}" -f $st) "Applied"
            } catch {
                Write-Status ("RDP host restore failed: {0}" -f $_.Exception.Message) "Failed"
            }
        } else {
            Write-Host "  [RDP host] Prior state unavailable (decrypt failed or not stored). Use Recovery > 3 Network > Remote access." -ForegroundColor Yellow
        }
    }
    Write-Host "  Undo finished (partial by design). Next step if issues remain: System Restore." -ForegroundColor Green
    Write-Host "  Prefer Recovery hubs (Services, Network, Security mitigations) over full Undo when you know what broke." -ForegroundColor DarkGray
    Wait-ForKey
}

# -----------------------------------------------------------------------------
# Get-CopilotM365Status
#   Live detection for Copilot / Office Hub Appx, provisioned packages, policy
#   TurnOffWindowsCopilot, taskbar ShowCopilotButton, and Office Click-to-Run.
#   NeedsWork is true if policy off is missing, button not hidden, or Appx present.
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Invoke-CopilotM365Hardening
#   Apply path for CopilotM365 section (and Recovery "safe all"): policy keys,
#   hide taskbar button, remove matching user Appx; optional provisioned remove.
#   Never uninstalls full Microsoft 365 Click-to-Run (Office suite).
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Invoke-CopilotM365Removal
#   Recovery Apps/UI > Copilot submenu. Interactive steps 1-5: policy, user Appx,
#   provisioned packages, destructive full Office C2R uninstall (YES gate), or
#   safe batch (1+2+3). Live status repaints each loop.
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Get-BastionFirewallGroupInboundStatus
#   Classify a Windows firewall DisplayGroup for Recovery UI:
#     NOT PRESENT - no inbound rules in group (edition/feature missing)
#     OPEN        - at least one inbound Allow rule is enabled
#     LOCKED      - group present but no enabled inbound Allows (Bastion style)
#   Does not read profile-level Inbound=Block; only named group rules.
# -----------------------------------------------------------------------------
function Get-BastionFirewallGroupInboundStatus {
    param([Parameter(Mandatory)][string]$DisplayGroup)
    $all = @()
    $enabledAllow = @()
    try {
        $all = @(Get-NetFirewallRule -DisplayGroup $DisplayGroup -ErrorAction SilentlyContinue |
            Where-Object { $_.Direction -eq "Inbound" })
        $enabledAllow = @($all | Where-Object {
            ($_.Enabled -eq $true -or $_.Enabled -eq "True") -and $_.Action -eq "Allow"
        })
    } catch {}
    $present = $all.Count -gt 0
    $open = $enabledAllow.Count -gt 0
    $label = if (-not $present) { "NOT PRESENT" } elseif ($open) { "OPEN" } else { "LOCKED" }
    return [PSCustomObject]@{
        DisplayGroup       = $DisplayGroup
        Present            = $present
        Open               = $open
        EnabledAllowCount  = $enabledAllow.Count
        InboundRuleCount   = $all.Count
        Label              = $label
    }
}

# -----------------------------------------------------------------------------
# Enable-BastionFirewallGroupInbound
#   Recovery helper: enable all inbound rules in DisplayGroup (opens the path).
#   Matches Undo behavior for tracked firewall groups. Increases exposure.
# -----------------------------------------------------------------------------
function Enable-BastionFirewallGroupInbound {
    param([Parameter(Mandatory)][string]$DisplayGroup)
    # Match Undo: re-enable inbound rules in the group so the remote path can work again.
    try {
        $rules = @(Get-NetFirewallRule -DisplayGroup $DisplayGroup -ErrorAction Stop |
            Where-Object { $_.Direction -eq "Inbound" })
        if ($rules.Count -eq 0) {
            Write-Status ("No inbound rules found for group: {0}" -f $DisplayGroup) "Warn"
            return $false
        }
        $n = 0
        foreach ($rule in $rules) {
            try {
                Set-NetFirewallRule -InputObject $rule -Enabled True -Confirm:$false -ErrorAction Stop
                $n++
            } catch {
                Write-Status ("Rule fail in {0}: {1}" -f $DisplayGroup, $rule.DisplayName) "Warn"
            }
        }
        Write-Status ("Enabled {0} inbound rule(s) in {1}" -f $n, $DisplayGroup) "Applied"
        Write-Log ("Enable-BastionFirewallGroupInbound group={0} count={1}" -f $DisplayGroup, $n) -NoConsole
        return $true
    } catch {
        Write-Status ("Enable group '{0}' failed: {1}" -f $DisplayGroup, $_.Exception.Message) "Failed"
        return $false
    }
}

# -----------------------------------------------------------------------------
# Disable-BastionFirewallGroupInbound
#   Bastion Apply style: disable currently enabled inbound rules in the group
#   (LOCKED). Leaves already-disabled rules alone. Profile Inbound=Block untouched.
# -----------------------------------------------------------------------------
function Disable-BastionFirewallGroupInbound {
    param([Parameter(Mandatory)][string]$DisplayGroup)
    # Bastion Apply style: disable currently enabled inbound rules in the group.
    try {
        $rules = @(Get-NetFirewallRule -DisplayGroup $DisplayGroup -ErrorAction Stop |
            Where-Object {
                $_.Direction -eq "Inbound" -and (
                    $_.Enabled -eq $true -or $_.Enabled -eq "True"
                )
            })
        if ($rules.Count -eq 0) {
            Write-Status ("Already locked / no enabled inbound rules: {0}" -f $DisplayGroup) "Already"
            return $true
        }
        $n = 0
        foreach ($rule in $rules) {
            try {
                Set-NetFirewallRule -InputObject $rule -Enabled False -Confirm:$false -ErrorAction Stop
                $n++
            } catch {
                Write-Status ("Rule fail in {0}: {1}" -f $DisplayGroup, $rule.DisplayName) "Warn"
            }
        }
        Write-Status ("Disabled {0} inbound rule(s) in {1}" -f $n, $DisplayGroup) "Applied"
        Write-Log ("Disable-BastionFirewallGroupInbound group={0} count={1}" -f $DisplayGroup, $n) -NoConsole
        return $true
    } catch {
        Write-Status ("Disable group '{0}' failed: {1}" -f $DisplayGroup, $_.Exception.Message) "Failed"
        return $false
    }
}

# -----------------------------------------------------------------------------
# Write-BastionRemoteAccessStatusBlock
#   Paint firewall groups (Remote Desktop / Assistance / WinRM) plus system
#   fDenyTSConnections and TermService for remote-access recovery screens.
# -----------------------------------------------------------------------------
function Write-BastionRemoteAccessStatusBlock {
    Write-Host "  Live status" -ForegroundColor Cyan
    foreach ($g in $script:RemoteAccessFirewallGroups) {
        $st = Get-BastionFirewallGroupInboundStatus -DisplayGroup $g
        $color = switch ($st.Label) {
            "OPEN" { "Yellow" }
            "LOCKED" { "Green" }
            default { "DarkGray" }
        }
        $detail = if ($st.Present) {
            "{0} inbound allow rule(s) enabled; {1} inbound rule(s) total" -f $st.EnabledAllowCount, $st.InboundRuleCount
        } else {
            "group not found on this PC"
        }
        Write-Host ("    Firewall  {0,-28} {1,-11}  {2}" -f $g, $st.Label, $detail) -ForegroundColor $color
    }
    $rdp = Get-BastionRemoteDesktopSystemStatus
    $rdpColor = switch ($rdp.SystemLabel) {
        "ALLOWED" { "Yellow" }
        "DENIED" { "Green" }
        default { "DarkGray" }
    }
    $denyVal = if ($null -eq $rdp.fDenyTSConnections) { "?" } else { [string]$rdp.fDenyTSConnections }
    Write-Host ("    System    Remote Desktop allow      {0,-11}  fDenyTSConnections={1}" -f $rdp.SystemLabel, $denyVal) -ForegroundColor $rdpColor
    $svcColor = if ($rdp.ServiceStatus -eq "Running") { "Yellow" } else { "DarkGray" }
    Write-Host ("    Service   TermService               {0,-11}  StartType={1}" -f $rdp.ServiceStatus, $rdp.ServiceStartType) -ForegroundColor $svcColor
}

# -----------------------------------------------------------------------------
# Show-RemoteDesktopRecoveryMenu
#   Network > Remote access > RDP triad:
#     firewall group OPEN/LOCK, system allow (fDenyTSConnections), TermService.
#   Full host RDP usually needs all three open/running. Home edition limits apply.
# -----------------------------------------------------------------------------
function Show-RemoteDesktopRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "REMOTE DESKTOP"
        $fw = Get-BastionFirewallGroupInboundStatus -DisplayGroup "Remote Desktop"
        $rdp = Get-BastionRemoteDesktopSystemStatus
        Write-Host "  Live status" -ForegroundColor Cyan
        Write-Host ("    Firewall group:  {0}  ({1} allow rule(s) on)" -f $fw.Label, $fw.EnabledAllowCount) `
            -ForegroundColor $(if ($fw.Open) { "Yellow" } else { "Green" })
        Write-Host ("    System allow:    {0}  (fDenyTSConnections={1})" -f $rdp.SystemLabel, $(if ($null -eq $rdp.fDenyTSConnections) { "?" } else { $rdp.fDenyTSConnections })) `
            -ForegroundColor $(if ($rdp.SystemAllowed) { "Yellow" } else { "Green" })
        Write-Host ("    TermService:     {0} / {1}" -f $rdp.ServiceStatus, $rdp.ServiceStartType) -ForegroundColor White
        Write-Host ""
        Write-Host "  What this controls" -ForegroundColor Cyan
        Write-Host "    Firewall rules  - whether the network can reach RDP ports (group Bastion disables on Apply)." -ForegroundColor White
        Write-Host "    System allow    - Windows policy fDenyTSConnections (Settings > System > Remote Desktop)." -ForegroundColor White
        Write-Host "    TermService     - Remote Desktop Services process that actually hosts sessions." -ForegroundColor White
        Write-Host ""
        Write-Host "  Honest notes" -ForegroundColor Yellow
        Write-Host "    Full host RDP usually needs OPEN firewall + system ALLOWED + TermService running." -ForegroundColor DarkGray
        Write-Host "    Windows Home often cannot act as a full RDP host the way Pro/Enterprise can." -ForegroundColor DarkGray
        Write-Host "    Opening RDP is a real security trade-off. Prefer DENIED/LOCKED when you do not need it." -ForegroundColor DarkGray
        Write-Host "    Bastion Firewall Apply does not set fDenyTSConnections; that is optional here only." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  -- Firewall rule group --" -ForegroundColor DarkCyan
        Write-Host "  1  Enable Remote Desktop inbound rules" -ForegroundColor Yellow
        Write-Host "  2  Disable / lock Remote Desktop inbound rules" -ForegroundColor Green
        Write-Host ""
        Write-Host "  -- System Remote Desktop (optional) --" -ForegroundColor DarkCyan
        Write-Host "  3  Allow remote connections (fDenyTSConnections=0; start TermService)" -ForegroundColor Yellow
        Write-Host "  4  Deny remote connections (fDenyTSConnections=1; stop TermService -> Manual)" -ForegroundColor Green
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3","4")
        switch ($c) {
            "0" { return }
            "1" {
                Write-Host ""
                Write-Host "  This opens inbound RDP firewall rules. Anyone who can reach this PC on the network" -ForegroundColor Yellow
                Write-Host "  may attempt to connect if system RDP is also allowed and accounts permit it." -ForegroundColor Yellow
                if ((Read-YesNo -Prompt "  Enable Remote Desktop firewall group (Y/N)?") -eq "Y") {
                    [void](Enable-BastionFirewallGroupInbound -DisplayGroup "Remote Desktop")
                }
                Wait-ForKey "Press any key to return to Remote Desktop..."
            }
            "2" {
                Write-Host ""
                if ((Read-YesNo -Prompt "  Lock Remote Desktop firewall group (Y/N)?") -eq "Y") {
                    [void](Disable-BastionFirewallGroupInbound -DisplayGroup "Remote Desktop")
                }
                Wait-ForKey "Press any key to return to Remote Desktop..."
            }
            "3" {
                Write-Host ""
                Write-Host "  This sets Windows to allow Remote Desktop connections and starts TermService." -ForegroundColor Yellow
                Write-Host "  You still need open firewall rules (option 1) for remote clients to reach this PC." -ForegroundColor DarkGray
                Write-Host "  Use a strong password / Windows Hello, and prefer private networks only." -ForegroundColor DarkGray
                if ((Read-YesNo -Prompt "  Allow system RDP and start TermService (Y/N)?") -eq "Y") {
                    [void](Enable-BastionRemoteDesktopSystem)
                }
                Wait-ForKey "Press any key to return to Remote Desktop..."
            }
            "4" {
                Write-Host ""
                Write-Host "  Denies new Remote Desktop logons via fDenyTSConnections=1 and stops TermService." -ForegroundColor White
                if ((Read-YesNo -Prompt "  Deny system RDP and stop TermService (Y/N)?") -eq "Y") {
                    [void](Disable-BastionRemoteDesktopSystem -StopService)
                }
                Wait-ForKey "Press any key to return to Remote Desktop..."
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-RemoteFirewallGroupMenu
#   Generic OPEN/LOCK UI for one firewall DisplayGroup (Assistance, WinRM, LAN
#   groups). Optional Purpose text explains why the group exists. Confirms Y/N.
# -----------------------------------------------------------------------------
function Show-RemoteFirewallGroupMenu {
    param(
        [Parameter(Mandatory)][string]$DisplayGroup,
        [Parameter(Mandatory)][string]$Title,
        [string]$Purpose = ""
    )
    while ($true) {
        Clear-BastionScreen
        Write-Header $Title
        $st = Get-BastionFirewallGroupInboundStatus -DisplayGroup $DisplayGroup
        Write-Host "  Live status" -ForegroundColor Cyan
        Write-Host ("    Group:   {0}" -f $DisplayGroup) -ForegroundColor White
        Write-Host ("    State:   {0}" -f $st.Label) -ForegroundColor $(if ($st.Open) { "Yellow" } else { "Green" })
        Write-Host ("    Detail:  {0} inbound allow rule(s) enabled; {1} inbound rule(s) total" -f $st.EnabledAllowCount, $st.InboundRuleCount) -ForegroundColor DarkGray
        if (-not $st.Present) {
            Write-Host "    Note:    This rule group was not found. Edition/feature may not include it." -ForegroundColor Yellow
        }
        Write-Host ""
        if ($Purpose) {
            Write-Host "  What this is" -ForegroundColor Cyan
            foreach ($line in @(Get-WrappedLines -Text $Purpose -Indent 4)) {
                Write-Host $line -ForegroundColor White
            }
            Write-Host ""
        }
        Write-Host "  Honest notes" -ForegroundColor Yellow
        Write-Host "    OPEN means inbound allow rules in this group are enabled (more exposure)." -ForegroundColor DarkGray
        Write-Host "    LOCKED matches Bastion Firewall Apply for this group (safer default)." -ForegroundColor DarkGray
        Write-Host "    Profile-level Inbound=Block from Bastion is not changed here." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  1  Enable inbound rules (open this path)" -ForegroundColor Yellow
        Write-Host "  2  Disable / lock inbound rules (Bastion-style)" -ForegroundColor Green
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2")
        switch ($c) {
            "0" { return }
            "1" {
                Write-Host ""
                if ((Read-YesNo -Prompt ("  Enable firewall group '{0}' (Y/N)?" -f $DisplayGroup)) -eq "Y") {
                    [void](Enable-BastionFirewallGroupInbound -DisplayGroup $DisplayGroup)
                }
                Wait-ForKey ("Press any key to return to {0}..." -f $Title)
            }
            "2" {
                Write-Host ""
                if ((Read-YesNo -Prompt ("  Lock firewall group '{0}' (Y/N)?" -f $DisplayGroup)) -eq "Y") {
                    [void](Disable-BastionFirewallGroupInbound -DisplayGroup $DisplayGroup)
                }
                Wait-ForKey ("Press any key to return to {0}..." -f $Title)
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-RemoteAccessRecoveryMenu
#   Network hub entry for remote paths Bastion locks on Firewall Apply.
#   Submenus: RDP triad, Remote Assistance group, WinRM group, bulk enable/lock
#   for all three groups (bulk enable requires YES). Does not set system RDP
#   except via the dedicated Remote Desktop submenu.
# -----------------------------------------------------------------------------
function Show-RemoteAccessRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "REMOTE ACCESS (RDP / ASSISTANCE / WINRM)"
        Write-AppliesWhen -Mode Now -Extra "Opening remote paths increases attack surface. Prefer LOCKED when you are not using them."
        Write-BastionRemoteAccessStatusBlock
        Write-Host ""
        Write-Host "  What this menu is for" -ForegroundColor Cyan
        Write-Host "    After Firewall Apply, Bastion locks inbound groups for Remote Desktop," -ForegroundColor White
        Write-Host "    Remote Assistance, and WinRM. Re-open a path here only when you need it again." -ForegroundColor White
        Write-Host ""
        Write-Host "  1  Remote Desktop (firewall + optional system allow / TermService)" -ForegroundColor White
        Write-Host "  2  Remote Assistance (firewall group)" -ForegroundColor White
        Write-Host "  3  WinRM / Windows Remote Management (firewall group)" -ForegroundColor White
        Write-Host "  4  Enable all three firewall groups (requires YES - more exposure)" -ForegroundColor Yellow
        Write-Host "  5  Lock all three firewall groups (Bastion-style; safer default)" -ForegroundColor Green
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3","4","5")
        switch ($c) {
            "0" { return }
            "1" { Show-RemoteDesktopRecoveryMenu }
            "2" {
                Show-RemoteFirewallGroupMenu -DisplayGroup "Remote Assistance" -Title "REMOTE ASSISTANCE" `
                    -Purpose "Remote Assistance lets a trusted helper connect to view or control this session when both parties accept. Bastion disables its inbound firewall group on Apply. Enable only for a temporary help session, then lock again."
            }
            "3" {
                Show-RemoteFirewallGroupMenu -DisplayGroup "Windows Remote Management" -Title "WINRM / WINDOWS REMOTE MANAGEMENT" `
                    -Purpose "WinRM (Windows Remote Management) is used by PowerShell remoting and some admin tools. Bastion disables its inbound firewall group on Apply. Enable only if you deliberately administer this PC over WinRM; leave locked for a normal single-user workstation."
            }
            "4" {
                Write-Host ""
                Write-Host "  This enables inbound firewall rules for:" -ForegroundColor Yellow
                foreach ($g in $script:RemoteAccessFirewallGroups) {
                    Write-Host ("    - {0}" -f $g) -ForegroundColor Yellow
                }
                Write-Host "  It does NOT change fDenyTSConnections or TermService (use menu 1 for system RDP)." -ForegroundColor DarkGray
                Write-Host "  Only do this if you need remote access paths open on purpose." -ForegroundColor Yellow
                if (-not (Read-ConfirmYes -Prompt "  Type YES to enable all three remote-access firewall groups")) {
                    Write-Host "  Cancelled." -ForegroundColor Yellow
                    Wait-ForKey "Press any key to return to Remote access..."
                    continue
                }
                foreach ($g in $script:RemoteAccessFirewallGroups) {
                    [void](Enable-BastionFirewallGroupInbound -DisplayGroup $g)
                }
                Wait-ForKey "Press any key to return to Remote access..."
            }
            "5" {
                Write-Host ""
                Write-Host "  Locks Remote Desktop, Remote Assistance, and WinRM inbound groups (Bastion Apply style)." -ForegroundColor White
                Write-Host "  Does not change fDenyTSConnections / TermService (use Remote Desktop menu 4 to deny system RDP)." -ForegroundColor DarkGray
                if ((Read-YesNo -Prompt "  Lock all three remote-access firewall groups (Y/N)?") -eq "Y") {
                    foreach ($g in $script:RemoteAccessFirewallGroups) {
                        [void](Disable-BastionFirewallGroupInbound -DisplayGroup $g)
                    }
                }
                Wait-ForKey "Press any key to return to Remote access..."
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Write-BastionServiceStatusBlock
#   Print live status rows from ServiceRecoveryCatalog (optional GroupFilter).
#   Color: DISABLED=Green (safer), RUNNING=Yellow, STOPPED=White.
#   Returns the row array for callers that need present-service lists.
# -----------------------------------------------------------------------------
function Write-BastionServiceStatusBlock {
    param([string]$GroupFilter = "")
    $rows = @()
    foreach ($e in $script:ServiceRecoveryCatalog) {
        if ($GroupFilter -and $e.Group -ne $GroupFilter) { continue }
        $rows += ,(Get-BastionServiceStatusRow -Name $e.Name)
    }
    foreach ($r in $rows) {
        $color = switch ($r.Label) {
            "DISABLED" { "Green" }
            "RUNNING" { "Yellow" }
            "STOPPED" { "White" }
            default { "DarkGray" }
        }
        Write-Host ("    {0,-16} {1,-11} {2,-10}  {3}" -f $r.Name, $r.Label, $r.StartType, $r.Display) -ForegroundColor $color
    }
    return $rows
}

# -----------------------------------------------------------------------------
# Show-BastionServiceGroupMenu
#   Enable one present service, all present, or disable all (Bastion-style) for
#   a catalog Group (HighRisk / Xbox). PreferStart drives re-enable startup type.
# -----------------------------------------------------------------------------
function Show-BastionServiceGroupMenu {
    param(
        [Parameter(Mandatory)][string]$Group,
        [Parameter(Mandatory)][string]$Title,
        [string]$Purpose = ""
    )
    while ($true) {
        Clear-BastionScreen
        Write-Header $Title
        Write-Host "  Live status" -ForegroundColor Cyan
        $rows = @(Write-BastionServiceStatusBlock -GroupFilter $Group)
        Write-Host ""
        if ($Purpose) {
            Write-Host "  What this is" -ForegroundColor Cyan
            foreach ($wl in @(Get-WrappedLines -Text $Purpose -Indent 4)) { Write-Host $wl -ForegroundColor White }
            Write-Host ""
        }
        Write-Host "  Honest notes" -ForegroundColor Yellow
        Write-Host "    DISABLED often means Bastion HighRiskServices / XboxGaming applied (or you disabled it)." -ForegroundColor DarkGray
        Write-Host "    Re-enabling restores function but also restores attack surface for that service." -ForegroundColor DarkGray
        Write-Host "    Remote Registry and ICS are higher risk; only enable if you know you need them." -ForegroundColor DarkGray
        Write-Host ""
        $present = @($rows | Where-Object { $_.Present })
        if ($present.Count -eq 0) {
            Write-Host "  No services from this group are installed on this PC." -ForegroundColor DarkGray
            Write-Host "  0  Back" -ForegroundColor DarkGray
            [void](Read-MenuChoice -Prompt "  Select" -Valid @("0"))
            return
        }
        for ($i = 0; $i -lt $present.Count; $i++) {
            $r = $present[$i]
            Write-Host ("  {0}  Enable {1} ({2})  [{3}]" -f ($i + 1), $r.Name, $r.Display, $r.Label) -ForegroundColor White
        }
        $allN = $present.Count + 1
        $disN = $present.Count + 2
        Write-Host ("  {0}  Enable ALL present in this group" -f $allN) -ForegroundColor Yellow
        Write-Host ("  {0}  Disable ALL present (Bastion-style)" -f $disN) -ForegroundColor Green
        Write-Host "  0  Back" -ForegroundColor DarkGray
        $valid = @("0") + @(1..$disN | ForEach-Object { "$_" })
        $c = Read-MenuChoice -Prompt "  Select" -Valid $valid
        if ($c -eq "0") { return }
        $n = [int]$c
        if ($n -ge 1 -and $n -le $present.Count) {
            $pick = $present[$n - 1]
            Write-Host ""
            Write-Host ("  {0}: {1}" -f $pick.Name, $pick.Why) -ForegroundColor Cyan
            if ((Read-YesNo -Prompt ("  Enable {0} as {1} (Y/N)?" -f $pick.Name, $pick.PreferStart)) -eq "Y") {
                [void](Enable-BastionService -Name $pick.Name -StartupType $pick.PreferStart)
            }
            Wait-ForKey ("Press any key to return to {0}..." -f $Title)
        } elseif ($n -eq $allN) {
            Write-Host ""
            Write-Host "  Enables every present service in this group (function over maximum lockdown)." -ForegroundColor Yellow
            if ((Read-YesNo -Prompt "  Enable all present services in this group (Y/N)?") -eq "Y") {
                foreach ($r in $present) {
                    [void](Enable-BastionService -Name $r.Name -StartupType $r.PreferStart)
                }
            }
            Wait-ForKey ("Press any key to return to {0}..." -f $Title)
        } elseif ($n -eq $disN) {
            Write-Host ""
            Write-Host "  Stops and disables these services the same way Apply does for this group." -ForegroundColor White
            if ((Read-YesNo -Prompt "  Disable all present services in this group (Y/N)?") -eq "Y") {
                foreach ($r in $present) {
                    [void](Disable-BastionService -Name $r.Name)
                }
            }
            Wait-ForKey ("Press any key to return to {0}..." -f $Title)
        }
    }
}

# -----------------------------------------------------------------------------
# Show-ServicesRecoveryMenu
#   Recovery hub 2. Quick Spooler re-enable plus HighRisk / Xbox group menus.
#   Live status of Bastion-managed services painted every entry.
# -----------------------------------------------------------------------------
function Show-ServicesRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "SERVICES RECOVERY"
        Write-AppliesWhen -Mode Now -Extra "Re-enable only what you need (printing, share, Xbox) without full Undo."
        Write-Host "  Live status (Bastion-managed)" -ForegroundColor Cyan
        Write-Host "  -- High-risk / discovery stack --" -ForegroundColor DarkCyan
        [void](Write-BastionServiceStatusBlock -GroupFilter "HighRisk")
        Write-Host "  -- Xbox --" -ForegroundColor DarkCyan
        [void](Write-BastionServiceStatusBlock -GroupFilter "Xbox")
        Write-Host ""
        Write-Host "  1  Print Spooler (common fix when printing stopped)" -ForegroundColor Green
        Write-Host "  2  High-risk services (file share, UPnP, Remote Registry, ...)" -ForegroundColor White
        Write-Host "  3  Xbox services" -ForegroundColor White
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3")
        switch ($c) {
            "0" { return }
            "1" {
                Write-Host ""
                $row = Get-BastionServiceStatusRow -Name "Spooler"
                Write-Host ("  Spooler now: {0} / {1}" -f $row.Label, $row.StartType) -ForegroundColor White
                if ((Read-YesNo -Prompt "  Re-enable Print Spooler as Automatic and start it (Y/N)?") -eq "Y") {
                    [void](Enable-BastionService -Name "Spooler" -StartupType "Automatic")
                }
                Wait-ForKey "Press any key to return to Services recovery..."
            }
            "2" {
                Show-BastionServiceGroupMenu -Group "HighRisk" -Title "HIGH-RISK SERVICES" `
                    -Purpose "These are the services HighRiskServices can disable: file sharing host, discovery helpers, Remote Registry, ICS, Fax, and Print Spooler. Re-enable only what you use. Prefer Spooler alone if you only need printing."
            }
            "3" {
                Show-BastionServiceGroupMenu -Group "Xbox" -Title "XBOX SERVICES" `
                    -Purpose "XboxGaming disables these services on Apply. Re-enable if you use Xbox / Game Pass features. Game DVR silence is separate under Apps and UI > Game Bar."
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-LanDiscoveryRecoveryMenu
#   Network hub: File and Printer Sharing, Network Discovery, mDNS groups.
#   Per-group OPEN/LOCK or bulk enable (YES) / lock. Profile block unchanged.
# -----------------------------------------------------------------------------
function Show-LanDiscoveryRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "LAN / DISCOVERY FIREWALL"
        Write-Host "  Live status" -ForegroundColor Cyan
        foreach ($g in $script:LanDiscoveryFirewallGroups) {
            $st = Get-BastionFirewallGroupInboundStatus -DisplayGroup $g
            $color = switch ($st.Label) {
                "OPEN" { "Yellow" }
                "LOCKED" { "Green" }
                default { "DarkGray" }
            }
            Write-Host ("    {0,-28} {1,-11}  {2} allow rule(s) on" -f $g, $st.Label, $st.EnabledAllowCount) -ForegroundColor $color
        }
        Write-Host ""
        Write-Host "  What this is for" -ForegroundColor Cyan
        Write-Host "    Firewall Apply locks File and Printer Sharing, Network Discovery, and mDNS inbound" -ForegroundColor White
        Write-Host "    groups so this PC is quieter on the LAN. Open them only if you need shares, printers," -ForegroundColor White
        Write-Host "    or device discovery. Remote Desktop / Assistance / WinRM live under Remote access." -ForegroundColor White
        Write-Host ""
        Write-Host "  Honest notes" -ForegroundColor Yellow
        Write-Host "    OPEN increases LAN exposure (especially File and Printer Sharing)." -ForegroundColor DarkGray
        Write-Host "    Profile-level Inbound=Block stays; this only toggles named groups." -ForegroundColor DarkGray
        Write-Host "    You may still need services like LanmanServer (Services recovery) for hosting shares." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  1  File and Printer Sharing" -ForegroundColor White
        Write-Host "  2  Network Discovery" -ForegroundColor White
        Write-Host "  3  mDNS" -ForegroundColor White
        Write-Host "  4  Enable all three LAN groups (requires YES)" -ForegroundColor Yellow
        Write-Host "  5  Lock all three LAN groups (Bastion-style)" -ForegroundColor Green
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3","4","5")
        switch ($c) {
            "0" { return }
            "1" {
                Show-RemoteFirewallGroupMenu -DisplayGroup "File and Printer Sharing" -Title "FILE AND PRINTER SHARING" `
                    -Purpose "Inbound rules for SMB/file and printer sharing. Needed to host or sometimes reach classic Windows shares on this PC. Pair with Server (LanmanServer) service if you host shares."
            }
            "2" {
                Show-RemoteFirewallGroupMenu -DisplayGroup "Network Discovery" -Title "NETWORK DISCOVERY" `
                    -Purpose "Lets this PC appear and discover other devices on the local network. Useful for home LAN browsing; not required for normal internet use."
            }
            "3" {
                Show-RemoteFirewallGroupMenu -DisplayGroup "mDNS" -Title "MDNS" `
                    -Purpose "Multicast DNS discovery used by some printers, media devices, and apps. Lock if you do not need local mDNS."
            }
            "4" {
                Write-Host ""
                Write-Host "  Opens inbound rules for File and Printer Sharing, Network Discovery, and mDNS." -ForegroundColor Yellow
                if (-not (Read-ConfirmYes -Prompt "  Type YES to enable all three LAN discovery groups")) {
                    Write-Host "  Cancelled." -ForegroundColor Yellow
                    Wait-ForKey "Press any key to return to LAN / discovery..."
                    continue
                }
                foreach ($g in $script:LanDiscoveryFirewallGroups) {
                    [void](Enable-BastionFirewallGroupInbound -DisplayGroup $g)
                }
                Wait-ForKey "Press any key to return to LAN / discovery..."
            }
            "5" {
                Write-Host ""
                if ((Read-YesNo -Prompt "  Lock all three LAN discovery groups (Y/N)?") -eq "Y") {
                    foreach ($g in $script:LanDiscoveryFirewallGroups) {
                        [void](Disable-BastionFirewallGroupInbound -DisplayGroup $g)
                    }
                }
                Wait-ForKey "Press any key to return to LAN / discovery..."
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-NetworkRecoveryMenu
#   Recovery hub 3. Live remote + LAN group labels, RDP host snapshot, live DNS
#   adapters, menu D preference, and encrypted prior-DNS snapshot availability.
#   Actions: remote access, LAN discovery, DNS->DHCP, DNS->restore snapshot.
#   Options 3 and 4 are independent; snapshot only exists after a DNS Apply.
# -----------------------------------------------------------------------------
function Show-NetworkRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "NETWORK RECOVERY"
        Write-AppliesWhen -Mode Now -Extra "Open a path below for firewall or DNS fixes. Prefer a specific option over full Undo when you know what broke."
        Write-Host ""
        Write-Host "  Live Windows status" -ForegroundColor Cyan
        Write-Host "  -- Remote access groups --" -ForegroundColor DarkCyan
        foreach ($g in $script:RemoteAccessFirewallGroups) {
            $st = Get-BastionFirewallGroupInboundStatus -DisplayGroup $g
            $color = if ($st.Label -eq "OPEN") { "Yellow" } elseif ($st.Label -eq "LOCKED") { "Green" } else { "DarkGray" }
            Write-Host ("    {0,-28} {1}" -f $g, $st.Label) -ForegroundColor $color
        }
        try {
            $rdpLive = Get-BastionRemoteDesktopSystemStatus
            Write-Host ("  -- RDP host (system) --  allow={0}  TermService={1}/{2}" -f `
                $rdpLive.SystemLabel, $rdpLive.ServiceStatus, $rdpLive.ServiceStartType) -ForegroundColor DarkCyan
        } catch {}
        Write-Host "  -- LAN / discovery groups --" -ForegroundColor DarkCyan
        foreach ($g in $script:LanDiscoveryFirewallGroups) {
            $st = Get-BastionFirewallGroupInboundStatus -DisplayGroup $g
            $color = if ($st.Label -eq "OPEN") { "Yellow" } elseif ($st.Label -eq "LOCKED") { "Green" } else { "DarkGray" }
            Write-Host ("    {0,-28} {1}" -f $g, $st.Label) -ForegroundColor $color
        }
        Write-Host "  -- DNS on eligible adapters (live) --" -ForegroundColor DarkCyan
        $adapters = @(Get-BastionDnsAdapters)
        if ($adapters.Count -eq 0) {
            Write-Host "    (no eligible adapters)" -ForegroundColor DarkGray
        } else {
            foreach ($a in $adapters) {
                $dns = @(Get-AdapterDnsServers -InterfaceIndex $a.ifIndex)
                $first = if ($dns.Count) { $dns[0] } else { "(automatic / none listed)" }
                Write-Host ("    {0,-28} {1}" -f $a.Name, $first) -ForegroundColor White
            }
        }
        Write-Host ""
        Write-Host "  Bastion DNS notes" -ForegroundColor Cyan
        Write-Host ("    Preferred provider (menu D):  {0}" -f (Get-BastionDnsProviderLabel)) -ForegroundColor White
        $undoPeek = Read-BastionUndoData
        $hasSnap = Test-BastionUndoHasDnsSnapshot -UndoData $undoPeek
        $snapPreview = if ($hasSnap) { Get-BastionDnsSnapshotPreviewText -UndoData $undoPeek } else { $null }
        if ($hasSnap) {
            Write-Host ("    Prior snapshot available:     {0}" -f $snapPreview) -ForegroundColor Cyan
            Write-Host "    (snapshot = what adapters had BEFORE your last Bastion DNS Apply)" -ForegroundColor DarkGray
        } else {
            Write-Host "    Prior snapshot available:     none yet" -ForegroundColor DarkGray
            Write-Host "    (create one by applying DNS once via DNS menu A or main menu 8)" -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-Host "  Choose an action" -ForegroundColor Cyan
        Write-Host "  1  Remote access (RDP / Assistance / WinRM + system RDP)" -ForegroundColor White
        Write-Host "  2  LAN / discovery (File Sharing, Network Discovery, mDNS)" -ForegroundColor White
        Write-Host "  3  DNS -> automatic (DHCP) on eligible adapters" -ForegroundColor Yellow
        if ($hasSnap) {
            Write-Host "  4  DNS -> restore prior snapshot (before last Bastion DNS Apply)" -ForegroundColor Yellow
        } else {
            Write-Host "  4  DNS -> restore prior snapshot (unavailable until you Apply DNS once)" -ForegroundColor DarkGray
        }
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Tip: 3 and 4 are independent. You do not need 3 before 4." -ForegroundColor DarkGray
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3","4")
        switch ($c) {
            "0" { return }
            "1" { Show-RemoteAccessRecoveryMenu }
            "2" { Show-LanDiscoveryRecoveryMenu }
            "3" {
                Write-Host ""
                Write-Host "  Reset DNS to automatic (DHCP)" -ForegroundColor Cyan
                Write-UxDivider
                Write-AppliesWhen -Mode Now
                Write-Host ""
                Write-Host "  Will do:" -ForegroundColor White
                Write-UxBullets -Items @(
                    "Clear static IPv4 DNS on Bastion-eligible adapters"
                    "Clear per-adapter DNS-over-HTTPS keys Bastion set"
                    "Let Windows use DHCP / automatic DNS again"
                )
                Write-Host ""
                Write-Host "  Will NOT do:" -ForegroundColor White
                Write-UxBullets -Items @(
                    ("Change menu D preference (still: {0})" -f (Get-BastionDnsProviderLabel))
                    "Delete the saved prior-DNS snapshot (option 4 still works later)"
                    "Require main menu 8"
                ) -ForegroundColor DarkGray
                Write-Host ""
                Write-Host "  Note: a VPN may still force its own DNS while connected." -ForegroundColor DarkGray
                Write-Host ""
                if ((Read-YesNo -Prompt "  Reset adapter DNS to automatic now (Y/N)?") -eq "Y") {
                    [void](Reset-BastionDnsToAutomatic)
                } else {
                    Write-Host "  Cancelled." -ForegroundColor DarkGray
                }
                Wait-ForKey "Press any key to return to Network recovery..."
            }
            "4" {
                Write-Host ""
                if (-not $hasSnap) {
                    Write-Host "  Restore prior DNS - unavailable" -ForegroundColor Yellow
                    Write-UxDivider
                    Write-Host "  Bastion has no prior-DNS snapshot yet." -ForegroundColor White
                    Write-Host ""
                    Write-Host "  How to create one:" -ForegroundColor Cyan
                    Write-UxBullets -Items @(
                        "Main menu D - pick a provider (saves preference only)"
                        "Apply that provider so adapters actually change:"
                        "  DNS menu: press A   - or -   main menu 8 (DNS section on)"
                        "Bastion saves what was on the adapters before that change"
                    )
                    Write-Host ""
                    Write-Host "  Then return here and choose 4 to put those prior servers back." -ForegroundColor DarkGray
                    Wait-ForKey "Press any key to return to Network recovery..."
                    continue
                }
                Write-Host "  Restore prior DNS from snapshot" -ForegroundColor Cyan
                Write-UxDivider
                Write-AppliesWhen -Mode Now
                Write-Host ""
                Write-Host "  Will do:" -ForegroundColor White
                Write-UxBullets -Items @(
                    ("Set eligible adapters back to: {0}" -f $snapPreview)
                    "Restore DNS-over-HTTPS when templates are known (Settings Encrypted)"
                ) -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  Will NOT do:" -ForegroundColor White
                Write-UxBullets -Items @(
                    ("Change menu D preference (still: {0})" -f (Get-BastionDnsProviderLabel))
                    "Change firewall, services, or other sections"
                    "Require main menu 8"
                ) -ForegroundColor DarkGray
                Write-Host ""
                Write-Host "  Notes:" -ForegroundColor White
                Write-UxBullets -Items @(
                    "Snapshot = adapter state before your last Bastion DNS Apply (not menu D alone)"
                    "Best-effort if adapters were renamed or removed"
                    "VPN may still override DNS while connected"
                    "Re-open Windows Settings if the Encrypted badge was already on screen"
                ) -ForegroundColor DarkGray
                Write-Host ""
                if ((Read-YesNo -Prompt "  Restore prior DNS now (Y/N)?") -eq "Y") {
                    $snap = Get-BastionDnsSnapshotFromUndo -UndoData $undoPeek
                    if ($snap) {
                        [void](Restore-BastionDnsFromSnapshot -Snapshot $snap)
                        Write-Host ""
                        Write-Host "  Live adapters after restore:" -ForegroundColor Cyan
                        foreach ($line in @(Get-BastionLiveDnsSummaryLines)) {
                            Write-Host $line -ForegroundColor Green
                        }
                    } else {
                        Write-Status "Could not load snapshot (decrypt failed or corrupt)" "Failed"
                    }
                } else {
                    Write-Host "  Cancelled." -ForegroundColor DarkGray
                }
                Wait-ForKey "Press any key to return to Network recovery..."
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-GameBarRecoveryMenu
#   Silence or re-enable Game DVR / ms-gamingoverlay capture flags when games
#   prompt for a missing Game Bar app. Does not install Xbox Game Bar itself.
# -----------------------------------------------------------------------------
function Show-GameBarRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "GAME BAR / MS-GAMINGOVERLAY"
        Write-Host "  Games may open ms-gamingoverlay when Game DVR is on but Xbox Game Bar is missing." -ForegroundColor Cyan
        Write-Host "  That shows: Get an app to open this 'ms-gamingoverlay' link." -ForegroundColor DarkGray
        Write-Host ""
        $silenced = Test-BastionGameDvrSilenced
        Write-Host ("  Game DVR silence status: {0}" -f $(if ($silenced) { "ON (capture discouraged)" } else { "OFF (games may still prompt)" })) -ForegroundColor White
        Write-Host ""
        Write-Host "  1 Silence prompt (disable Game DVR / capture flags)  [recommended if you do not use Game Bar]"
        Write-Host "  2 Re-enable Game DVR flags (then install Xbox Game Bar from Store if needed)"
        Write-Host "  0 Back"
        $g = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2")
        switch ($g) {
            "0" { return }
            "1" {
                [void](Disable-BastionGameDvrOverlay)
                Write-Host "  Fully quit and relaunch games to confirm the dialog is gone." -ForegroundColor DarkGray
                Wait-ForKey
            }
            "2" {
                [void](Enable-BastionGameDvrOverlay)
                Wait-ForKey
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-AppsUiRecoveryMenu
#   Recovery hub 5. Copilot tools, Widgets/Suggestions restore, Game Bar silence.
#   Honest: Appx bloat removed by Apply is not reinstallable from this menu.
# -----------------------------------------------------------------------------
function Show-AppsUiRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "APPS AND UI RECOVERY"
        Write-Host "  Targeted fixes for optional app/UI surfaces Bastion can change." -ForegroundColor White
        Write-Host "  Appx bloat removal is not reinstallable here - use System Restore or Microsoft Store." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  1  Copilot / M365 tools" -ForegroundColor White
        Write-Host "  2  Restore Widgets / Suggestions defaults" -ForegroundColor Green
        Write-Host "  3  Game Bar / ms-gamingoverlay prompt" -ForegroundColor Yellow
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3")
        switch ($c) {
            "0" { return }
            "1" { Invoke-CopilotM365Removal }
            "2" {
                Write-Host ""
                if ((Read-YesNo -Prompt "  Restore Widgets/Suggestions registry defaults (Y/N)?") -eq "Y") {
                    Restore-SuggestionDefaults
                }
                Wait-ForKey "Press any key to return to Apps and UI..."
            }
            "3" { Show-GameBarRecoveryMenu }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-StrictHandleRecoveryMenu
#   Security mitigations > StrictHandle. Live system ON/OFF, DEP, Wow*/config
#   exception paths. Options: disable system StrictHandle (reboot), refresh
#   known exceptions only, or re-enable system profile + exceptions.
#   Honesty: only known exception EXEs are covered; other titles need reports.
# -----------------------------------------------------------------------------
function Show-StrictHandleRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "STRICTHANDLE / EXPLOIT PROTECTION"
        $st = Get-BastionStrictHandleSystemStatus
        Write-Host "  Live status" -ForegroundColor Cyan
        Write-Host ("    System StrictHandle: {0}" -f $st.StrictLabel) -ForegroundColor $(if ($st.StrictLabel -eq "ON") { "Yellow" } elseif ($st.StrictLabel -eq "OFF") { "Green" } else { "DarkGray" })
        Write-Host ("    System DEP:          {0}" -f $(if ($null -eq $st.DepOn) { "UNKNOWN" } elseif ($st.DepOn) { "ON" } else { "OFF" })) -ForegroundColor DarkGray
        Write-Host ("    Wow*/exception EXEs: {0} discovered now" -f $st.ExceptionCount) -ForegroundColor White
        if ($st.ExceptionCount -gt 0) {
            foreach ($p in ($st.ExceptionPaths | Select-Object -First 6)) {
                Write-Host ("      - {0}" -f $p) -ForegroundColor DarkGray
            }
            if ($st.ExceptionCount -gt 6) {
                Write-Host ("      ... and {0} more" -f ($st.ExceptionCount - 6)) -ForegroundColor DarkGray
            }
        }
        Write-Host ""
        Write-BastionStrictHandleGuidance -Style Block
        Write-Host ""
        Write-Host "  1  Disable system StrictHandle (whole PC; reboot recommended)" -ForegroundColor Yellow
        Write-Host "  2  Refresh known exception EXEs only (Wow*.exe + config paths; system stays ON)" -ForegroundColor Cyan
        Write-Host "  3  Re-enable system StrictHandle + refresh exceptions (after you can run your apps)" -ForegroundColor Green
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3")
        switch ($c) {
            "0" { return }
            "1" {
                Write-Host ""
                Write-Host "  Turns OFF system-wide StrictHandle. Other mitigations (DEP/SEHOP/ASLR) are left alone." -ForegroundColor Yellow
                Write-Host "  Reboot after this before testing games." -ForegroundColor DarkGray
                if ((Read-YesNo -Prompt "  Disable system StrictHandle now (Y/N)?") -eq "Y") {
                    try {
                        Set-ProcessMitigation -System -Disable StrictHandle -ErrorAction Stop
                        Write-Status "System StrictHandle disabled (reboot recommended)" "Applied"
                    } catch {
                        Write-Status ("StrictHandle disable failed: {0}" -f $_.Exception.Message) "Failed"
                    }
                }
                Wait-ForKey "Press any key to return to StrictHandle recovery..."
            }
            "2" {
                Write-Host ""
                Write-Host "  Discovers known exception EXEs (Wow*.exe + StrictHandleExceptionPaths) and sets StrictHandle OFF for those only." -ForegroundColor White
                Write-Host "  Does not create exceptions for other games until you add paths or we ship them after a report." -ForegroundColor DarkGray
                [void](Set-BastionStrictHandleExceptions)
                Wait-ForKey "Press any key to return to StrictHandle recovery..."
            }
            "3" {
                Write-Host ""
                Write-Host "  Re-applies mild system mitigations including StrictHandle ON, then refreshes known exceptions." -ForegroundColor Yellow
                Write-Host "  Only do this after broken programs work again (or their exceptions exist)." -ForegroundColor DarkGray
                if ((Read-YesNo -Prompt "  Re-enable system StrictHandle profile now (Y/N)?") -eq "Y") {
                    try {
                        Set-ProcessMitigation -System -Enable DEP,SEHOP,BottomUp,HighEntropy,StrictHandle -ErrorAction Stop
                        Write-Status "System mitigations re-applied (StrictHandle ON)" "Applied"
                        [void](Set-BastionStrictHandleExceptions)
                        Write-Host "  Reboot recommended before heavy game testing." -ForegroundColor DarkGray
                    } catch {
                        Write-Status ("Re-enable failed: {0}" -f $_.Exception.Message) "Failed"
                    }
                }
                Wait-ForKey "Press any key to return to StrictHandle recovery..."
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-DefenderRecoveryMenu
#   Soften or re-harden Network Protection and Controlled Folder Access.
#   Softening reduces ransomware/network blocking; prefer CFA allow-list first.
#   Re-harden turns both ON and calls Add-CfaAllowPaths for catalog apps.
# -----------------------------------------------------------------------------
function Show-DefenderRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "DEFENDER (NP / CFA)"
        $np = $null; $cfa = $null
        try {
            $pref = Get-MpPreference -ErrorAction Stop
            $np = ($pref.EnableNetworkProtection -eq 1 -or "$($pref.EnableNetworkProtection)" -eq "Enabled")
            $cfa = ($pref.EnableControlledFolderAccess -eq 1 -or "$($pref.EnableControlledFolderAccess)" -eq "Enabled")
        } catch {}
        Write-Host "  Live status" -ForegroundColor Cyan
        Write-Host ("    Network Protection:        {0}" -f $(if ($null -eq $np) { "UNKNOWN" } elseif ($np) { "ON" } else { "OFF" })) `
            -ForegroundColor $(if ($np) { "Yellow" } elseif ($null -eq $np) { "DarkGray" } else { "Green" })
        Write-Host ("    Controlled Folder Access:  {0}" -f $(if ($null -eq $cfa) { "UNKNOWN" } elseif ($cfa) { "ON" } else { "OFF" })) `
            -ForegroundColor $(if ($cfa) { "Yellow" } elseif ($null -eq $cfa) { "DarkGray" } else { "Green" })
        Write-Host ""
        Write-Host "  Honest notes" -ForegroundColor Yellow
        Write-Host "    Bastion Defender Apply turns these ON and refreshes CFA allow paths for catalog apps." -ForegroundColor DarkGray
        Write-Host "    Softening reduces ransomware / network blocking strength. Prefer allow-list fixes first." -ForegroundColor DarkGray
        Write-Host "    Third-party antivirus may ignore or block these settings." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  1  Soften: turn Network Protection OFF" -ForegroundColor Yellow
        Write-Host "  2  Soften: turn Controlled Folder Access OFF" -ForegroundColor Yellow
        Write-Host "  3  Soften both NP and CFA" -ForegroundColor Yellow
        Write-Host "  4  Re-harden: turn NP + CFA ON and refresh CFA allow paths" -ForegroundColor Green
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3","4")
        switch ($c) {
            "0" { return }
            "1" {
                if ((Read-YesNo -Prompt "  Disable Network Protection (Y/N)?") -eq "Y") {
                    try {
                        Set-MpPreference -EnableNetworkProtection Disabled -ErrorAction Stop
                        Write-Status "Network Protection disabled" "Applied"
                    } catch { Write-Status ("NP disable failed: {0}" -f $_.Exception.Message) "Failed" }
                }
                Wait-ForKey "Press any key to return to Defender recovery..."
            }
            "2" {
                if ((Read-YesNo -Prompt "  Disable Controlled Folder Access (Y/N)?") -eq "Y") {
                    try {
                        Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction Stop
                        Write-Status "Controlled Folder Access disabled" "Applied"
                    } catch { Write-Status ("CFA disable failed: {0}" -f $_.Exception.Message) "Failed" }
                }
                Wait-ForKey "Press any key to return to Defender recovery..."
            }
            "3" {
                if ((Read-YesNo -Prompt "  Disable both Network Protection and CFA (Y/N)?") -eq "Y") {
                    try {
                        Set-MpPreference -EnableNetworkProtection Disabled -ErrorAction SilentlyContinue
                        Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
                        Write-Status "Network Protection + CFA disabled (requested)" "Applied"
                    } catch { Write-Status ("Defender soften failed: {0}" -f $_.Exception.Message) "Failed" }
                }
                Wait-ForKey "Press any key to return to Defender recovery..."
            }
            "4" {
                if ((Read-YesNo -Prompt "  Re-enable NP + CFA and refresh allow paths (Y/N)?") -eq "Y") {
                    try {
                        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
                        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
                        Write-Status "Network Protection + CFA requested ON" "Applied"
                        Add-CfaAllowPaths
                    } catch { Write-Status ("Defender re-harden failed: {0}" -f $_.Exception.Message) "Failed" }
                }
                Wait-ForKey "Press any key to return to Defender recovery..."
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-PolicyTasksRecoveryMenu
#   Clear or re-set Delivery Optimization policy, PowerShell Script Block
#   Logging, LSA RunAsPPL (reboot), and Bastion-listed scheduled tasks
#   (CEIP/Appraiser style list in BastionScheduledTaskPaths).
# -----------------------------------------------------------------------------
function Show-PolicyTasksRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "POLICIES AND TASKS"
        # Live probes for the status strip (read-only until user confirms an action).
        # Delivery Optimization
        $doVal = $null
        try {
            $doVal = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name DODownloadMode -ErrorAction SilentlyContinue).DODownloadMode
        } catch {}
        # PS auditing
        $psLog = $null
        try {
            $psLog = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        } catch {}
        # LSA
        $lsa = $null
        try {
            $lsa = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
        } catch {}
        Write-Host "  Live status" -ForegroundColor Cyan
        Write-Host ("    Delivery Optimization DODownloadMode: {0}" -f $(if ($null -eq $doVal) { "(not set)" } else { $doVal })) -ForegroundColor White
        Write-Host ("    PowerShell ScriptBlockLogging:       {0}" -f $(if ($null -eq $psLog) { "(not set)" } elseif ($psLog -eq 1) { "ON" } else { $psLog })) -ForegroundColor White
        Write-Host ("    LSA RunAsPPL:                        {0}" -f $(if ($null -eq $lsa) { "(not set)" } elseif ($lsa -eq 1) { "ON (1)" } else { $lsa })) -ForegroundColor White
        Write-Host "    Scheduled tasks (Bastion list):" -ForegroundColor White
        foreach ($t in $script:BastionScheduledTaskPaths) {
            $leaf = Split-Path $t -Leaf
            try {
                $task = Get-ScheduledTask -TaskPath (Split-Path $t -Parent) -TaskName $leaf -ErrorAction SilentlyContinue
                if (-not $task) {
                    Write-Host ("      {0,-40} ABSENT" -f $leaf) -ForegroundColor DarkGray
                } else {
                    $col = if ($task.State -eq "Disabled") { "Green" } else { "Yellow" }
                    Write-Host ("      {0,-40} {1}" -f $leaf, $task.State) -ForegroundColor $col
                }
            } catch {
                Write-Host ("      {0,-40} ?" -f $leaf) -ForegroundColor DarkGray
            }
        }
        Write-Host ""
        Write-Host "  Honest notes" -ForegroundColor Yellow
        Write-Host "    Clearing policies undoes Bastion-applied settings for that area only." -ForegroundColor DarkGray
        Write-Host "    LSA changes need a reboot to fully apply. Disabling RunAsPPL weakens credential protection." -ForegroundColor DarkGray
        Write-Host "    Re-enabling CEIP/Appraiser tasks restores Microsoft compatibility telemetry collection." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  1  Clear Delivery Optimization policy (remove DODownloadMode)" -ForegroundColor Yellow
        Write-Host "  2  Turn off PowerShell Script Block Logging policy" -ForegroundColor Yellow
        Write-Host "  3  LSA RunAsPPL: turn OFF (reboot required)" -ForegroundColor Yellow
        Write-Host "  4  LSA RunAsPPL: turn ON (reboot required)" -ForegroundColor Green
        Write-Host "  5  Re-enable Bastion-listed scheduled tasks" -ForegroundColor Yellow
        Write-Host "  6  Disable Bastion-listed scheduled tasks (Bastion-style)" -ForegroundColor Green
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3","4","5","6")
        switch ($c) {
            "0" { return }
            "1" {
                if ((Read-YesNo -Prompt "  Remove DODownloadMode policy value (Y/N)?") -eq "Y") {
                    try {
                        $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
                        if (Test-Path $key) {
                            Remove-ItemProperty -Path $key -Name DODownloadMode -Force -ErrorAction SilentlyContinue
                        }
                        Write-Status "DODownloadMode policy cleared (Windows default DO behavior returns)" "Applied"
                    } catch {
                        Write-Status ("DO clear failed: {0}" -f $_.Exception.Message) "Failed"
                    }
                }
                Wait-ForKey "Press any key to return to Policies and tasks..."
            }
            "2" {
                if ((Read-YesNo -Prompt "  Disable PowerShell Script Block Logging policy (Y/N)?") -eq "Y") {
                    try {
                        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
                        if (-not (Test-Path $path)) { New-Item $path -Force | Out-Null }
                        Set-ItemProperty $path -Name EnableScriptBlockLogging -Value 0 -ErrorAction Stop
                        Set-ItemProperty $path -Name EnableScriptBlockInvocationLogging -Value 0 -ErrorAction SilentlyContinue
                        Write-Status "Script Block Logging policy set to 0" "Applied"
                    } catch {
                        Write-Status ("PS auditing clear failed: {0}" -f $_.Exception.Message) "Failed"
                    }
                }
                Wait-ForKey "Press any key to return to Policies and tasks..."
            }
            "3" {
                Write-Host "  Disabling RunAsPPL makes some credential theft techniques easier." -ForegroundColor Yellow
                if ((Read-YesNo -Prompt "  Set RunAsPPL=0 and plan a reboot (Y/N)?") -eq "Y") {
                    try {
                        New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                        Write-Status "RunAsPPL=0 set. Reboot required for full effect." "Applied"
                    } catch {
                        Write-Status ("LSA off failed: {0}" -f $_.Exception.Message) "Failed"
                    }
                }
                Wait-ForKey "Press any key to return to Policies and tasks..."
            }
            "4" {
                if ((Read-YesNo -Prompt "  Set RunAsPPL=1 and plan a reboot (Y/N)?") -eq "Y") {
                    try {
                        New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                        Write-Status "RunAsPPL=1 set. Reboot required to enforce." "Applied"
                    } catch {
                        Write-Status ("LSA on failed: {0}" -f $_.Exception.Message) "Failed"
                    }
                }
                Wait-ForKey "Press any key to return to Policies and tasks..."
            }
            "5" {
                if ((Read-YesNo -Prompt "  Re-enable Bastion-listed scheduled tasks (Y/N)?") -eq "Y") {
                    foreach ($t in $script:BastionScheduledTaskPaths) {
                        $leaf = Split-Path $t -Leaf
                        try {
                            $task = Get-ScheduledTask -TaskPath (Split-Path $t -Parent) -TaskName $leaf -ErrorAction SilentlyContinue
                            if (-not $task) {
                                Write-Status ("Absent {0}" -f $leaf) "Already"
                                continue
                            }
                            Enable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
                            Write-Status ("Enabled {0}" -f $leaf) "Applied"
                        } catch {
                            Write-Status ("Task {0}: {1}" -f $leaf, $_.Exception.Message) "Warn"
                        }
                    }
                }
                Wait-ForKey "Press any key to return to Policies and tasks..."
            }
            "6" {
                if ((Read-YesNo -Prompt "  Disable Bastion-listed scheduled tasks (Y/N)?") -eq "Y") {
                    foreach ($t in $script:BastionScheduledTaskPaths) {
                        $leaf = Split-Path $t -Leaf
                        try {
                            $task = Get-ScheduledTask -TaskPath (Split-Path $t -Parent) -TaskName $leaf -ErrorAction SilentlyContinue
                            if (-not $task) {
                                Write-Status ("Absent {0}" -f $leaf) "Already"
                                continue
                            }
                            if ($task.State -eq "Disabled") {
                                Write-Status ("Already disabled {0}" -f $leaf) "Already"
                            } else {
                                Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
                                Write-Status ("Disabled {0}" -f $leaf) "Applied"
                            }
                        } catch {
                            Write-Status ("Task {0}: {1}" -f $leaf, $_.Exception.Message) "Warn"
                        }
                    }
                }
                Wait-ForKey "Press any key to return to Policies and tasks..."
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-SecurityMitigationsRecoveryMenu
#   Recovery hub 6. Snapshot of StrictHandle + LSA; dispatches to StrictHandle,
#   Defender NP/CFA, and Policies/tasks submenus for reverse or re-harden.
# -----------------------------------------------------------------------------
function Show-SecurityMitigationsRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "SECURITY MITIGATIONS RECOVERY"
        $sh = Get-BastionStrictHandleSystemStatus
        $lsa = $null
        try { $lsa = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL } catch {}
        Write-Host "  Snapshot" -ForegroundColor Cyan
        Write-Host ("    StrictHandle (system): {0}" -f $sh.StrictLabel) -ForegroundColor White
        Write-Host ("    LSA RunAsPPL:          {0}" -f $(if ($null -eq $lsa) { "(not set)" } elseif ($lsa -eq 1) { "ON" } else { $lsa })) -ForegroundColor White
        Write-Host "    Open a submenu for live detail and safe reverse / re-harden actions." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  1  StrictHandle / Exploit protection (games-safe reverse)" -ForegroundColor Yellow
        Write-Host "  2  Defender Network Protection and Controlled Folder Access" -ForegroundColor White
        Write-Host "  3  Policies and tasks (DO, PowerShell logging, LSA, CEIP tasks)" -ForegroundColor White
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3")
        switch ($c) {
            "0" { return }
            "1" { Show-StrictHandleRecoveryMenu }
            "2" { Show-DefenderRecoveryMenu }
            "3" { Show-PolicyTasksRecoveryMenu }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-RecoveryMenu
#   Main menu 9 entry. Six hubs (see file header). Prefer a specific hub when
#   the user knows what broke; full Undo remains partial by design.
#   Option 4 reuses Show-BrowserPolicyMenu (same as main menu 6).
# -----------------------------------------------------------------------------
function Show-RecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "RECOVERY / FIX"
        Write-AppliesWhen -Mode Now -Extra "Prefer a specific hub when you know what broke. Full Undo (1) is broader and still best-effort."
        Write-Host ""
        Write-Host "  1  Undo last Apply (tracked services, firewall groups, DNS snapshot, RDP prior)" -ForegroundColor White
        Write-Host "  2  Services (Print Spooler, high-risk stack, Xbox)" -ForegroundColor White
        Write-Host "  3  Network (remote access, LAN discovery, DNS DHCP / restore snapshot)" -ForegroundColor Cyan
        Write-Host "  4  Browser policies (per browser; Default reverts Bastion policies)" -ForegroundColor White
        Write-Host "  5  Apps and UI (Copilot, Widgets/Suggestions, Game Bar)" -ForegroundColor Green
        Write-Host "  6  Security mitigations (StrictHandle, Defender, LSA, policies/tasks)" -ForegroundColor Yellow
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Notes:" -ForegroundColor DarkGray
        Write-UxBullets -Items @(
            "Hubs show live status first, then offer reverse / re-harden actions"
            "Re-opening remote/LAN paths or services increases attack surface"
            "Appx bloat and OneDrive are not reinstallable here - System Restore or vendor installers"
        ) -ForegroundColor DarkGray
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3","4","5","6")
        switch ($c) {
            "0" { return }
            "1" { Invoke-UndoHardening }
            "2" { Show-ServicesRecoveryMenu }
            "3" { Show-NetworkRecoveryMenu }
            "4" { Show-BrowserPolicyMenu }
            "5" { Show-AppsUiRecoveryMenu }
            "6" { Show-SecurityMitigationsRecoveryMenu }
        }
    }
}
