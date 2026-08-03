# Bastion.Apply.ps1 - modular domain (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.
#
# Role in modular architecture:
#   Orchestration for Dry Run (preview), Security Audit (live posture), Apply (make
#   changes real), Quick Harden (safe preset then Apply), and System Restore Point
#   create/check flows. Calls helpers in Services, Dns, Harden, Programs, Browsers.
#
# Load-order position: 9 of 11 (after Harden, before Recovery).
#   Order: Init, Core, Config, Programs, Services, Browsers, Dns, Harden, Apply, Recovery, Menus.
#
# Dependencies on $script: state (non-exhaustive):
#   $script:Sections / QuickSections / Config.ScriptVersion
#   $script:FirewallGroups / HighRiskServiceList / XboxServiceList / BastionScheduledTaskPaths
#   $script:DnsProviderId / DnsProviders / SelectedApps / BrowserPolicyModes / BrowserEchLocks
#   $script:SuggestionRegistry / SkipSpoolerThisApply
#   $script:Stats / ApplyFailures / dryWould / dryAlready / drySkip (counters)
#   Undo via Save-UndoData after Apply (disabled services, firewall groups, DNS snapshot, RDP prior)

function Convert-RestorePointTime {
    <#
      Purpose:
        Normalize System Restore CreationTime (WMI string or DateTime) to [datetime] or $null.

      When called:
        Get-RestorePointStatus when enriching Get-ComputerRestorePoint results.

      Side effects:
        None (parse only).

      Undo implications:
        None.
    #>
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
    <#
      Purpose:
        Query System Restore points and flag recent (48h) or Bastion-named coverage.

      When called:
        Restore point menu, Confirm-RestorePointBeforeApply, Security Audit tooling row.

      Side effects:
        Get-ComputerRestorePoint (read). Does not create points.

      Undo implications:
        None. Absence of points is a safety warning, not a Bastion failure.
    #>
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
    <#
      Purpose:
        Interactive menu to view restore point status and create a named point.

      When called:
        Main menu restore point option (e.g. 13 / R). Immediate create on choice 1.

      Side effects:
        Console UI; New-BastionRestorePoint may create a real restore point.

      Undo implications:
        Creating a point is the safety net for later Apply; Bastion does not delete points.
    #>
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
    <#
      Purpose:
        Gate Apply / Quick Harden / DNS Apply: require recent restore coverage or explicit YES.

      When called:
        Invoke-ApplyHardening (unless SkipRestorePrompt), Invoke-QuickHardening,
        Invoke-BastionDnsSectionApply.

      Side effects:
        May call New-BastionRestorePoint; interactive prompts only otherwise.

      Undo implications:
        Does not change hardening state. Returning $false cancels the parent action.
    #>
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
    <#
      Purpose:
        Create a Checkpoint-Computer restore point with suggested or custom name.

      When called:
        Restore menu and pre-Apply confirmation flows.

      Side effects / Windows objects touched:
        System Restore: Checkpoint-Computer -RestorePointType MODIFY_SETTINGS.
        Requires System Protection enabled on OS drive.

      Undo implications:
        New point is the rollback vehicle via Windows System Restore UI, not Bastion undo JSON.
    #>
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
    <#
      Purpose:
        Preview what Apply would change for currently enabled sections; never mutates Windows.

      When called:
        Main menu Dry Run (option 1). Read-only queries + console report.

      Side effects:
        Sets $script:dryWould / dryAlready / drySkip counters for summary only.
        Nested Show-DryItem is local to this function.

      Undo implications:
        None (no changes). User must run Apply (8) or Quick Harden (7) to execute.

      Honesty:
        - ExploitProtection path reports StrictHandle and WoW exception counts; prints guidance
        - DNS notes VPN may override; snapshots only happen on real Apply
        - BloatApps / OneDrive hard-to-reverse called out in verdict text
        - Programs lists winget catalog installs only
        - Soft suggestion keys do not force "Would change"
    #>
    Clear-BastionScreen
    Write-Header "DRY RUN (NO CHANGES)"
    Write-Host "  Preview only - nothing is changed on Windows." -ForegroundColor Cyan
    Write-Host "  Based on current section toggles / DNS preference. To make changes: main menu 8 (or 7 Quick Harden)." -ForegroundColor DarkGray
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
            $openGroups = @()
            foreach ($g in $script:FirewallGroups) {
                $gst = Get-BastionFirewallGroupInboundStatus -DisplayGroup $g
                if ($gst.Open) { $openGroups += $g }
            }
            if ($fwOk -and $openGroups.Count -eq 0) {
                Show-DryItem "Firewall" "Already OK" "Profiles enabled, Inbound=Block; discovery/RDP/WinRM/mDNS groups locked"
            } elseif ($fwOk) {
                Show-DryItem "Firewall" "Would change" ("Profiles OK; would lock open group(s): {0}" -f ($openGroups -join ", "))
            } else {
                Show-DryItem "Firewall" "Would change" "Set profiles Enabled + Inbound=Block; disable discovery/RDP/WinRM/mDNS inbound groups if enabled"
            }
        } catch { Show-DryItem "Firewall" "Would change" "Could not read profiles; Apply would set Inbound=Block" }
        # RDP triad (informational): firewall group vs OS host switch vs TermService
        try {
            $rdg = Get-BastionFirewallGroupInboundStatus -DisplayGroup "Remote Desktop"
            $rdp = Get-BastionRemoteDesktopSystemStatus
            Show-DryItem "RDP triad (live)" "Already OK" ("Firewall group={0}; system={1}; TermService={2}/{3}" -f `
                $rdg.Label, $rdp.SystemLabel, $rdp.ServiceStatus, $rdp.ServiceStartType)
        } catch {
            Show-DryItem "RDP triad (live)" "Skipped" "Could not query RDP host status"
        }
    }

    if (-not $script:Sections["RdpHostLock"]) {
        Show-DryItem "RdpHostLock" "Skipped" "Section off (optional OS RDP host deny; enable under option 4 if needed)"
    } else {
        try {
            $rdp = Get-BastionRemoteDesktopSystemStatus
            if ($rdp.SystemLabel -eq "DENIED" -and $rdp.ServiceStartType -ne "Automatic") {
                Show-DryItem "RdpHostLock" "Already OK" "System RDP denied and TermService not Automatic"
            } else {
                Show-DryItem "RdpHostLock" "Would change" "Deny system RDP (fDenyTSConnections=1) and set TermService Manual/stopped"
            }
        } catch {
            Show-DryItem "RdpHostLock" "Would change" "Deny system RDP host + TermService Manual"
        }
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
                Show-DryItem "DNS" "Would change" ("Snapshot prior DNS (encrypted), then set {0} on: {1}; already OK: {2}" -f $prov.DisplayName, ($need -join ", "), ($ok -join ", "))
            } else {
                Show-DryItem "DNS" "Would change" ("Snapshot prior DNS (encrypted), then set eligible adapters to {0} ({1})" -f $prov.DisplayName, $label)
            }
        } catch {
            Show-DryItem "DNS" "Would change" ("Snapshot prior DNS if needed; set eligible adapters to {0}" -f $prov.DisplayName)
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
            $strictOn = $false
            try {
                $strictOn = ($mit.StrictHandle.Enable -eq "ON" -or "$($mit.StrictHandle.Enable)" -eq "ON" -or $mit.StrictHandle.Enable -eq $true)
            } catch {}
            $wowEx = @(Get-BastionStrictHandleExceptionPaths)
            $wowNote = if ($wowEx.Count -gt 0) {
                ("StrictHandle exceptions for {0} Wow*.exe path(s)" -f $wowEx.Count)
            } else {
                "no Wow*.exe found yet (exception applied when present at Apply)"
            }
            if ($depOn -and $sehOn -and $strictOn) {
                Show-DryItem "ExploitProtection" "Already OK" ("DEP/SEHOP/StrictHandle system ON; {0}" -f $wowNote)
            } elseif ($depOn -and $sehOn) {
                Show-DryItem "ExploitProtection" "Would change" ("Enable system StrictHandle + refresh WoW exceptions ({0})" -f $wowNote)
            } else {
                Show-DryItem "ExploitProtection" "Would change" ("Enable DEP, SEHOP, BottomUp, HighEntropy, StrictHandle; {0}" -f $wowNote)
            }
            Write-BastionStrictHandleGuidance -Style Inline
        } catch {
            Show-DryItem "ExploitProtection" "Would change" "Apply mild mitigations + known StrictHandle exceptions (could not query ProcessMitigation)"
            Write-BastionStrictHandleGuidance -Style Inline
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
        $taskPaths = @($script:BastionScheduledTaskPaths)
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
        $dvrNote = if (Test-BastionGameDvrSilenced) { "Game DVR already silenced" } else { "will silence Game DVR / ms-gamingoverlay prompts" }
        if ($need.Count -eq 0) {
            Show-DryItem "XboxGaming" "Already OK" ("Xbox services absent or already disabled; {0}" -f $dvrNote)
        } else {
            Show-DryItem "XboxGaming" "Would change" ("Disable: {0}; {1}" -f ($need -join ", "), $dvrNote)
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

function Show-ExploitProtectionGameNotice {
    <#
      Purpose:
        Surface StrictHandle / games honesty before Apply (wrapper over shared guidance).

      When called:
        Show-ApplyPreview when ExploitProtection section is enabled.

      Side effects:
        Console only (Inline or Notice style).

      Honesty (StrictHandle):
        Pre-Apply notice so users are not surprised by game breakage. WoW is example only.
    #>
    # Pre-Apply honesty: shared guidance (WoW is an example; others may break until reported).
    param([switch]$Compact)
    if ($Compact) {
        Write-BastionStrictHandleGuidance -Style Inline
    } else {
        Write-BastionStrictHandleGuidance -Style Notice
    }
}

function Show-ApplyPreview {
    <#
      Purpose:
        List enabled sections with short risk/intent annotations before YES confirm.

      When called:
        Start of Invoke-ApplyHardening (after sections non-empty check).

      Side effects:
        Console only; may call Show-ExploitProtectionGameNotice.

      Undo implications:
        None (preview).
    #>
    Write-Host ""
    Write-Host "  Enabled sections:" -ForegroundColor Cyan
    foreach ($k in $script:Sections.Keys) {
        if (-not $script:Sections[$k]) { continue }
        $extra = switch ($k) {
            "BrowserPolicies" { (" [{0}]" -f (Get-BrowserPolicyModesSummary)) }
            "DNS" {
                $p = Get-BastionDnsProvider
                if ($script:DnsProviderId -eq "None" -or -not $p.Primary) { " [leave unchanged]" }
                else { (" -> {0} ({1}); prior DNS snapshotted encrypted" -f $p.DisplayName, $p.Primary) }
            }
            "HighRiskServices" { " [includes Print Spooler]" }
            "Firewall" { " [locks remote/LAN groups; Recovery > 3 Network to re-open]" }
            "RdpHostLock" { " [opt-in: deny fDenyTSConnections + TermService Manual]" }
            "Programs" {
                if ($script:SelectedApps.Count) { (" -> {0}" -f ($script:SelectedApps -join ", ")) } else { " -> none" }
            }
            "LSAProtection" { " [reboot required]" }
            "BloatApps" { " [hard to reverse]" }
            "ExploitProtection" { " [StrictHandle: games notice below]" }
            default { "" }
        }
        Write-Host ("    * {0}{1}" -f $k, $extra) -ForegroundColor White
    }
    if ($script:Sections["ExploitProtection"]) {
        Show-ExploitProtectionGameNotice
    } else {
        Write-Host ""
    }
}

function Write-AuditRow {
    <#
      Purpose:
        Format one Security Audit line (Name, Status, optional Detail/Hint, color by Level).

      When called:
        Invoke-SelfTest via nested Add-Good/Warn/Bad helpers.

      Side effects:
        Console only.
    #>
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
    <#
      Purpose:
        Print an Audit section header separator.

      When called:
        Invoke-SelfTest between category blocks.
    #>
    Write-Host ""
    Write-Host ("  -- {0} --" -f $Title) -ForegroundColor Cyan
}

function Invoke-SelfTest {
    <#
      Purpose:
        Live, read-only security posture audit independent of section toggles; score Good/Warn/Bad.

      When called:
        Main menu Audit; optional post-Apply offer. Never changes Windows.

      Side effects:
        Queries firewall, services, Defender, DNS adapters, ports, browsers, restore points, winget.
        Counters $script:_ag / _aw / _ab for score only.

      Undo implications:
        None.

      Honesty:
        - Good does not mean "Bastion applied it" (could be default or other tool)
        - DNS leave-unchanged is Good by user choice, not hardened DNS
        - StrictHandle/DEP sample is partial; full games notice lives under ExploitProtection Apply
        - ECH never treated as default; Warn when Strict/ECH live or intended
        - winget preflight is tooling readiness, not an install action
    #>
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

    try {
        $rdg = Get-BastionFirewallGroupInboundStatus -DisplayGroup "Remote Desktop"
        $rdp = Get-BastionRemoteDesktopSystemStatus
        $detail = ("group={0}; system={1}; TermService={2}/{3}" -f $rdg.Label, $rdp.SystemLabel, $rdp.ServiceStatus, $rdp.ServiceStartType)
        if ($rdg.Label -eq "LOCKED" -and $rdp.SystemLabel -eq "DENIED") {
            Add-Good "RDP triad" "Firewall locked + system denied" $detail "Full host needs OPEN group + ALLOWED + TermService"
        } elseif ($rdg.Label -eq "LOCKED") {
            Add-Good "RDP triad" "Firewall group locked" $detail "System host may still be ALLOWED; optional RdpHostLock section"
        } elseif ($rdp.SystemLabel -eq "ALLOWED" -and $rdg.Label -eq "OPEN") {
            Add-Warn "RDP triad" "Host path open" $detail "Network Recovery or Firewall Apply"
        } else {
            Add-Warn "RDP triad" "Mixed" $detail "Recovery > 3 Network > Remote access"
        }
    } catch { Add-Warn "RDP triad" "Query failed" }

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
        $taskPaths = @($script:BastionScheduledTaskPaths)
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

function Invoke-QuickHardening {
    <#
      Purpose:
        Guided preset: enable QuickSections, optional DNS + Spooler keep, then Apply with confirms.

      When called:
        Main menu Quick Harden (option 7). Ends in Invoke-ApplyHardening -SkipRestorePrompt
        only after restore-point and YES gates in this function.

      Side effects:
        Mutates $script:Sections, DnsProviderId, SkipSpoolerThisApply; Save-BastionConfig;
        then full Apply side effects. Finally block clears SkipSpoolerThisApply.

      Undo implications:
        Same as Apply (Bastion-LastApply undo + System Restore). Spooler skip means Spooler
        may remain enabled even when HighRiskServices runs.
    #>
    Clear-BastionScreen
    Write-Header "QUICK HARDEN"
    Write-AppliesWhen -Mode Now -Extra "This guided path sets a safe preset and then runs Apply in this flow (you will still confirm YES)."
    Write-Host "  BloatApps / Xbox stay off unless you enable them later under sections (4)." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Preset sections:" -ForegroundColor White
    foreach ($s in $script:QuickSections) { Write-Host ("    - {0}" -f $s) -ForegroundColor Green }
    Write-Host ""
    Write-Host "  Heads-up:" -ForegroundColor Yellow
    Write-UxBullets -Items @(
        "HighRiskServices can disable Print Spooler (printing stops until Recovery > 2)"
        "Firewall locks remote/LAN discovery groups (re-open under Recovery > 3 Network)"
    ) -ForegroundColor Yellow
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
    <#
      Purpose:
        Execute enabled sections for real: firewall, services, SMBv1, OneDrive, Xbox, LSA,
        tasks, DO, DNS+DoH, RdpHostLock, Defender/CFA, PS auditing, ExploitProtection
        (including system StrictHandle + exceptions), browser policies, bloat Appx,
        suggestions, Copilot/M365, catalog Programs. Write undo + config; optional audit.

      When called:
        Main menu Apply (8); Quick Harden after YES; not Dry Run.

      Side effects / Windows objects touched (by enabled section):
        - Firewall profiles and inbound groups; high-risk/Xbox services
        - Optional Windows features (SMB1); OneDriveSetup uninstall
        - Registry: LSA RunAsPPL, DO, PS ScriptBlockLogging, Terminal Server, suggestions
        - Scheduled tasks disabled; Defender NP/CFA; Process mitigations system + per-EXE
        - DNS client addresses + DoH (DohFlags=17 path); Appx/provisioned removals
        - Browser policy files; winget installs; Bastion undo + config files

      Undo implications:
        Save-UndoData records DisabledServices, FirewallGroups, DnsSnapshot (DPAPI),
        RdpHostPrior, ProgramsInstalledList, browser modes, sections run.
        Recovery hubs reverse many items; BloatApps/OneDrive/LSA are harder or reboot-bound.
        System Restore point (if created) is the broadest OS rollback.

      Honesty:
        - StrictHandle ON system-wide with known EXE exceptions only; other apps may break
        - DoH Flags 17 = Settings Encrypted compatibility; VPN may override DNS
        - Programs: catalog-only winget; never --ignore-security-hash
        - ECH only when saved Yes under Strict (never assumed from Strict alone)
        - BloatApps hard to reverse; Copilot section does not remove Office Click-to-Run suite
    #>
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
        HasDnsSnapshot = $false
        RdpHostLocked = $false
        RdpHostPrior = $null
    }
    foreach ($bk in $script:BrowserPolicyModes.Keys) {
        $undoTrack.BrowserPolicyModes[$bk] = [string]$script:BrowserPolicyModes[$bk]
    }
    foreach ($ek in $script:BrowserEchLocks.Keys) {
        $undoTrack.BrowserEchLocks[$ek] = [bool]$script:BrowserEchLocks[$ek]
    }

    Clear-BastionScreen
    Write-Header "APPLY HARDENING"
    Write-AppliesWhen -Mode Now -Extra "This is the main 'make it real' step for sections (4), program queue (5), and DNS preference (D) when DNS is enabled."
    Write-Host ""
    foreach ($k in $script:Sections.Keys) {
        if ($script:Sections[$k]) { $undoTrack.SectionsRun += $k }
    }
    if ($undoTrack.SectionsRun.Count -eq 0) {
        Write-Host "  No sections enabled. Turn some on under main menu 4, then return to 8." -ForegroundColor Yellow
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

    # --- Firewall: profiles Inbound=Block; disable discovery/RDP/WinRM/mDNS inbound groups ---
    # Undo: FirewallGroups list for Recovery Network re-open. Does not change OS RDP host alone.
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
        # Games still open ms-gamingoverlay when Game DVR is on but Game Bar was removed/disabled.
        [void](Disable-BastionGameDvrOverlay)
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
        foreach ($t in $script:BastionScheduledTaskPaths) {
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

    # --- DNS: eligible adapters only; snapshot prior servers/DoH (DPAPI on save); set IPs + DoH ---
    # Honesty: DohFlags=17 path in Bastion.Dns; Settings Encrypted = wire DoH, not Bastion DPAPI.
    # VPN may still override while connected. Undo: Restore-BastionDnsFromSnapshot.
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
            } else {
                # Snapshot prior DNS once before any change (encrypted when Save-UndoData runs).
                $needSnap = $false
                foreach ($a in $adapters) {
                    try {
                        if (-not (Test-AdapterDnsMatchesProvider -InterfaceIndex $a.ifIndex)) { $needSnap = $true; break }
                    } catch { $needSnap = $true; break }
                }
                if ($needSnap -and -not $undoTrack.DnsSnapshot) {
                    $undoTrack.DnsSnapshot = Get-BastionDnsSnapshot
                    Write-Status ("Captured DNS snapshot for {0} eligible adapter(s) (stored encrypted)" -f @($undoTrack.DnsSnapshot.Adapters).Count) "Applied"
                }
            }
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
                    }
                } catch {
                    Write-Status ("DNS fail on {0}: {1}" -f $a.Name, $_.Exception.Message) "Failed"
                }
            }
            try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
            Write-Host "  DNS/DoH were applied during this run. Re-open Settings if the Encrypted badge was already on screen." -ForegroundColor DarkGray
            Write-Host "  Bastion DPAPI snapshot encryption is separate (undo file on disk)." -ForegroundColor DarkGray
        }
    }

    if ($script:Sections["RdpHostLock"]) {
        Write-Host "  [RdpHostLock]" -ForegroundColor Cyan
        try {
            $prior = Get-BastionRemoteDesktopSystemStatus
            $undoTrack.RdpHostPrior = @{
                fDenyTSConnections = $prior.fDenyTSConnections
                ServiceStartType   = $prior.ServiceStartType
                ServiceStatus      = $prior.ServiceStatus
            }
            if ($prior.SystemLabel -eq "DENIED" -and $prior.ServiceStartType -ne "Automatic") {
                Write-Status "System RDP already denied / TermService not Automatic" "Already"
                $undoTrack.RdpHostLocked = $true
            } else {
                $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
                Set-ItemProperty -Path $path -Name fDenyTSConnections -Value 1 -Type DWord -Force -ErrorAction Stop
                Write-Status "fDenyTSConnections=1 (system denies Remote Desktop)" "Applied"
                try {
                    Stop-Service -Name TermService -Force -ErrorAction SilentlyContinue
                    Set-Service -Name TermService -StartupType Manual -ErrorAction Stop
                    Write-Status "TermService: stopped and Manual" "Applied"
                } catch {
                    Write-Status ("TermService: {0}" -f $_.Exception.Message) "Warn"
                }
                $undoTrack.RdpHostLocked = $true
            }
        } catch {
            Write-Status ("RdpHostLock failed: {0}" -f $_.Exception.Message) "Failed"
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

    # --- ExploitProtection: mild system mitigations + system StrictHandle ON ---
    # Honesty (StrictHandle): per-app OFF only for discovered/config exception EXEs (issue #18).
    # Other software may break until Recovery > 6 or a shipped exception. Reboot may be needed
    # for some mitigation changes to fully take effect depending on Windows build.
    if ($script:Sections["ExploitProtection"]) {
        Write-Host "  [ExploitProtection]" -ForegroundColor Cyan
        Write-Host "    StrictHandle ON system-wide. Known exception EXEs (e.g. discovered Wow*.exe) get per-app OFF." -ForegroundColor DarkGray
        try {
            $already = $false
            try {
                $mit = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
                $depOn = ($mit.DEP.Enable -eq "ON" -or "$($mit.DEP.Enable)" -eq "ON")
                $strictOn = $false
                try {
                    $strictOn = ($mit.StrictHandle.Enable -eq "ON" -or "$($mit.StrictHandle.Enable)" -eq "ON")
                } catch {}
                if ($depOn -and $strictOn) { $already = $true }
            } catch {}
            # System-wide StrictHandle; per-exe OFF for discovered exception paths (issue #18).
            Set-ProcessMitigation -System -Enable DEP,SEHOP,BottomUp,HighEntropy,StrictHandle -ErrorAction Stop
            if ($already) {
                Write-Status "Mild system mitigations already present (re-applied; StrictHandle ON system-wide)" "Already"
            } else {
                Write-Status "Mild system mitigations applied (DEP/SEHOP/ASLR + StrictHandle system-wide)" "Applied"
            }
            [void](Set-BastionStrictHandleExceptions)
            Write-BastionStrictHandleGuidance -Style Inline
        } catch {
            Write-Status ("Exploit Protection failed: {0}. Next step: Windows Security > App and browser control, or Recovery > 6." -f $_.Exception.Message) "Failed"
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
        # If Xbox Gaming Overlay was in scope or is now absent, silence ms-gamingoverlay prompts.
        $overlayGone = $true
        try {
            $overlayGone = -not [bool](Get-AppxPackage -Name "Microsoft.XboxGamingOverlay*" -ErrorAction SilentlyContinue)
        } catch {}
        $removedOverlay = @($targets | Where-Object { $_.DisplayName -match 'Xbox Gaming Overlay' }).Count -gt 0
        if ($overlayGone -or $removedOverlay) {
            [void](Disable-BastionGameDvrOverlay)
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

    # --- Programs: catalog-only winget installs (Install-BastionCatalogApp gates) ---
    # Honesty: trusted source preflight + exact WingetId; never --ignore-security-hash.
    # Undo list is informational; uninstall via Programs menu, not full automatic reverse.
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
