# Bastion.Services.ps1 - modular domain (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.
#
# Role in modular architecture:
#   Service enable/disable helpers for high-risk and Xbox service lists, plus Recovery
#   catalog metadata used by Recovery menus. Pure helpers; no main menu loop lives here.
#
# Load-order position: 5 of 11 (after Programs, before Browsers).
#   Order: Init, Core, Config, Programs, Services, Browsers, Dns, Harden, Apply, Recovery, Menus.
#
# Dependencies on $script: state (set in Init / mutated by Apply and Quick Harden):
#   $script:HighRiskServiceList   - names Apply may disable when HighRiskServices is on
#   $script:SkipSpoolerThisApply  - one-shot Quick Harden opt-out so Spooler stays printable
#   $script:ServiceRecoveryCatalog - Name/Group/Display/PreferStart/Why for Recovery UI
#   $script:Stats                 - ServicesDisabled counter during Apply (Write-Status paths)
#   $script:XboxServiceList       - used from Apply/Audit, not directly in this file

function Get-HighRiskServicesForApply {
    <#
      Purpose:
        Return the high-risk service name list for the current Apply run, optionally
        without Spooler when the user chose to keep printing during Quick Harden.

      When called:
        Apply (HighRiskServices section) and Dry Run (to preview what would disable).
        Not used by Recovery (Recovery enables by catalog entry, not this filter).

      Side effects:
        None. Read-only filter over $script:HighRiskServiceList.

      Undo implications:
        None here. Disable-BastionService records original start type into Apply undo
        when a service is actually disabled.

      Honesty:
        Skipping Spooler is a usability trade-off, not "already hardened." Print Spooler
        remains a known attack surface (PrintNightmare-class issues) if left enabled.
    #>
    # Spooler can be skipped for one Apply when Quick Harden user opts to keep printing.
    $list = @($script:HighRiskServiceList)
    if ($script:SkipSpoolerThisApply) {
        $list = @($list | Where-Object { $_ -ne "Spooler" })
    }
    return $list
}

function Get-ServiceState([string]$Name) {
    <#
      Purpose:
        Safe wrapper around Get-Service: return the ServiceController or $null if missing.

      When called:
        Dry Run, Apply, Audit, Recovery service rows, and any disable/enable path.

      Side effects:
        None (query only). Does not start or stop services.

      Undo implications:
        None.
    #>
    try { return Get-Service -Name $Name -ErrorAction Stop } catch { return $null }
}

function Disable-BastionService {
    <#
      Purpose:
        Stop a Windows service if running, set StartupType to Disabled, and return
        an object with Name + Original start type for undo tracking.

      When called:
        Apply (HighRiskServices, XboxGaming). Not Dry Run (Dry Run only reads state).

      Side effects / Windows objects touched:
        - Service Control Manager: Stop-Service -Force when not already Stopped
        - Service start type set to Disabled via Set-Service
        - Increments $script:Stats.ServicesDisabled on success
        - Console + log via Write-Status

      Undo implications:
        Returns @{ Name; Original } for Apply undo (Bastion-LastApply / Recovery service
        restore). If stop fails but disable succeeds, process may keep running until reboot;
        undo still restores the recorded start type, not a guaranteed running state.

      Honesty:
        "Disabled" means start type only when stop failed. User may need reboot for a
        stuck process. Absent services report Already (not an error).
    #>
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

function Get-BastionServiceCatalogEntry {
    <#
      Purpose:
        Look up Recovery catalog metadata for a service name (group, display, preferred
        start type, short why text). Fallback object if not in catalog.

      When called:
        Recovery service UI and Enable-BastionService (default PreferStart).

      Side effects:
        None. Reads $script:ServiceRecoveryCatalog only.

      Undo implications:
        None. PreferStart guides re-enable defaults; it is not a snapshot of pre-Apply state.
    #>
    param([Parameter(Mandatory)][string]$Name)
    foreach ($e in $script:ServiceRecoveryCatalog) {
        if ($e.Name -eq $Name) { return $e }
    }
    return @{ Name = $Name; Group = "Other"; Display = $Name; PreferStart = "Manual"; Why = "" }
}

function Get-BastionServiceStatusRow {
    <#
      Purpose:
        Build a display row for Recovery/status menus: present?, Status, StartType,
        hardened (Disabled), and a short Label (ABSENT/DISABLED/RUNNING/STOPPED).

      When called:
        Recovery service hubs (read-only posture for each catalog service).

      Side effects:
        None beyond Get-Service query.

      Undo implications:
        None. "Hardened" here means StartType is Disabled only; it is not a claim that
        Bastion last applied the change.
    #>
    param([Parameter(Mandatory)][string]$Name)
    $meta = Get-BastionServiceCatalogEntry -Name $Name
    $svc = Get-ServiceState $Name
    if (-not $svc) {
        return [PSCustomObject]@{
            Name = $Name; Display = $meta.Display; Group = $meta.Group; Why = $meta.Why
            Present = $false; Status = "Absent"; StartType = "Absent"; PreferStart = $meta.PreferStart
            Hardened = $false; Label = "ABSENT"
        }
    }
    $st = [string]$svc.Status
    $start = [string]$svc.StartType
    $hardened = ($start -eq "Disabled")
    $label = if ($hardened) { "DISABLED" } elseif ($st -eq "Running") { "RUNNING" } else { "STOPPED" }
    return [PSCustomObject]@{
        Name = $Name; Display = $meta.Display; Group = $meta.Group; Why = $meta.Why
        Present = $true; Status = $st; StartType = $start; PreferStart = $meta.PreferStart
        Hardened = $hardened; Label = $label
    }
}

function Enable-BastionService {
    <#
      Purpose:
        Set a service StartupType (default from catalog PreferStart) and start it unless
        the requested type is Disabled.

      When called:
        Recovery (re-enable Spooler, high-risk services, Xbox services, etc.).
        Not called by Dry Run or main Apply (Apply only disables).

      Side effects / Windows objects touched:
        - Set-Service StartupType (Automatic / Manual / Disabled)
        - Start-Service when StartupType is not Disabled
        - Log line via Write-Log -NoConsole

      Undo implications:
        This is the reverse path for user-driven recovery. It does not rewrite Bastion
        undo files. PreferStart may differ from the original type captured at Apply time;
        Recovery may also restore from undo DisabledServices when that data exists.

      Honesty:
        Start failure after type change leaves start type applied but service not running;
        user is pointed at services.msc. Absent service is Already, not Failed.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$StartupType = ""
    )
    $meta = Get-BastionServiceCatalogEntry -Name $Name
    if ([string]::IsNullOrWhiteSpace($StartupType)) { $StartupType = [string]$meta.PreferStart }
    if ($StartupType -notin @("Automatic","Manual","Disabled")) { $StartupType = "Manual" }
    $svc = Get-ServiceState $Name
    if (-not $svc) {
        Write-Status ("{0} not installed on this PC" -f $Name) "Already"
        return $false
    }
    try {
        Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
        if ($StartupType -ne "Disabled") {
            try {
                Start-Service -Name $Name -ErrorAction Stop
                Write-Status ("{0}: {1}, running ({2})" -f $Name, $StartupType, $meta.Display) "Applied"
            } catch {
                Write-Status ("{0}: start type {1}; start failed: {2}. Next step: services.msc." -f $Name, $StartupType, $_.Exception.Message) "Warn"
            }
        } else {
            Write-Status ("{0}: Disabled" -f $Name) "Applied"
        }
        Write-Log ("Enable-BastionService name={0} start={1}" -f $Name, $StartupType) -NoConsole
        return $true
    } catch {
        Write-Status ("Failed to configure {0}: {1}. Next step: services.msc -> {0}." -f $Name, $_.Exception.Message) "Failed"
        return $false
    }
}

function Enable-PrintSpooler {
    <#
      Purpose:
        Interactive shortcut: confirm, then set Spooler to Automatic and start it.

      When called:
        Recovery menus (printing restore). Immediate apply with Y/N; no main menu 8.

      Side effects / Windows objects touched:
        - Spooler service: StartupType Automatic, Start-Service
        - Wait-ForKey after result

      Undo implications:
        Reverses HighRiskServices Spooler disable. Does not edit Bastion undo JSON.

      Honesty:
        Restoring Spooler restores print capability and the Spooler attack surface.
        This is intentional for home/workstations that must print.
    #>
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
