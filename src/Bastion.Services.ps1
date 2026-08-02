# Bastion.Services.ps1 - modular domain (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.

function Get-HighRiskServicesForApply {
    # Spooler can be skipped for one Apply when Quick Harden user opts to keep printing.
    $list = @($script:HighRiskServiceList)
    if ($script:SkipSpoolerThisApply) {
        $list = @($list | Where-Object { $_ -ne "Spooler" })
    }
    return $list
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

function Get-BastionServiceCatalogEntry {
    param([Parameter(Mandatory)][string]$Name)
    foreach ($e in $script:ServiceRecoveryCatalog) {
        if ($e.Name -eq $Name) { return $e }
    }
    return @{ Name = $Name; Group = "Other"; Display = $Name; PreferStart = "Manual"; Why = "" }
}

function Get-BastionServiceStatusRow {
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
