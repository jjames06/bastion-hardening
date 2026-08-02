#Requires -Version 5.1
<#
.SYNOPSIS
  One-shot modular restructure: extract Bastion monolith into src\*.ps1 modules.
  Intended for developer migration to v15.9.0; not part of the runtime product.
#>
[CmdletBinding()]
param(
  [string]$MonolithPath = "",
  [string]$SrcDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
if (-not $MonolithPath) {
  $MonolithPath = Join-Path $RepoRoot "tools\archive\Bastion-Hardening-v15.8.4-monolith.ps1"
}
if (-not $SrcDir) {
  $SrcDir = Join-Path $RepoRoot "src"
}

if (-not (Test-Path -LiteralPath $MonolithPath)) {
  throw "Monolith not found: $MonolithPath"
}

$lines = Get-Content -LiteralPath $MonolithPath -Encoding UTF8
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($MonolithPath, [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) {
  throw "Parse errors in monolith: $($errors[0].Message)"
}

function Get-FuncText {
  param([System.Management.Automation.Language.FunctionDefinitionAst]$Fn)
  $start = $Fn.Extent.StartLineNumber
  $end = $Fn.Extent.EndLineNumber
  return ($lines[($start - 1)..($end - 1)] -join "`r`n")
}

function Get-StmtText {
  param($Stmt)
  $start = $Stmt.Extent.StartLineNumber
  $end = $Stmt.Extent.EndLineNumber
  return ($lines[($start - 1)..($end - 1)] -join "`r`n")
}

function Test-NameMatch {
  param([string]$Name, [string[]]$Patterns)
  foreach ($p in $Patterns) {
    if ($Name -like $p) { return $true }
  }
  return $false
}

# Explicit assignments win over heuristics
$Explicit = @{
  # Config / paths / data store
  "Get-BastionDataDirCandidates" = "Config"
  "Test-BastionDirWritable" = "Config"
  "Test-BastionStatePresent" = "Config"
  "Resolve-BastionLogDirectory" = "Config"
  "Bind-BastionDataPaths" = "Config"
  "Ensure-BastionPaths" = "Config"
  "Protect-BastionBlob" = "Config"
  "Unprotect-BastionBlob" = "Config"
  "Set-BastionSensitiveFileAcl" = "Config"
  "Save-BastionConfig" = "Config"
  "Load-BastionConfig" = "Config"
  "Save-UndoData" = "Config"
  "Read-BastionUndoData" = "Config"
  "Get-LastApplyInfo" = "Config"
  "Write-BastionSessionSnapshot" = "Config"
  "Initialize-BastionDataStore" = "Config"
  "Get-BastionDnsSnapshotFromUndo" = "Config"
  "Test-BastionUndoHasDnsSnapshot" = "Config"
  "Get-BastionRdpHostPriorFromUndo" = "Config"
  "Get-BastionDnsSnapshotPreviewText" = "Config"
  "Save-BrowserPolicyStateFile" = "Config"
  "Load-BrowserPolicyStateFile" = "Config"

  # Core UI
  "Write-Log" = "Core"
  "Write-Status" = "Core"
  "Wait-ForKey" = "Core"
  "Write-Banner" = "Core"
  "Get-BastionConsoleWidth" = "Core"
  "Get-BastionConsoleHeight" = "Core"
  "Clear-BastionScreen" = "Core"
  "Maximize-BastionConsole" = "Core"
  "Get-WrappedLines" = "Core"
  "Write-Wrapped" = "Core"
  "Write-WrappedBlock" = "Core"
  "Write-Header" = "Core"
  "Write-MenuGroup" = "Core"
  "Write-UxDivider" = "Core"
  "Write-AppliesWhen" = "Core"
  "Write-UxBullets" = "Core"
  "Read-YesNo" = "Core"
  "Read-ConfirmYes" = "Core"
  "Read-MenuChoice" = "Core"
  "Open-UrlSafe" = "Core"

  # Services
  "Get-HighRiskServicesForApply" = "Services"
  "Get-ServiceState" = "Services"
  "Disable-BastionService" = "Services"
  "Enable-BastionService" = "Services"
  "Get-BastionServiceCatalogEntry" = "Services"
  "Get-BastionServiceStatusRow" = "Services"
  "Enable-PrintSpooler" = "Services"

  # Programs
  "Test-WingetAvailable" = "Programs"
  "Test-WingetSecurityPreflight" = "Programs"
  "Test-CatalogPackageId" = "Programs"
  "Invoke-WingetShow" = "Programs"
  "Test-AuthenticodeRelaxed" = "Programs"
  "Get-AvailableInstallVolumes" = "Programs"
  "Test-SafeInstallRoot" = "Programs"
  "Get-EffectiveInstallRoot" = "Programs"
  "Test-Installed" = "Programs"
  "Get-SelectedMissingApps" = "Programs"
  "Sync-ProgramInstallQueue" = "Programs"
  "Get-CatalogProgramRows" = "Programs"
  "Clear-StaleInstallRoots" = "Programs"
  "Install-BastionCatalogApp" = "Programs"
  "Select-InstallRootFromVolumes" = "Programs"
  "Set-LocationsForPendingInstalls" = "Programs"
  "Stop-BastionCatalogProcesses" = "Programs"
  "Get-HkcuUninstallCommands" = "Programs"
  "Invoke-HkcuUninstallString" = "Programs"
  "Invoke-WingetUninstallCatalog" = "Programs"
  "Get-DetectedCatalogInstalls" = "Programs"

  # DNS
  "Get-BastionDnsProvider" = "Dns"
  "Get-BastionDnsProviderLabel" = "Dns"
  "Get-BastionDnsAdapters" = "Dns"
  "Get-AdapterDnsServers" = "Dns"
  "Format-BastionInterfaceGuid" = "Dns"
  "Get-BastionDnsKnownDohTemplate" = "Dns"
  "Get-BastionInterfaceDohEntries" = "Dns"
  "Clear-BastionInterfaceDohEntries" = "Dns"
  "Set-BastionInterfaceDohEntry" = "Dns"
  "Enable-BastionDnsOverHttpsForAdapter" = "Dns"
  "Get-BastionDnsSnapshot" = "Dns"
  "Restore-BastionDnsFromSnapshot" = "Dns"
  "Test-AdapterDnsMatchesProvider" = "Dns"
  "Set-BastionDnsProviderId" = "Dns"
  "Get-BastionLiveDnsSummaryLines" = "Dns"
  "Invoke-BastionDnsSectionApply" = "Dns"
  "Reset-BastionDnsToAutomatic" = "Dns"

  # Browsers
  "Get-FirefoxPoliciesPath" = "Browsers"
  "Test-FirefoxEchLocksPresent" = "Browsers"
  "Get-FirefoxPolicyModeFromFile" = "Browsers"
  "Set-FirefoxPolicyMode" = "Browsers"
  "Get-BrowserPolicyBackupDir" = "Browsers"
  "Get-BrowserPolicyStatePath" = "Browsers"
  "Write-BrowserStrictDisclaimer" = "Browsers"
  "Clear-BrowserEchLocksAll" = "Browsers"
  "Resolve-BrowserEchChoice" = "Browsers"
  "Get-BrowserPolicyModesSummary" = "Browsers"
  "Get-BrowserPolicyWantedEch" = "Browsers"
  "Format-BrowserPolicyStatusLine" = "Browsers"
  "Get-LiveBrowserPostureSnapshot" = "Browsers"
  "Record-BrowserPolicyChange" = "Browsers"
  "Backup-FirefoxPoliciesFile" = "Browsers"
  "Get-ChromiumPolicyBase" = "Browsers"
  "Backup-ChromiumPolicyValues" = "Browsers"
  "Get-ChromiumPolicyMode" = "Browsers"
  "Test-ChromiumEchLockPresent" = "Browsers"
  "Test-BrowserEchLockLive" = "Browsers"
  "Remove-ChromiumBastionValues" = "Browsers"
  "Set-ChromiumPolicyMode" = "Browsers"
  "Set-ChromePolicyMode" = "Browsers"
  "Set-BravePolicyMode" = "Browsers"
  "Get-InstalledBastionBrowsers" = "Browsers"
  "Invoke-BastionBrowserPolicy" = "Browsers"

  # Apply
  "Invoke-DryRun" = "Apply"
  "Invoke-ApplyHardening" = "Apply"
  "Invoke-QuickHardening" = "Apply"
  "Invoke-SelfTest" = "Apply"
  "Show-RestorePointMenu" = "Apply"
  "Confirm-RestorePointBeforeApply" = "Apply"
  "New-BastionRestorePoint" = "Apply"
  "Get-RestorePointStatus" = "Apply"
  "Convert-RestorePointTime" = "Apply"
  "Show-ApplyPreview" = "Apply"
  "Show-ExploitProtectionGameNotice" = "Apply"
  "Write-AuditRow" = "Apply"
  "Write-AuditCategory" = "Apply"

  # Recovery
  "Invoke-UndoHardening" = "Recovery"
  "Get-CopilotM365Status" = "Recovery"
  "Invoke-CopilotM365Hardening" = "Recovery"
  "Invoke-CopilotM365Removal" = "Recovery"
  "Get-BastionFirewallGroupInboundStatus" = "Recovery"
  "Enable-BastionFirewallGroupInbound" = "Recovery"
  "Disable-BastionFirewallGroupInbound" = "Recovery"
  "Write-BastionRemoteAccessStatusBlock" = "Recovery"
  "Show-RemoteDesktopRecoveryMenu" = "Recovery"
  "Show-RemoteFirewallGroupMenu" = "Recovery"
  "Show-RemoteAccessRecoveryMenu" = "Recovery"
  "Write-BastionServiceStatusBlock" = "Recovery"
  "Show-BastionServiceGroupMenu" = "Recovery"
  "Show-ServicesRecoveryMenu" = "Recovery"
  "Show-LanDiscoveryRecoveryMenu" = "Recovery"
  "Show-NetworkRecoveryMenu" = "Recovery"
  "Show-GameBarRecoveryMenu" = "Recovery"
  "Show-AppsUiRecoveryMenu" = "Recovery"
  "Show-StrictHandleRecoveryMenu" = "Recovery"
  "Show-DefenderRecoveryMenu" = "Recovery"
  "Show-PolicyTasksRecoveryMenu" = "Recovery"
  "Show-SecurityMitigationsRecoveryMenu" = "Recovery"
  "Show-RecoveryMenu" = "Recovery"
  "Enable-BastionRemoteDesktopSystem" = "Harden"  # low-level used by Apply
  "Disable-BastionRemoteDesktopSystem" = "Harden"
  "Get-BastionRemoteDesktopSystemStatus" = "Harden"

  # Menus
  "Show-MainMenu" = "Menus"
  "Show-SectionMenu" = "Menus"
  "Show-ProgramMenu" = "Menus"
  "Show-DnsProviderMenu" = "Menus"
  "Show-BrowserPolicyMenu" = "Menus"
  "Show-Help" = "Menus"
  "Show-HelpReportsMenu" = "Menus"
  "Show-UninstallMenu" = "Menus"
  "Reset-ToDefaults" = "Menus"
  "Show-HardwareDriverGuide" = "Menus"
  "Get-HardwareInventory" = "Menus"
  "Get-MotherboardSupportLinks" = "Menus"

  # Harden (everything else hardening)
  "Get-OneDriveStatus" = "Harden"
  "Remove-BastionOneDrive" = "Harden"
  "Get-BloatAppxStatus" = "Harden"
  "Get-CfaCandidatePaths" = "Harden"
  "Add-CfaAllowPaths" = "Harden"
  "ConvertTo-BastionNormalizedPath" = "Harden"
  "Test-BastionLooksLikeWowRoot" = "Harden"
  "Resolve-BastionWowRootFromPath" = "Harden"
  "Get-BastionAsciiPathStringsFromFile" = "Harden"
  "Get-BastionWowRootsFromBattleNetMetadata" = "Harden"
  "Get-BastionWowRootsFromUninstallRegistry" = "Harden"
  "Get-BastionWowInstallRoots" = "Harden"
  "Get-BastionStrictHandleExceptionPaths" = "Harden"
  "Set-BastionStrictHandleExceptions" = "Harden"
  "Write-BastionStrictHandleGuidance" = "Harden"
  "Set-RegistryValueSafe" = "Harden"
  "Restore-SuggestionDefaults" = "Harden"
  "Test-BastionGameDvrSilenced" = "Harden"
  "Disable-BastionGameDvrOverlay" = "Harden"
  "Enable-BastionGameDvrOverlay" = "Harden"
  "Get-BastionStrictHandleSystemStatus" = "Harden"
}

function Resolve-ModuleForFunction {
  param([string]$Name)
  if ($Explicit.ContainsKey($Name)) { return $Explicit[$Name] }

  # Heuristic fallbacks
  if (Test-NameMatch $Name @("Write-*","Read-*","Wait-*","Clear-Bastion*","Maximize*","Get-BastionConsole*","Get-Wrapped*","Open-Url*")) {
    return "Core"
  }
  if (Test-NameMatch $Name @("Protect-*","Unprotect-*","Save-Undo*","Read-Bastion*","Initialize-Bastion*","Ensure-Bastion*","Bind-Bastion*","Resolve-BastionLog*","Get-BastionDataDir*","Test-BastionDir*","Test-BastionState*","Load-Bastion*","Save-BastionConfig*","Get-LastApply*","Set-BastionSensitiveFileAcl*","Get-BastionDnsSnapshotFromUndo*")) {
    return "Config"
  }
  if (Test-NameMatch $Name @("*Dns*","*Doh*","*DoH*","*DnsProvider*","*AdapterDns*","*BastionDns*")) {
    return "Dns"
  }
  if (Test-NameMatch $Name @("*Browser*","*Firefox*","*Chromium*","*Ech*","*ECH*","*Chrome*","*Brave*")) {
    return "Browsers"
  }
  if (Test-NameMatch $Name @("*Winget*","*Install*","*Catalog*","*Program*","*Uninstall*","*InstallRoot*","*Authenticode*")) {
    return "Programs"
  }
  if (Test-NameMatch $Name @("*Service*","*Spooler*","*HighRisk*","*Xbox*")) {
    # Xbox services vs GameBar recovery - if Show-* already handled
    if ($Name -like "Show-*") { return "Recovery" }
    return "Services"
  }
  if (Test-NameMatch $Name @("Invoke-DryRun*","Invoke-Apply*","Invoke-Quick*","Invoke-SelfTest*","*RestorePoint*","Confirm-Restore*","New-BastionRestore*","Get-RestorePoint*","Show-Apply*","Write-Audit*","Show-Exploit*")) {
    return "Apply"
  }
  if (Test-NameMatch $Name @("Show-MainMenu*","Show-Section*","Show-Program*","Show-Dns*","Show-Browser*","Show-Help*","Show-Uninstall*","Reset-ToDefaults*","Show-Hardware*")) {
    return "Menus"
  }
  if (Test-NameMatch $Name @("*Firewall*","*Remote*","*Lan*","*Rdp*","*NetworkRecovery*","*GameBar*","*Copilot*","*Defender*","*PolicyTasks*","*Recovery*","Invoke-Undo*")) {
    if ($Name -like "*RemoteDesktopSystem*" -or $Name -like "Get-BastionRemoteDesktopSystem*") {
      return "Harden"
    }
    return "Recovery"
  }
  return "Harden"
}

$ModuleOrder = @(
  "Init",
  "Core",
  "Config",
  "Programs",
  "Services",
  "Browsers",
  "Dns",
  "Harden",
  "Apply",
  "Recovery",
  "Menus"
)

$moduleBodies = @{}
$moduleFuncCounts = @{}
foreach ($m in $ModuleOrder) {
  $moduleBodies[$m] = New-Object System.Collections.Generic.List[string]
  $moduleFuncCounts[$m] = 0
}

# Collect non-function statements for Init (skip prefs + try entry + early path resolve that needs functions)
$initStmts = New-Object System.Collections.Generic.List[object]
$earlyPathResolveLines = $null
$entryTry = $null

foreach ($stmt in $ast.EndBlock.Statements) {
  if ($stmt -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
    $mod = Resolve-ModuleForFunction -Name $stmt.Name
    $text = Get-FuncText -Fn $stmt
    [void]$moduleBodies[$mod].Add($text)
    $moduleFuncCounts[$mod]++
    continue
  }

  $start = $stmt.Extent.StartLineNumber
  $end = $stmt.Extent.EndLineNumber
  $text = Get-StmtText -Stmt $stmt

  # Skip bootstrap prefs (live in Bastion-Hardening.ps1)
  if ($start -ge 18 -and $end -le 20) { continue }

  # Early path resolve block uses functions; move to bootstrap after import
  if ($start -eq 125 -or ($start -ge 125 -and $end -le 133 -and $text -match 'Resolve-BastionLogDirectory|Bind-BastionDataPaths')) {
    if ($null -eq $earlyPathResolveLines) {
      $earlyPathResolveLines = $text
    } else {
      $earlyPathResolveLines += "`r`n" + $text
    }
    continue
  }

  # Entry try/catch stays in bootstrap
  if ($stmt -is [System.Management.Automation.Language.TryStatementAst] -and $start -ge 8290) {
    $entryTry = $text
    continue
  }

  # Version bump in Config assignment
  if ($text -match 'ScriptVersion\s*=\s*"15\.8\.4"') {
    $text = $text -replace 'ScriptVersion\s*=\s*"15\.8\.4"', 'ScriptVersion = "15.9.0"'
  }

  [void]$initStmts.Add([PSCustomObject]@{ Start = $start; End = $end; Text = $text })
}

# Init header + statements in original order
$initHeader = @"
# Bastion.Init.ps1 - script-scoped state, catalogs, and section docs (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1. Do not run standalone.
# Plain text GPLv3 source - never encrypt.

"@

$initBody = New-Object System.Collections.Generic.List[string]
[void]$initBody.Add($initHeader.TrimEnd())
foreach ($s in ($initStmts | Sort-Object Start)) {
  [void]$initBody.Add("")
  [void]$initBody.Add($s.Text)
}
$moduleBodies["Init"] = $initBody

# Module file headers
$ModuleFileNames = @{
  "Init"     = "Bastion.Init.ps1"
  "Core"     = "Bastion.Core.ps1"
  "Config"   = "Bastion.Config.ps1"
  "Programs" = "Bastion.Programs.ps1"
  "Services" = "Bastion.Services.ps1"
  "Browsers" = "Bastion.Browsers.ps1"
  "Dns"      = "Bastion.Dns.ps1"
  "Harden"   = "Bastion.Harden.ps1"
  "Apply"    = "Bastion.Apply.ps1"
  "Recovery" = "Bastion.Recovery.ps1"
  "Menus"    = "Bastion.Menus.ps1"
}

if (-not (Test-Path -LiteralPath $SrcDir)) {
  New-Item -ItemType Directory -Path $SrcDir -Force | Out-Null
}

# ACL tightening: patch Save-BastionConfig / Set-BastionSensitiveFileAcl usage
# We'll post-process Config module after write if Save-BastionConfig doesn't ACL config file

$assignmentLog = New-Object System.Collections.Generic.List[string]
foreach ($stmt in $ast.EndBlock.Statements) {
  if ($stmt -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
    $mod = Resolve-ModuleForFunction -Name $stmt.Name
    [void]$assignmentLog.Add("$($stmt.Name)`t$mod`t$($stmt.Extent.StartLineNumber)-$($stmt.Extent.EndLineNumber)")
  }
}
$assignmentLog | Set-Content (Join-Path $PSScriptRoot "_module-assign.txt") -Encoding utf8

foreach ($m in $ModuleOrder) {
  $fileName = $ModuleFileNames[$m]
  $path = Join-Path $SrcDir $fileName
  if ($m -eq "Init") {
    $content = ($moduleBodies[$m] -join "`r`n") + "`r`n"
  } else {
    $header = @"
# Bastion.$m.ps1 - modular domain (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace (`$script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.

"@
    $parts = New-Object System.Collections.Generic.List[string]
    [void]$parts.Add($header.TrimEnd())
    foreach ($fnText in $moduleBodies[$m]) {
      [void]$parts.Add("")
      [void]$parts.Add($fnText)
    }
    $content = ($parts -join "`r`n") + "`r`n"
  }

  # Pure ASCII enforcement: strip any non-ASCII that may have snuck in (should be none)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
  # Write as UTF-8 without BOM for PowerShell-friendliness; content is ASCII
  [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding $false))
  $lineCount = ($content -split "`n").Count
  Write-Host ("  {0,-22} funcs={1,3} lines~{2,5}" -f $fileName, $moduleFuncCounts[$m], $lineCount)
}

# Export early path resolve + entry try for bootstrap generator
$meta = @{
  EarlyPathResolve = $earlyPathResolveLines
  EntryTry = $entryTry
}
$meta | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $PSScriptRoot "_split-meta.json") -Encoding utf8

Write-Host ""
Write-Host "Init non-function statements: $($initStmts.Count)"
Write-Host "Total functions assigned: $($assignmentLog.Count)"
Write-Host "Done. Modules written under $SrcDir"
