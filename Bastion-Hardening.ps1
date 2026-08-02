#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Bastion Hardening Framework v15.9.1 FINAL
.DESCRIPTION
    Selective Windows hardening. Catalog-only winget installs. Pure ASCII source
    for reliable paste into editors and terminals.

    v15.9.0 modular layout: this file is a thin elevated bootstrap. Implementation
    lives in plain-text src\*.ps1 modules (NEVER encrypted - GPLv3 + auditability).
    Modules are dot-sourced into this runspace so $script: scope is shared.
.NOTES
    Version 15.9.1 FINAL. System Restore is the strongest rollback. Run elevated. Save as UTF-8 (ASCII subset).
    Licensed under GNU GPLv3 - see LICENSE and NOTICE in the project root.
    v15.8: DPAPI-protected DNS snapshots, restore prior DNS, optional RDP host lock, RDP triad in Dry Run/Audit.
    v15.8.1: DNS Apply/restore also set Windows DNS-over-HTTPS (DoH) for known resolvers (separate from DPAPI).
    v15.8.2: DNS menu shows live vs preferred, DoH labels, and Apply DNS now (A); preference alone does not change Windows.
    v15.8.3: Preserve DNS/RDP undo blobs across Applies; Network option 4 previews snapshot targets; clearer restore UX.
    v15.8.4: Match Settings Edit DNS DoH path (per-interface QWord DohFlags=17 + template) so Encrypted shows without manual click.
    v15.9.0: Modular plain-text src\ layout, MANIFEST.sha256 integrity at startup, ACL on Bastion-Config.json.
    v15.9.1: Fix module load scope so functions remain after import (UAC flash-exit).
#>
param(
    [switch]$BastionSmokeLoadOnly
)

$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"
$ConfirmPreference     = "None"

$script:BastionRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($script:BastionRoot)) {
    $script:BastionRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# Load order: Init (state/catalogs) then domain modules. Dot-source only - same runspace for $script:.
$script:BastionSourceModules = @(
    "Bastion.Init.ps1",
    "Bastion.Core.ps1",
    "Bastion.Config.ps1",
    "Bastion.Programs.ps1",
    "Bastion.Services.ps1",
    "Bastion.Browsers.ps1",
    "Bastion.Dns.ps1",
    "Bastion.Harden.ps1",
    "Bastion.Apply.ps1",
    "Bastion.Recovery.ps1",
    "Bastion.Menus.ps1"
)

function Wait-BastionBootstrapKey {
    <#
    .SYNOPSIS
      Pause so the user can read a fatal message before the console closes.
      Available before modules load (does not depend on Wait-ForKey).
    #>
    param([string]$Message = "Press any key to exit...")
    Write-Host ""
    Write-Host ("  {0}" -f $Message) -ForegroundColor Gray
    try {
        [void][System.Console]::ReadKey($true)
    } catch {
        try {
            [void](Read-Host "  Press Enter to exit")
        } catch {
            Start-Sleep -Seconds 8
        }
    }
}

function Test-BastionSourceIntegrity {
    <#
    .SYNOPSIS
      Verify SHA256 of each src file listed in src\MANIFEST.sha256 (hard-fail on mismatch).
    #>
    param(
        [Parameter(Mandatory)][string]$SrcDir,
        [Parameter(Mandatory)][string]$ManifestPath
    )
    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        return [PSCustomObject]@{
            Ok      = $false
            Message = "Missing integrity manifest: $ManifestPath"
        }
    }
    $lines = Get-Content -LiteralPath $ManifestPath -ErrorAction Stop
    $checked = 0
    foreach ($raw in $lines) {
        $line = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.StartsWith("#")) { continue }

        $hash = $null
        $rel = $null
        # Formats: "hash  relativepath" or "hash *relativepath" (certutil / Get-FileHash style)
        if ($line -match '^\s*([A-Fa-f0-9]{64})\s+\*?\s*(.+?)\s*$') {
            $hash = $Matches[1].ToUpperInvariant()
            $rel = $Matches[2].Trim().TrimStart(".\")
        } else {
            return [PSCustomObject]@{
                Ok      = $false
                Message = "Malformed MANIFEST line: $line"
            }
        }

        # Do not re-hash the manifest itself if listed
        $leaf = Split-Path -Leaf $rel
        if ($leaf -ieq "MANIFEST.sha256") { continue }

        $full = Join-Path $SrcDir $rel
        # Also accept paths already prefixed with src\
        if (-not (Test-Path -LiteralPath $full)) {
            $alt = Join-Path $script:BastionRoot $rel
            if (Test-Path -LiteralPath $alt) { $full = $alt }
        }
        if (-not (Test-Path -LiteralPath $full)) {
            return [PSCustomObject]@{
                Ok      = $false
                Message = "MANIFEST lists missing file: $rel"
            }
        }

        $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actual -ne $hash) {
            return [PSCustomObject]@{
                Ok      = $false
                Message = "Hash mismatch for $rel (expected $hash, got $actual). Re-download the official release or regenerate MANIFEST if you intentionally edited sources."
            }
        }
        $checked++
    }
    if ($checked -lt 1) {
        return [PSCustomObject]@{
            Ok      = $false
            Message = "MANIFEST.sha256 contained no verifiable file entries."
        }
    }
    return [PSCustomObject]@{
        Ok      = $true
        Message = "OK ($checked files)"
        Count   = $checked
    }
}

function Test-BastionSourcesReady {
    <#
    .SYNOPSIS
      Fail-closed layout + integrity checks. Does NOT dot-source (caller must . at script scope).
    .OUTPUTS
      Source directory path on success; throws on failure.
    #>
    $srcDir = Join-Path $script:BastionRoot "src"
    if (-not (Test-Path -LiteralPath $srcDir -PathType Container)) {
        throw "Bastion source directory missing: $srcDir`nKeep Bastion-Hardening.ps1 next to the src\ folder (official release layout)."
    }

    foreach ($name in $script:BastionSourceModules) {
        $path = Join-Path $srcDir $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required Bastion module missing: $path"
        }
    }

    $manifestPath = Join-Path $srcDir "MANIFEST.sha256"
    $integrity = Test-BastionSourceIntegrity -SrcDir $srcDir -ManifestPath $manifestPath
    if (-not $integrity.Ok) {
        throw "Bastion source integrity check failed.`n$($integrity.Message)"
    }

    return $srcDir
}

# CRITICAL: Dot-source modules at SCRIPT scope, not inside a function.
# PowerShell function-scope . (dot-source) defines functions only for that function;
# after return, Resolve-BastionLogDirectory / Show-MainMenu / etc. vanish while
# $script:Config still looks fine (smoke load would pass, then flash-and-close).
try {
    $bastionSrcDir = Test-BastionSourcesReady
    foreach ($name in $script:BastionSourceModules) {
        $path = Join-Path $bastionSrcDir $name
        . $path
    }
} catch {
    Write-Host ""
    Write-Host "  FATAL: Cannot load Bastion modules." -ForegroundColor Red
    Write-Host ("  {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    Write-Host "  Expected layout: Bastion-Hardening.ps1 + src\Bastion.*.ps1 + src\MANIFEST.sha256" -ForegroundColor DarkGray
    Write-Host ""
    if (-not $BastionSmokeLoadOnly) {
        Wait-BastionBootstrapKey "Press any key to exit..."
    }
    exit 1
}

if ($BastionSmokeLoadOnly) {
    Write-Host ("Bastion smoke load OK v{0}" -f $script:Config.ScriptVersion)
    exit 0
}

# Path bind was deferred until after Config module load (functions available).
$resolvedLog = Resolve-BastionLogDirectory
if ($resolvedLog) {
    Bind-BastionDataPaths -LogDirectory $resolvedLog
} else {
    Write-Host "  WARNING: Could not create a writable Bastion data directory." -ForegroundColor Red
    Write-Host "  Tried C:\Temp\Bastion, C:\Temp, %ProgramData%\Bastion, %LOCALAPPDATA%\Bastion, %TEMP%\Bastion." -ForegroundColor Yellow
    Bind-BastionDataPaths -LogDirectory "C:\Temp\Bastion"
}

try {
    if (-not (Ensure-BastionPaths)) {
        Write-Host ("Cannot initialize {0}. Exiting." -f $script:Config.LogDirectory) -ForegroundColor Red
        Wait-BastionBootstrapKey "Press any key to exit..."
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
        Wait-BastionBootstrapKey "Press any key to exit..."
        exit 1
    }
    Write-Log ("Bastion v{0} FINAL started | data={1}" -f $script:Config.ScriptVersion, $script:Config.LogDirectory)
    Show-MainMenu
} catch {
    Write-Host ("FATAL: {0}" -f $_.Exception.Message) -ForegroundColor Red
    try {
        Write-Log ("FATAL: {0}" -f $_.Exception.Message) -Level Error
    } catch {}
    try {
        if (Get-Command Wait-ForKey -ErrorAction SilentlyContinue) {
            Wait-ForKey "Press any key to exit..."
        } else {
            Wait-BastionBootstrapKey "Press any key to exit..."
        }
    } catch {
        Wait-BastionBootstrapKey "Press any key to exit..."
    }
    exit 1
}
