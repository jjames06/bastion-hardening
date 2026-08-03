# =============================================================================
# Bastion.Browsers.ps1 - modular domain (v15.9.0)
# =============================================================================
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.
#
# Role of this module
#   Detect and write enterprise privacy policies for installed Firefox, Chrome,
#   and Brave. Called from menu 6 / Recovery hub 4 and (when enabled) Apply.
#
# Policy modes (per browser)
#   Default - remove Bastion-managed policy material (best-effort; backups kept)
#   Medium  - privacy baseline (telemetry / tracking / cookies); fewer breakages
#   Strict  - Medium + HTTPS-Only (and Chromium transport extras); NOT ECH alone
#
# Encrypted Client Hello (ECH) - NEVER default
#   EnableEch parameters default to false. Resolve-BrowserEchChoice returns true
#   only when Mode is Strict AND the caller passes EnableEch true (user said Yes
#   to the separate ECH pack prompt under Strict). First-run seed, Medium, and
#   Strict without Yes never write ECH locks. Clear-BrowserEchLocksAll / reset
#   force all wanted ECH flags false.
#
# Engine differences
#   Firefox: distribution\policies.json preference locks for ECH prefs.
#   Chrome/Brave: HKLM policy keys; BastionEchLock intent marker + best-effort
#   EncryptedClientHelloEnabled (not identical to Firefox prefs).
#   Comments use ASCII punctuation only.
# =============================================================================

# -----------------------------------------------------------------------------
# Get-FirefoxPoliciesPath
#   Prefer an existing Firefox install root (64-bit then 32-bit). Returns the
#   policies.json path under distribution\, even if the file does not exist yet
#   (write path for Set-FirefoxPolicyMode).
# -----------------------------------------------------------------------------
function Get-FirefoxPoliciesPath {
    foreach ($c in @(
        "C:\Program Files\Mozilla Firefox\distribution\policies.json",
        "C:\Program Files (x86)\Mozilla Firefox\distribution\policies.json"
    )) {
        $root = Split-Path (Split-Path $c -Parent) -Parent
        if (Test-Path -LiteralPath $root) { return $c }
    }
    return "C:\Program Files\Mozilla Firefox\distribution\policies.json"
}

# -----------------------------------------------------------------------------
# Test-FirefoxEchLocksPresent
#   Live ECH detection: true if policies.json Preferences contain ECH-related
#   names (echconfig / EncryptedClientHello / network.dns.ech). False if file
#   missing or unreadable. Used for Dry Run / Audit / UI "ECH live".
# -----------------------------------------------------------------------------
function Test-FirefoxEchLocksPresent {
    $path = Get-FirefoxPoliciesPath
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    try {
        $j = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
        $p = $j.policies
        if (-not $p -or -not $p.Preferences) { return $false }
        $prefNames = @($p.Preferences.PSObject.Properties | ForEach-Object { $_.Name })
        return [bool]($prefNames -match 'echconfig|EncryptedClientHello|network\.dns\.ech')
    } catch {
        return $false
    }
}

# -----------------------------------------------------------------------------
# Get-FirefoxPolicyModeFromFile
#   Classify live policies.json for UI: Default (no file), Medium (telemetry
#   baseline), Strict (HTTPS-Only / locked tracking / ECH prefs), else Custom
#   (foreign or DisableEncryptedClientHello). Heuristic, not a full parser.
# -----------------------------------------------------------------------------
function Get-FirefoxPolicyModeFromFile {
    # Classify Bastion-written (or compatible) policies.json for UI display.
    $path = Get-FirefoxPoliciesPath
    if (-not (Test-Path -LiteralPath $path)) { return "Default" }
    try {
        $j = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
        $p = $j.policies
        if (-not $p) { return "Custom" }
        $httpsOnly = ("$($p.HTTPSOnlyMode)" -eq "force_enabled")
        $echPref = Test-FirefoxEchLocksPresent
        $echDisabled = ($p.DisableEncryptedClientHello -eq $true)
        if ($httpsOnly -or $echPref -or ($p.DisablePocket -eq $true -and $p.EnableTrackingProtection -and $p.EnableTrackingProtection.Locked)) {
            return "Strict"
        }
        if ($p.DisableTelemetry -eq $true -or $p.DisableFirefoxStudies -eq $true) {
            return "Medium"
        }
        if ($echDisabled) { return "Custom" }
        return "Custom"
    } catch {
        return "Custom"
    }
}

# -----------------------------------------------------------------------------
# Set-FirefoxPolicyMode
#   Write or remove Firefox policies.json for Default / Medium / Strict.
#   EnableEch defaults false; gated again via Resolve-BrowserEchChoice so ECH
#   preference locks are written only for Strict + explicit true. Never sets
#   DisableEncryptedClientHello (that would force ECH off). Backs up first.
# -----------------------------------------------------------------------------
function Set-FirefoxPolicyMode {
    param(
        [ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch = $false
    )
    $path = Get-FirefoxPoliciesPath
    $dist = Split-Path $path -Parent
    $modeBefore = Get-FirefoxPolicyModeFromFile
    $echBefore = Test-FirefoxEchLocksPresent
    try {
        if ($Mode -eq "Default") {
            $bak = Backup-FirefoxPoliciesFile
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                Write-Status "Firefox policies.json removed (full Bastion revert)" "Applied"
                Write-Host "      Cleared: telemetry/studies locks, tracking protection locks," -ForegroundColor DarkGray
                Write-Host "      HTTPS-Only force, Pocket disable, Encrypted Client Hello (ECH) preference locks." -ForegroundColor DarkGray
                Write-Host ("      File was: {0}" -f $path) -ForegroundColor DarkGray
                Write-Host "      Restart Firefox. about:policies should show no active Bastion file." -ForegroundColor DarkGray
            } else {
                Write-Status "Firefox already default (no policies.json)" "Already"
            }
            if ($script:BrowserPolicyModes.Contains("Firefox")) { $script:BrowserPolicyModes["Firefox"] = "Default" }
            if ($script:BrowserEchLocks.Contains("Firefox")) { $script:BrowserEchLocks["Firefox"] = $false }
            Record-BrowserPolicyChange -Browser "Firefox" -ModeBefore $modeBefore -ModeAfter "Default" `
                -Detail ("Deleted policies.json (revert; ECH was {0})" -f $(if ($echBefore) { "on" } else { "off" })) -BackupPath $bak
            return $true
        }

        # Encrypted Client Hello (ECH): never by default; only if EnableEch was explicitly true for Strict.
        $EnableEch = Resolve-BrowserEchChoice -Mode $Mode -EnableEch:$EnableEch

        $bak = Backup-FirefoxPoliciesFile
        $policy = if ($Mode -eq "Medium") {
            @{ policies = @{
                DisableTelemetry = $true
                DisableFirefoxStudies = $true
                EnableTrackingProtection = @{ Value = $true; Cryptomining = $true; Fingerprinting = $true }
            }}
        } else {
            $pol = @{
                DisableTelemetry = $true
                DisableFirefoxStudies = $true
                DisablePocket = $true
                HTTPSOnlyMode = "force_enabled"
                EnableTrackingProtection = @{
                    Value = $true
                    Locked = $true
                    Cryptomining = $true
                    Fingerprinting = $true
                }
            }
            if ($EnableEch) {
                # Lock Encrypted Client Hello (ECH) related prefs on. Never set DisableEncryptedClientHello.
                $pol.Preferences = @{
                    "network.dns.echconfig.enabled" = @{
                        Value  = $true
                        Status = "locked"
                    }
                    "network.dns.http3_echconfig.enabled" = @{
                        Value  = $true
                        Status = "locked"
                    }
                }
            }
            @{ policies = $pol }
        }
        if (-not (Test-Path -LiteralPath $dist)) {
            New-Item -Path $dist -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $json = ($policy | ConvertTo-Json -Depth 10)
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($path, $json, $utf8)
        Write-Status ("Firefox policies -> {0}{1}" -f $Mode, $(if ($EnableEch) { " + Encrypted Client Hello (ECH) locks" } else { "" })) "Applied"
        if ($Mode -eq "Strict") {
            Write-Host "      Strict base: HTTPS-Only force, tracking protection locked, Pocket off, telemetry/studies off." -ForegroundColor DarkGray
            if ($EnableEch) {
                Write-Host "      Encrypted Client Hello (ECH): preference locks ON (handshake privacy when supported)." -ForegroundColor DarkGray
                Write-Host "      Some networks mishandle Encrypted Client Hello (ECH); use another browser or Default if needed." -ForegroundColor DarkGray
            } else {
                Write-Host "      Encrypted Client Hello (ECH): not locked (you declined the optional ECH pack)." -ForegroundColor DarkGray
            }
            Write-Host "      Revert this browser: menu 6 > Firefox > Default." -ForegroundColor DarkGray
        }
        if ($script:BrowserPolicyModes.Contains("Firefox")) { $script:BrowserPolicyModes["Firefox"] = $Mode }
        if ($script:BrowserEchLocks.Contains("Firefox")) { $script:BrowserEchLocks["Firefox"] = [bool]$EnableEch }
        Record-BrowserPolicyChange -Browser "Firefox" -ModeBefore $modeBefore -ModeAfter $Mode `
            -Detail ("Wrote Bastion {0} policies.json; ECH locks={1}" -f $Mode, $EnableEch) -BackupPath $bak
        return $true
    } catch {
        Write-Status ("Firefox policy failed: {0}" -f $_.Exception.Message) "Failed"
        return $false
    }
}

# -----------------------------------------------------------------------------
# Get-BrowserPolicyBackupDir
#   Ensure browser-policy-backups under LogDirectory exists; return path.
# -----------------------------------------------------------------------------
function Get-BrowserPolicyBackupDir {
    $dir = Join-Path $script:Config.LogDirectory "browser-policy-backups"
    try {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
    } catch {}
    return $dir
}

# -----------------------------------------------------------------------------
# Get-BrowserPolicyStatePath
#   Path to Bastion-BrowserPolicies-State.json (wanted + live summary file).
# -----------------------------------------------------------------------------
function Get-BrowserPolicyStatePath {
    return (Join-Path $script:Config.LogDirectory "Bastion-BrowserPolicies-State.json")
}

# -----------------------------------------------------------------------------
# Write-BrowserStrictDisclaimer
#   User-facing Strict / ECH honesty block. Compact=true for menu overview;
#   full text before confirming Strict. ECH described as optional, never default.
# -----------------------------------------------------------------------------
function Write-BrowserStrictDisclaimer {
    param([switch]$Compact)
    Write-Host ""
    Write-Host "  ---------- Strict mode notice ----------" -ForegroundColor Yellow
    Write-Host "  Strict favors privacy and transport hardening over maximum site compatibility." -ForegroundColor Yellow
    if (-not $Compact) {
        Write-Host "  HTTPS-Only: the browser prefers or requires HTTPS. Plain HTTP, mixed content," -ForegroundColor DarkYellow
        Write-Host "  captive portals, and some older or misconfigured hosts may fail or warn." -ForegroundColor DarkYellow
        Write-Host "  Encrypted Client Hello (ECH) is NOT included unless you answer Yes to the" -ForegroundColor DarkYellow
        Write-Host "  separate ECH pack question. ECH can hide the destination hostname in the TLS" -ForegroundColor DarkYellow
        Write-Host "  Client Hello from passive observers (when supported); some networks mishandle it." -ForegroundColor DarkYellow
        Write-Host "  Other Strict effects: stronger tracking/cookie limits (varies by browser)." -ForegroundColor DarkYellow
        Write-Host "  Suggested pattern: one browser Strict (optional ECH) for daily use; another" -ForegroundColor Cyan
        Write-Host "  Medium/Default for sites that need looser settings." -ForegroundColor Cyan
        Write-Host "  Revert one browser: menu 6 > that browser > Default (best-effort)." -ForegroundColor DarkGray
        Write-Host "  Bulletproof rollback: System Restore (menu 13 / R)." -ForegroundColor DarkGray
    } else {
        Write-Host "  May break HTTP-only or misconfigured sites and some SSO/embeds." -ForegroundColor DarkYellow
        Write-Host "  Encrypted Client Hello (ECH) is optional (asked separately; never on by default)." -ForegroundColor DarkYellow
        Write-Host "  Tip: different modes per browser. Restore Point if unsure." -ForegroundColor Cyan
    }
    Write-Host "  ----------------------------------------" -ForegroundColor Yellow
    Write-Host ""
}

# -----------------------------------------------------------------------------
# Clear-BrowserEchLocksAll
#   Force every BrowserEchLocks entry to false (wanted ECH off). Used by reset
#   paths so ECH never remains "wanted" after config wipe.
# -----------------------------------------------------------------------------
function Clear-BrowserEchLocksAll {
    foreach ($k in @($script:BrowserEchLocks.Keys)) {
        $script:BrowserEchLocks[$k] = $false
    }
}

# -----------------------------------------------------------------------------
# Resolve-BrowserEchChoice
#   Single gate for ECH pack application:
#     - Mode must be Strict
#     - EnableEch must be explicitly true (user Yes under Strict)
#   Any other combination returns false. Callers re-assign EnableEch to result
#   so Medium/Default never write ECH even if a stale true flag is passed.
# -----------------------------------------------------------------------------
function Resolve-BrowserEchChoice {
    # Single gate: ECH only when caller passes explicit true AND mode is Strict.
    param(
        [ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch
    )
    if ($Mode -ne "Strict") { return $false }
    return [bool]$EnableEch
}

# -----------------------------------------------------------------------------
# Get-BrowserPolicyModesSummary
#   Compact "Firefox=Strict+ECH, Chrome=Medium, ..." for main menu status line.
#   +ECH only when wanted ECH is true AND saved mode is Strict.
# -----------------------------------------------------------------------------
function Get-BrowserPolicyModesSummary {
    $parts = foreach ($k in @($script:BrowserPolicyModes.Keys)) {
        $mode = $script:BrowserPolicyModes[$k]
        $ech = if ($script:BrowserEchLocks.Contains($k) -and $script:BrowserEchLocks[$k] -and $mode -eq "Strict") {
            "+ECH"
        } else {
            ""
        }
        "{0}={1}{2}" -f $k, $mode, $ech
    }
    return ($parts -join ", ")
}

# -----------------------------------------------------------------------------
# Get-BrowserPolicyWantedEch
#   True only if saved mode is Strict and BrowserEchLocks[name] is true.
#   Defaults false when keys missing (ECH never assumed on).
# -----------------------------------------------------------------------------
function Get-BrowserPolicyWantedEch {
    param([string]$BrowserName)
    if (-not $script:BrowserPolicyModes.Contains($BrowserName)) { return $false }
    if ($script:BrowserPolicyModes[$BrowserName] -ne "Strict") { return $false }
    if (-not $script:BrowserEchLocks.Contains($BrowserName)) { return $false }
    return [bool]$script:BrowserEchLocks[$BrowserName]
}

# -----------------------------------------------------------------------------
# Format-BrowserPolicyStatusLine
#   Compact readable line for Dry Run / Audit / logs (live vs want, ECH Yes/No).
# -----------------------------------------------------------------------------
function Format-BrowserPolicyStatusLine {
    # Compact readable line for Dry Run / Audit / logs.
    param(
        [string]$Name,
        [string]$LiveMode,
        [string]$WantMode,
        [bool]$EchLive,
        [bool]$WantEch
    )
    $echL = if ($EchLive) { "Yes" } else { "No" }
    $echW = if ($WantEch) { "Yes" } else { "No" }
    return ("{0}: live {1} (ECH {2}) -> want {3} (ECH {4})" -f $Name, $LiveMode, $echL, $WantMode, $echW)
}

# -----------------------------------------------------------------------------
# Get-LiveBrowserPostureSnapshot
#   Live OS/file detection for Firefox/Chrome/Brave: installed flag, mode class,
#   ECH live on/off. Never invents Bastion Apply history. NotInstalled when paths
#   fail Test-Installed.
# -----------------------------------------------------------------------------
function Get-LiveBrowserPostureSnapshot {
    # Live OS/file detection only - never invents Bastion Apply history.
    $modes = [ordered]@{}
    $ech = [ordered]@{}
    $installed = [ordered]@{}
    foreach ($name in @("Firefox", "Chrome", "Brave")) {
        $isOn = $false
        try {
            if ($script:ProgramDefs.Contains($name)) {
                $isOn = [bool](Test-Installed -Name $name -Paths $script:ProgramDefs[$name].Paths)
            }
        } catch { $isOn = $false }
        $installed[$name] = $isOn
        if (-not $isOn) {
            $modes[$name] = "NotInstalled"
            $ech[$name] = $false
            continue
        }
        try {
            if ($name -eq "Firefox") { $modes[$name] = [string](Get-FirefoxPolicyModeFromFile) }
            else { $modes[$name] = [string](Get-ChromiumPolicyMode -Browser $name) }
        } catch { $modes[$name] = "Unknown" }
        try { $ech[$name] = [bool](Test-BrowserEchLockLive -Browser $name) } catch { $ech[$name] = $false }
    }
    return @{ Modes = $modes; Ech = $ech; Installed = $installed }
}

# -----------------------------------------------------------------------------
# Record-BrowserPolicyChange
#   Update in-memory last-change record, session log, and state JSON after a
#   successful (or attempted) policy write/remove.
# -----------------------------------------------------------------------------
function Record-BrowserPolicyChange {
    param(
        [string]$Browser,
        [string]$ModeBefore,
        [string]$ModeAfter,
        [string]$Detail,
        [string]$BackupPath = ""
    )
    $script:BrowserPolicyLastChange = @{
        Timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Browser    = $Browser
        ModeBefore = $ModeBefore
        ModeAfter  = $ModeAfter
        Detail     = $Detail
        BackupPath = $BackupPath
        LogFile    = $script:logFile
    }
    Write-Log ("BrowserPolicy {0}: {1} -> {2} | {3} | backup={4}" -f $Browser, $ModeBefore, $ModeAfter, $Detail, $BackupPath)
    Save-BrowserPolicyStateFile
}

# -----------------------------------------------------------------------------
# Backup-FirefoxPoliciesFile
#   Copy existing policies.json into browser-policy-backups with timestamp.
#   Returns dest path or empty string if missing/fail (non-fatal).
# -----------------------------------------------------------------------------
function Backup-FirefoxPoliciesFile {
    $path = Get-FirefoxPoliciesPath
    if (-not (Test-Path -LiteralPath $path)) { return "" }
    try {
        $dir = Get-BrowserPolicyBackupDir
        $dest = Join-Path $dir ("firefox-policies-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
        Copy-Item -LiteralPath $path -Destination $dest -Force -ErrorAction Stop
        Write-Log ("Firefox policies backup: {0}" -f $dest) -NoConsole
        return $dest
    } catch {
        Write-Log ("Firefox policies backup failed: {0}" -f $_.Exception.Message) -Level Warning -NoConsole
        return ""
    }
}

# -----------------------------------------------------------------------------
# Get-ChromiumPolicyBase
#   HKLM enterprise policy root for Chrome or Brave (Bastion-managed values).
# -----------------------------------------------------------------------------
function Get-ChromiumPolicyBase {
    param([ValidateSet("Chrome","Brave")][string]$Browser)
    if ($Browser -eq "Brave") {
        return "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
    }
    return "HKLM:\SOFTWARE\Policies\Google\Chrome"
}

# -----------------------------------------------------------------------------
# Backup-ChromiumPolicyValues
#   Snapshot Bastion-named values under the Chromium policy key to JSON backup.
#   Uses ChromiumBastionValueNames allow-list; foreign values left alone later.
# -----------------------------------------------------------------------------
function Backup-ChromiumPolicyValues {
    param([ValidateSet("Chrome","Brave")][string]$Browser)
    $base = Get-ChromiumPolicyBase -Browser $Browser
    $snap = [ordered]@{ Browser = $Browser; Path = $base; Values = [ordered]@{}; Existed = $false }
    if (-not (Test-Path -LiteralPath $base)) {
        return $snap
    }
    $snap.Existed = $true
    try {
        $props = Get-ItemProperty -LiteralPath $base -ErrorAction Stop
        foreach ($n in $script:ChromiumBastionValueNames) {
            if ($null -ne $props.PSObject.Properties[$n]) {
                $snap.Values[$n] = $props.$n
            }
        }
        $dir = Get-BrowserPolicyBackupDir
        $dest = Join-Path $dir ("{0}-policy-{1}.json" -f $Browser.ToLowerInvariant(), (Get-Date -Format "yyyyMMdd-HHmmss"))
        ($snap | ConvertTo-Json -Depth 6) | Out-File -LiteralPath $dest -Encoding utf8 -Force
        Write-Log ("{0} policy backup: {1}" -f $Browser, $dest) -NoConsole
        $snap.BackupFile = $dest
        return $snap
    } catch {
        Write-Log ("{0} policy backup failed: {1}" -f $Browser, $_.Exception.Message) -Level Warning -NoConsole
        return $snap
    }
}

# -----------------------------------------------------------------------------
# Get-ChromiumPolicyMode
#   Classify live HKLM policy for UI: Default (no key), Strict (HTTPS-Only /
#   BastionEchLock / cookie force), Medium (BastionManaged or telemetry markers),
#   Custom (foreign key without Bastion markers).
# -----------------------------------------------------------------------------
function Get-ChromiumPolicyMode {
    param([ValidateSet("Chrome","Brave")][string]$Browser)
    $base = Get-ChromiumPolicyBase -Browser $Browser
    if (-not (Test-Path -LiteralPath $base)) { return "Default" }
    try {
        $c = Get-ItemProperty -LiteralPath $base -ErrorAction SilentlyContinue
        if ($null -eq $c) { return "Default" }
        if ($c.HttpsOnlyMode -eq 2 -or $c.DefaultCookiesSetting -eq 4 -or $c.BastionEchLock -eq 1) { return "Strict" }
        if ($null -ne $c.MetricsReportingEnabled -or $null -ne $c.BlockThirdPartyCookies -or $c.BastionManaged -eq 1) {
            return "Medium"
        }
        # Key exists but no Bastion markers - treat as custom foreign policy.
        return "Custom"
    } catch {
        return "Custom"
    }
}

# -----------------------------------------------------------------------------
# Test-ChromiumEchLockPresent
#   Live ECH intent: BastionEchLock DWORD == 1 under the browser policy key.
#   This is Bastion's marker; Chromium ECH support still varies by build.
# -----------------------------------------------------------------------------
function Test-ChromiumEchLockPresent {
    param([ValidateSet("Chrome","Brave")][string]$Browser)
    $base = Get-ChromiumPolicyBase -Browser $Browser
    if (-not (Test-Path -LiteralPath $base)) { return $false }
    try {
        $v = (Get-ItemProperty -LiteralPath $base -Name BastionEchLock -ErrorAction SilentlyContinue).BastionEchLock
        return ($v -eq 1)
    } catch {
        return $false
    }
}

# -----------------------------------------------------------------------------
# Test-BrowserEchLockLive
#   Dispatch live ECH detection to Firefox prefs or Chromium BastionEchLock.
# -----------------------------------------------------------------------------
function Test-BrowserEchLockLive {
    param([ValidateSet("Firefox","Chrome","Brave")][string]$Browser)
    switch ($Browser) {
        "Firefox" { return (Test-FirefoxEchLocksPresent) }
        "Chrome"  { return (Test-ChromiumEchLockPresent -Browser Chrome) }
        "Brave"   { return (Test-ChromiumEchLockPresent -Browser Brave) }
    }
    return $false
}

# -----------------------------------------------------------------------------
# Remove-ChromiumBastionValues
#   Default mode helper: remove only ChromiumBastionValueNames entries. Leaves
#   non-Bastion enterprise values in place. Drops empty policy key if vacant.
# -----------------------------------------------------------------------------
function Remove-ChromiumBastionValues {
    param([ValidateSet("Chrome","Brave")][string]$Browser)
    $base = Get-ChromiumPolicyBase -Browser $Browser
    if (-not (Test-Path -LiteralPath $base)) {
        Write-Status ("{0} already default (no policy key)" -f $Browser) "Already"
        return $true
    }
    $removed = 0
    foreach ($n in $script:ChromiumBastionValueNames) {
        try {
            if ($null -ne (Get-ItemProperty -LiteralPath $base -Name $n -ErrorAction SilentlyContinue)) {
                Remove-ItemProperty -LiteralPath $base -Name $n -Force -ErrorAction Stop
                $removed++
                Write-Log ("Removed {0} policy value: {1}" -f $Browser, $n) -NoConsole
            }
        } catch {
            Write-Log ("Could not remove {0}\{1}: {2}" -f $Browser, $n, $_.Exception.Message) -Level Warning -NoConsole
        }
    }
    # If no values remain, remove the key.
    try {
        $key = Get-Item -LiteralPath $base -ErrorAction SilentlyContinue
        if ($key -and @($key.GetValueNames()).Count -eq 0) {
            Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log ("Removed empty policy key: {0}" -f $base) -NoConsole
        }
    } catch {}
    if ($removed -gt 0) {
        Write-Status ("{0} Bastion policy values removed ({1})" -f $Browser, $removed) "Applied"
        Write-Host "      Non-Bastion policy values (if any) were left in place." -ForegroundColor DarkGray
    } else {
        Write-Status ("{0}: no Bastion-managed values found" -f $Browser) "Already"
    }
    return $true
}

# -----------------------------------------------------------------------------
# Set-ChromiumPolicyMode
#   Write Chrome or Brave HKLM policies for Default / Medium / Strict.
#   EnableEch defaults false; Resolve-BrowserEchChoice re-gates so ECH pack
#   (BastionEchLock + optional EncryptedClientHelloEnabled) is only for
#   Strict + explicit true. Medium sets telemetry/cookie baseline without ECH.
# -----------------------------------------------------------------------------
function Set-ChromiumPolicyMode {
    param(
        [ValidateSet("Chrome","Brave")][string]$Browser,
        [ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch = $false
    )
    $base = Get-ChromiumPolicyBase -Browser $Browser
    $modeBefore = Get-ChromiumPolicyMode -Browser $Browser
    $echBefore = Test-ChromiumEchLockPresent -Browser $Browser
    try {
        if ($Mode -eq "Default") {
            $bak = Backup-ChromiumPolicyValues -Browser $Browser
            $bakPath = if ($bak.BackupFile) { [string]$bak.BackupFile } else { "" }
            [void](Remove-ChromiumBastionValues -Browser $Browser)
            if ($script:BrowserPolicyModes.Contains($Browser)) { $script:BrowserPolicyModes[$Browser] = "Default" }
            if ($script:BrowserEchLocks.Contains($Browser)) { $script:BrowserEchLocks[$Browser] = $false }
            Record-BrowserPolicyChange -Browser $Browser -ModeBefore $modeBefore -ModeAfter "Default" `
                -Detail ("Removed Bastion Chromium values (ECH intent was {0})" -f $(if ($echBefore) { "on" } else { "off" })) -BackupPath $bakPath
            return $true
        }

        # Encrypted Client Hello (ECH) pack: never by default; only explicit Yes + Strict.
        $EnableEch = Resolve-BrowserEchChoice -Mode $Mode -EnableEch:$EnableEch

        $bak = Backup-ChromiumPolicyValues -Browser $Browser
        $bakPath = if ($bak.BackupFile) { [string]$bak.BackupFile } else { "" }

        if ($Browser -eq "Chrome") {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Google")) {
                New-Item "HKLM:\SOFTWARE\Policies\Google" -Force | Out-Null
            }
        } else {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\BraveSoftware")) {
                New-Item "HKLM:\SOFTWARE\Policies\BraveSoftware" -Force | Out-Null
            }
        }
        if (-not (Test-Path $base)) { New-Item $base -Force | Out-Null }

        foreach ($n in @("BlockThirdPartyCookies","DefaultCookiesSetting","HttpsOnlyMode","DnsOverHttpsMode","BastionEchLock","EncryptedClientHelloEnabled")) {
            try { Remove-ItemProperty -LiteralPath $base -Name $n -Force -ErrorAction SilentlyContinue } catch {}
        }

        New-ItemProperty $base -Name "BastionManaged" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty $base -Name "MetricsReportingEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty $base -Name "SafeBrowsingEnabled" -Value 1 -PropertyType DWord -Force | Out-Null

        if ($Mode -eq "Strict") {
            New-ItemProperty $base -Name "HttpsOnlyMode" -Value 2 -PropertyType DWord -Force | Out-Null
            New-ItemProperty $base -Name "BlockThirdPartyCookies" -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty $base -Name "DnsOverHttpsMode" -Value 2 -PropertyType DWord -Force | Out-Null
            Write-Host ("      {0} Strict: HTTPS-Only force, third-party cookie block, DNS-over-HTTPS preference, telemetry off." -f $Browser) -ForegroundColor DarkGray
            if ($EnableEch) {
                # Intent marker + best-effort Chromium policy. Not identical to Firefox preference locks.
                New-ItemProperty $base -Name "BastionEchLock" -Value 1 -PropertyType DWord -Force | Out-Null
                try {
                    New-ItemProperty $base -Name "EncryptedClientHelloEnabled" -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                } catch {}
                Write-Host ("      Encrypted Client Hello (ECH) pack: ON for {0}." -f $Browser) -ForegroundColor DarkGray
                Write-Host "      Chromium cannot use Firefox policies.json prefs; Bastion records ECH intent and applies" -ForegroundColor DarkGray
                Write-Host "      the strongest transport policies available (HTTPS-Only + DNS-over-HTTPS + optional ECH policy)." -ForegroundColor DarkGray
            } else {
                Write-Host ("      Encrypted Client Hello (ECH) pack: OFF for {0} (optional; not selected)." -f $Browser) -ForegroundColor DarkGray
            }
        } else {
            New-ItemProperty $base -Name "BlockThirdPartyCookies" -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Host ("      {0} Medium: telemetry off, Safe Browsing on, third-party cookies blocked." -f $Browser) -ForegroundColor DarkGray
        }

        Write-Status ("{0} policies -> {1}{2}" -f $Browser, $Mode, $(if ($EnableEch) { " + ECH pack" } else { "" })) "Applied"
        if ($script:BrowserPolicyModes.Contains($Browser)) { $script:BrowserPolicyModes[$Browser] = $Mode }
        if ($script:BrowserEchLocks.Contains($Browser)) { $script:BrowserEchLocks[$Browser] = [bool]$EnableEch }
        Record-BrowserPolicyChange -Browser $Browser -ModeBefore $modeBefore -ModeAfter $Mode `
            -Detail ("Wrote Bastion {0} pack under {1}; ECH pack={2}" -f $Mode, $base, $EnableEch) -BackupPath $bakPath
        Write-Host ("      Revert this browser only: menu 6 > {0} > Default." -f $Browser) -ForegroundColor DarkGray
        return $true
    } catch {
        Write-Status ("{0} policy failed: {1}" -f $Browser, $_.Exception.Message) "Failed"
        return $false
    }
}

# -----------------------------------------------------------------------------
# Set-ChromePolicyMode / Set-BravePolicyMode
#   Thin wrappers around Set-ChromiumPolicyMode. EnableEch still defaults false.
# -----------------------------------------------------------------------------
function Set-ChromePolicyMode {
    param(
        [ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch = $false
    )
    return (Set-ChromiumPolicyMode -Browser Chrome -Mode $Mode -EnableEch:$EnableEch)
}

function Set-BravePolicyMode {
    param(
        [ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch = $false
    )
    return (Set-ChromiumPolicyMode -Browser Brave -Mode $Mode -EnableEch:$EnableEch)
}

# -----------------------------------------------------------------------------
# Get-InstalledBastionBrowsers
#   Menu 6 list builder: only engines that pass path detect. Never lists missing
#   browsers. Each row: live Mode, SavedMode, EchLive, EchSaved (wanted ECH only
#   when saved Strict and lock true), Key for Invoke-BastionBrowserPolicy.
# -----------------------------------------------------------------------------
function Get-InstalledBastionBrowsers {
    # Only supported browsers that are actually installed (path detect). Never list missing engines.
    $list = [System.Collections.Generic.List[object]]::new()
    $map = @(
        @{ Name = "Firefox"; Test = { Test-Installed -Name "Firefox" -Paths $script:ProgramDefs["Firefox"].Paths }; Set = "Firefox"; GetMode = { Get-FirefoxPolicyModeFromFile } }
        @{ Name = "Chrome";  Test = { Test-Installed -Name "Chrome"  -Paths $script:ProgramDefs["Chrome"].Paths  }; Set = "Chrome";  GetMode = { Get-ChromiumPolicyMode -Browser Chrome } }
        @{ Name = "Brave";   Test = { Test-Installed -Name "Brave"   -Paths $script:ProgramDefs["Brave"].Paths   }; Set = "Brave";   GetMode = { Get-ChromiumPolicyMode -Browser Brave } }
    )
    foreach ($m in $map) {
        $installed = $false
        try { $installed = [bool](& $m.Test) } catch { $installed = $false }
        if (-not $installed) { continue }

        $mode = "Default"
        try { $mode = & $m.GetMode } catch { $mode = "Custom" }
        $saved = if ($script:BrowserPolicyModes.Contains($m.Name)) { $script:BrowserPolicyModes[$m.Name] } else { "Default" }
        # Saved ECH only if explicitly true in state (defaults false).
        $echSaved = $false
        if ($script:BrowserEchLocks.Contains($m.Name) -and $script:BrowserEchLocks[$m.Name] -and $saved -eq "Strict") {
            $echSaved = $true
        }
        $echLive = $false
        try { $echLive = [bool](Test-BrowserEchLockLive -Browser $m.Name) } catch { $echLive = $false }
        [void]$list.Add([PSCustomObject]@{
            Name      = $m.Name
            Mode      = $mode
            SavedMode = $saved
            EchLive   = $echLive
            EchSaved  = $echSaved
            Key       = $m.Set
        })
    }
    return @($list)
}

# -----------------------------------------------------------------------------
# Invoke-BastionBrowserPolicy
#   Public entry from menus / Apply for one browser. Refuses missing engines.
#   Re-gates EnableEch through Resolve-BrowserEchChoice (never default ECH).
#   Dispatches to Set-FirefoxPolicyMode or Set-Chrome/BravePolicyMode.
# -----------------------------------------------------------------------------
function Invoke-BastionBrowserPolicy {
    param(
        [Parameter(Mandatory)][ValidateSet("Firefox","Chrome","Brave")][string]$Browser,
        [Parameter(Mandatory)][ValidateSet("Default","Medium","Strict")][string]$Mode,
        [bool]$EnableEch = $false
    )
    # Refuse to configure a browser that is not installed.
    if (-not $script:ProgramDefs.Contains($Browser)) {
        Write-Status ("{0} is not a supported Bastion browser" -f $Browser) "Failed"
        return $false
    }
    if (-not (Test-Installed -Name $Browser -Paths $script:ProgramDefs[$Browser].Paths)) {
        Write-Status ("{0} is not installed; skipping policy change" -f $Browser) "Skip"
        return $false
    }
    # Final ECH gate: Medium/Default and Strict-without-Yes never enable the pack.
    $EnableEch = Resolve-BrowserEchChoice -Mode $Mode -EnableEch:$EnableEch
    switch ($Browser) {
        "Firefox" { return (Set-FirefoxPolicyMode -Mode $Mode -EnableEch:$EnableEch) }
        "Chrome"  { return (Set-ChromePolicyMode -Mode $Mode -EnableEch:$EnableEch) }
        "Brave"   { return (Set-BravePolicyMode -Mode $Mode -EnableEch:$EnableEch) }
    }
    return $false
}
