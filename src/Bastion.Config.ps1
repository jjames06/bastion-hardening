# Bastion.Config.ps1 - modular domain (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.

function Get-BastionDataDirCandidates {
    # Discovery order for existing state + durable fallbacks. %TEMP%\Bastion is last (wipe-prone).
    $raw = @(
        (Join-Path "C:\Temp" "Bastion"),
        "C:\Temp",   # legacy flat layout (pre-subfolder)
        (Join-Path $env:ProgramData "Bastion"),
        (Join-Path $env:LOCALAPPDATA "Bastion"),
        (Join-Path $env:TEMP "Bastion")
    )
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($c in $raw) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        if (-not $list.Contains($c)) { [void]$list.Add($c) }
    }
    return @($list)
}

function Test-BastionDirWritable {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $probe = Join-Path $Path ("bastion-write-test-{0}.tmp" -f [guid]::NewGuid().ToString("N"))
        Set-Content -LiteralPath $probe -Value "ok" -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

function Test-BastionStatePresent {
    param([string]$Dir)
    if ([string]::IsNullOrWhiteSpace($Dir)) { return $false }
    if (-not (Test-Path -LiteralPath $Dir)) { return $false }
    foreach ($name in @("Bastion-Config.json", "Bastion-LastApply.json", "Bastion-BrowserPolicies-State.json", "Bastion-Session.json")) {
        if (Test-Path -LiteralPath (Join-Path $Dir $name)) { return $true }
    }
    return $false
}

function Resolve-BastionLogDirectory {
    # 1) Reuse a writable dir that already has Bastion state (prefer newest config).
    # 2) Else create the first durable writable path (never invent Apply history).
    $candidates = @(Get-BastionDataDirCandidates)
    $withState = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $candidates) {
        if (-not (Test-Path -LiteralPath $c)) { continue }
        if (-not (Test-BastionStatePresent -Dir $c)) { continue }
        if (-not (Test-BastionDirWritable -Path $c)) { continue }
        $cfg = Join-Path $c "Bastion-Config.json"
        $mtime = [datetime]::MinValue
        if (Test-Path -LiteralPath $cfg) {
            try { $mtime = (Get-Item -LiteralPath $cfg).LastWriteTimeUtc } catch {}
        }
        [void]$withState.Add([PSCustomObject]@{ Path = $c; Mtime = $mtime })
    }
    if ($withState.Count -gt 0) {
        $best = $withState | Sort-Object Mtime -Descending | Select-Object -First 1
        return $best.Path
    }

    # New store: durable first. Prefer C:\Temp\Bastion over flat C:\Temp and over wipeable %TEMP%.
    $preferredNew = @(
        (Join-Path "C:\Temp" "Bastion"),
        (Join-Path $env:ProgramData "Bastion"),
        (Join-Path $env:LOCALAPPDATA "Bastion"),
        "C:\Temp",
        (Join-Path $env:TEMP "Bastion")
    )
    foreach ($c in $preferredNew) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        if (Test-BastionDirWritable -Path $c) { return $c }
    }
    return $null
}

function Bind-BastionDataPaths {
    param([string]$LogDirectory)
    $script:Config.LogDirectory = $LogDirectory
    $script:logFile    = Join-Path $LogDirectory ("Bastion-Log-{0}.txt" -f $script:timestamp)
    $script:tempDir    = Join-Path $LogDirectory "BastionInstallers"
    $script:undoFile   = Join-Path $LogDirectory "Bastion-LastApply.json"
    $script:configFile = Join-Path $LogDirectory "Bastion-Config.json"
    $script:sessionFile = Join-Path $LogDirectory "Bastion-Session.json"
}

function Ensure-BastionPaths {
    try {
        # Re-resolve if preferred path became unusable mid-session
        if (-not (Test-Path -LiteralPath $script:Config.LogDirectory) -or -not (Test-BastionDirWritable -Path $script:Config.LogDirectory)) {
            $again = Resolve-BastionLogDirectory
            if ($again) {
                Bind-BastionDataPaths -LogDirectory $again
            }
        }
        $backupDir = Join-Path $script:Config.LogDirectory "browser-policy-backups"
        foreach ($p in @($script:Config.LogDirectory, $script:tempDir, $backupDir)) {
            if (-not (Test-Path -LiteralPath $p)) {
                New-Item -Path $p -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
        }
        if (-not $script:sessionFile) {
            $script:sessionFile = Join-Path $script:Config.LogDirectory "Bastion-Session.json"
        }
        return $true
    } catch {
        Write-Host ("  ERROR: Cannot prepare Bastion data directory ({0}): {1}" -f $script:Config.LogDirectory, $_.Exception.Message) -ForegroundColor Red
        return $false
    }
}

function Save-BrowserPolicyStateFile {
    if (-not (Ensure-BastionPaths)) { return }
    try {
        $path = Get-BrowserPolicyStatePath
        $live = Get-LiveBrowserPostureSnapshot
        $data = @{
            UpdatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ScriptVersion = $script:Config.ScriptVersion
            # Wanted (menu / Bastion-Config) vs Live (policies on disk / registry).
            Modes = [ordered]@{}
            EchLocks = [ordered]@{}
            LiveModes = $live.Modes
            LiveEch = $live.Ech
            Installed = $live.Installed
            LastChange = $script:BrowserPolicyLastChange
            Note = "Wanted modes come from Bastion config. Live modes are detected each save. Deleting this file does not fake Apply history."
        }
        foreach ($k in $script:BrowserPolicyModes.Keys) {
            $data.Modes[$k] = $script:BrowserPolicyModes[$k]
        }
        foreach ($k in $script:BrowserEchLocks.Keys) {
            $data.EchLocks[$k] = [bool]$script:BrowserEchLocks[$k]
        }
        ($data | ConvertTo-Json -Depth 8) | Out-File -LiteralPath $path -Encoding utf8 -Force
        Write-Log ("Browser policy state saved: {0}" -f $path) -NoConsole
    } catch {
        Write-Log ("Browser policy state save failed: {0}" -f $_.Exception.Message) -Level Warning -NoConsole
    }
}

function Load-BrowserPolicyStateFile {
    # Restore last-change metadata only. Wanted modes live in Bastion-Config.json.
    $path = Get-BrowserPolicyStatePath
    if (-not (Test-Path -LiteralPath $path)) { return }
    try {
        $data = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($data.LastChange) {
            $lc = $data.LastChange
            $script:BrowserPolicyLastChange = @{
                Timestamp  = [string]$lc.Timestamp
                Browser    = [string]$lc.Browser
                ModeBefore = [string]$lc.ModeBefore
                ModeAfter  = [string]$lc.ModeAfter
                Detail     = [string]$lc.Detail
                BackupPath = [string]$lc.BackupPath
                LogFile    = [string]$lc.LogFile
            }
        }
    } catch {
        Write-Log ("Browser policy state load failed: {0}" -f $_.Exception.Message) -Level Warning -NoConsole
    }
}

function Write-BastionSessionSnapshot {
    # Rewritten every launch: proves the store is real and records live detection vs Bastion files.
    if (-not (Ensure-BastionPaths)) { return }
    try {
        if (-not $script:sessionFile) {
            $script:sessionFile = Join-Path $script:Config.LogDirectory "Bastion-Session.json"
        }
        $live = Get-LiveBrowserPostureSnapshot
        $wantedModes = [ordered]@{}
        $wantedEch = [ordered]@{}
        foreach ($k in $script:BrowserPolicyModes.Keys) { $wantedModes[$k] = [string]$script:BrowserPolicyModes[$k] }
        foreach ($k in $script:BrowserEchLocks.Keys) { $wantedEch[$k] = [bool]$script:BrowserEchLocks[$k] }
        $sectionSnap = [ordered]@{}
        foreach ($k in $script:Sections.Keys) { $sectionSnap[$k] = [bool]$script:Sections[$k] }
        $data = [ordered]@{
            WrittenAt         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ScriptVersion     = $script:Config.ScriptVersion
            DataDirectory     = $script:Config.LogDirectory
            HadPriorConfig    = [bool]$script:HadPriorConfig
            HadPriorApply     = [bool]$script:HadPriorApply
            ConfigLoaded      = [bool]$script:ConfigLoaded
            FirstRunSeeded    = [bool]$script:FirstRunSeeded
            DnsProviderId     = [string]$script:DnsProviderId
            SectionsEnabled   = $sectionSnap
            WantedBrowserModes = $wantedModes
            WantedBrowserEch   = $wantedEch
            LiveBrowserModes   = $live.Modes
            LiveBrowserEch     = $live.Ech
            BrowsersInstalled  = $live.Installed
            HasConfigFile      = (Test-Path -LiteralPath $script:configFile)
            HasLastApplyFile   = (Test-Path -LiteralPath $script:undoFile)
            Note = "Apply and Dry Run detect live Windows state. Bastion-LastApply.json is only written after a real Apply. Deleting this data directory just forces a clean seed next run - it does not invent prior hardening."
        }
        ($data | ConvertTo-Json -Depth 8) | Out-File -LiteralPath $script:sessionFile -Encoding utf8 -Force
        Write-Log ("Session snapshot written: {0}" -f $script:sessionFile) -NoConsole
    } catch {
        Write-Log ("Session snapshot failed: {0}" -f $_.Exception.Message) -Level Warning -NoConsole
    }
}

function Initialize-BastionDataStore {
    # First bat/ps1 run (and every later run): ensure dirs exist, load real files if present,
    # seed defaults only when missing, rewrite session/browser state from live detection.
    # Never invent Bastion-LastApply.json without a completed Apply.
    if (-not (Ensure-BastionPaths)) {
        $script:DataStoreReady = $false
        return $false
    }

    $script:HadPriorConfig = Test-Path -LiteralPath $script:configFile
    $script:HadPriorApply  = Test-Path -LiteralPath $script:undoFile
    $script:FirstRunSeeded = $false

    Load-BastionConfig
    Load-BrowserPolicyStateFile

    if (-not $script:HadPriorConfig) {
        # Materialize a real config on first run / after wipe so the store is not empty theater.
        Save-BastionConfig
        $script:FirstRunSeeded = $true
        Write-Log "First-run (or wiped store): seeded Bastion-Config.json with defaults (no Apply history invented)."
    }

    # Always refresh browser policy state + session snapshot from live OS + current wants.
    Save-BrowserPolicyStateFile
    Write-BastionSessionSnapshot

    $script:DataStoreReady = $true
    Write-Log ("Data store ready at {0} (priorConfig={1} priorApply={2} seeded={3})" -f `
        $script:Config.LogDirectory, $script:HadPriorConfig, $script:HadPriorApply, $script:FirstRunSeeded)
    return $true
}

function Protect-BastionBlob {
    param([Parameter(Mandatory)][string]$PlainText)
    try {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        $prot = [System.Security.Cryptography.ProtectedData]::Protect(
            $bytes,
            $script:BastionDpapiEntropy,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [Convert]::ToBase64String($prot)
    } catch {
        Write-Log ("Protect-BastionBlob failed: {0}" -f $_.Exception.Message) -Level Warning
        return $null
    }
}

function Unprotect-BastionBlob {
    param([Parameter(Mandatory)][string]$Base64)
    try {
        if ([string]::IsNullOrWhiteSpace($Base64)) { return $null }
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null
        $prot = [Convert]::FromBase64String($Base64)
        $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $prot,
            $script:BastionDpapiEntropy,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    } catch {
        Write-Log ("Unprotect-BastionBlob failed: {0}" -f $_.Exception.Message) -Level Warning
        return $null
    }
}

function Set-BastionSensitiveFileAcl {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        # SYSTEM + Administrators only; strip inherited ACEs so local standard users cannot read undo blobs.
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        $rules = @($acl.Access)
        foreach ($r in $rules) {
            try { [void]$acl.RemoveAccessRule($r) } catch {}
        }
        $system = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "Allow"
        )
        $admins = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators", "FullControl", "Allow"
        )
        $acl.AddAccessRule($system)
        $acl.AddAccessRule($admins)
        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch {
        Write-Log ("Set-BastionSensitiveFileAcl failed: {0}" -f $_.Exception.Message) -Level Warning
    }
}

function Test-BastionUndoHasDnsSnapshot {
    param($UndoData)
    if ($null -eq $UndoData) { return $false }
    try {
        if ($UndoData.HasDnsSnapshot -eq $true) { return $true }
        if ($UndoData.DnsSnapshotProtected) { return $true }
    } catch {}
    return $false
}

function Get-BastionDnsSnapshotFromUndo {
    param($UndoData)
    if ($null -eq $UndoData) { return $null }
    try {
        if ($UndoData.DnsSnapshotProtected) {
            $plain = Unprotect-BastionBlob -Base64 ([string]$UndoData.DnsSnapshotProtected)
            if ($plain) {
                return ($plain | ConvertFrom-Json)
            }
            Write-Status "Could not decrypt DNS snapshot (wrong Windows user or damaged file)" "Warn"
            return $null
        }
    } catch {}
    return $null
}

function Save-BastionConfig {
    if (-not (Ensure-BastionPaths)) { return }
    try {
        $data = @{
            Version = $script:Config.ScriptVersion
            SavedAt = Get-Date -Format "yyyy-MM-dd HH:mm"
            Sections = [ordered]@{}
            SelectedApps = @($script:SelectedApps)
            GlobalInstallRoot = $script:GlobalInstallRoot
            ProgramInstallRoots = @{}
            BrowserPolicyMode = $script:BrowserPolicyMode
            BrowserPolicyModes = [ordered]@{}
            BrowserEchLocks = [ordered]@{}
            DnsProviderId = $script:DnsProviderId
            WowInstallRoots = @($script:WowInstallRoots)
            StrictHandleExceptionPaths = @($script:StrictHandleExceptionPaths)
        }
        foreach ($k in $script:Sections.Keys) { $data.Sections[$k] = [bool]$script:Sections[$k] }
        foreach ($k in $script:ProgramInstallRoots.Keys) { $data.ProgramInstallRoots[$k] = $script:ProgramInstallRoots[$k] }
        foreach ($k in $script:BrowserPolicyModes.Keys) { $data.BrowserPolicyModes[$k] = [string]$script:BrowserPolicyModes[$k] }
        foreach ($k in $script:BrowserEchLocks.Keys) { $data.BrowserEchLocks[$k] = [bool]$script:BrowserEchLocks[$k] }
        $data | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $script:configFile -Encoding utf8 -Force
        # Preferences are not secret, but ACL reduces casual read of custom paths / section choices
        # by local standard users (same posture as undo file: SYSTEM + Administrators).
        Set-BastionSensitiveFileAcl -Path $script:configFile
    } catch {
        Write-Log ("Config save failed: {0}" -f $_.Exception.Message) -Level Warning
    }
}

function Load-BastionConfig {
    if (-not (Test-Path -LiteralPath $script:configFile)) { return }
    try {
        $data = Get-Content -LiteralPath $script:configFile -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($data.Sections) {
            foreach ($prop in $data.Sections.PSObject.Properties) {
                if ($script:Sections.Contains($prop.Name)) {
                    $script:Sections[$prop.Name] = [bool]$prop.Value
                }
            }
        }
        if ($data.SelectedApps) {
            $script:SelectedApps.Clear()
            foreach ($a in @($data.SelectedApps)) {
                if ($script:ProgramDefs.Contains("$a")) { [void]$script:SelectedApps.Add("$a") }
            }
            # Drop names already present on disk so the install menu is not pre-checked.
            Sync-ProgramInstallQueue
        }
        if ($data.BrowserPolicyMode) { $script:BrowserPolicyMode = [string]$data.BrowserPolicyMode }
        if ($data.BrowserPolicyModes) {
            foreach ($prop in $data.BrowserPolicyModes.PSObject.Properties) {
                if ($script:BrowserPolicyModes.Contains($prop.Name)) {
                    $v = [string]$prop.Value
                    if ($v -in @("Default","Medium","Strict")) {
                        $script:BrowserPolicyModes[$prop.Name] = $v
                    }
                }
            }
        } elseif ($data.BrowserPolicyMode -and $data.BrowserPolicyMode -in @("Default","Medium","Strict")) {
            foreach ($k in @($script:BrowserPolicyModes.Keys)) {
                $script:BrowserPolicyModes[$k] = [string]$data.BrowserPolicyMode
            }
        }
        # Start from all-false, then apply only explicit saved Yes flags (never infer ECH from Strict alone).
        Clear-BrowserEchLocksAll
        if ($data.BrowserEchLocks) {
            foreach ($prop in $data.BrowserEchLocks.PSObject.Properties) {
                if ($script:BrowserEchLocks.Contains($prop.Name) -and [bool]$prop.Value) {
                    # Only honor saved ECH Yes when that browser's saved mode is Strict.
                    $modeForBrowser = if ($script:BrowserPolicyModes.Contains($prop.Name)) {
                        $script:BrowserPolicyModes[$prop.Name]
                    } else { "Default" }
                    if ($modeForBrowser -eq "Strict") {
                        $script:BrowserEchLocks[$prop.Name] = $true
                    }
                }
            }
        }
        if ($data.DnsProviderId -and $script:DnsProviders.Contains([string]$data.DnsProviderId)) {
            $script:DnsProviderId = [string]$data.DnsProviderId
            if ($script:DnsProviderId -eq "None") { $script:Sections["DNS"] = $false }
        }
        # If DNS section is off after load, treat provider as None for clear UI unless a real provider was saved.
        if (-not $script:Sections["DNS"] -and $script:DnsProviderId -ne "None") {
            # Keep last real provider in memory for re-enable, but label shows do-not-change via Sections.
        }
        $script:ProgramInstallRoots = @{}
        $vols = @(Get-AvailableInstallVolumes)
        if ($data.ProgramInstallRoots) {
            foreach ($prop in $data.ProgramInstallRoots.PSObject.Properties) {
                if ($script:ProgramDefs.Contains($prop.Name) -and $prop.Value) {
                    $check = Test-SafeInstallRoot -Path ([string]$prop.Value) -AllowedVolumes $vols
                    if ($check.Ok) { $script:ProgramInstallRoots[$prop.Name] = $check.Path }
                }
            }
        }
        if ($data.GlobalInstallRoot) {
            $check = Test-SafeInstallRoot -Path ([string]$data.GlobalInstallRoot) -AllowedVolumes $vols
            $script:GlobalInstallRoot = $(if ($check.Ok) { $check.Path } else { $null })
        }
        # Optional StrictHandle / WoW discovery overrides (any path the user trusts).
        $script:WowInstallRoots = [System.Collections.Generic.List[string]]::new()
        if ($data.WowInstallRoots) {
            foreach ($r in @($data.WowInstallRoots)) {
                $n = ConvertTo-BastionNormalizedPath -Raw ([string]$r)
                if ($n -and (Test-Path -LiteralPath $n -PathType Container) -and -not $script:WowInstallRoots.Contains($n)) {
                    [void]$script:WowInstallRoots.Add($n)
                }
            }
        }
        $script:StrictHandleExceptionPaths = [System.Collections.Generic.List[string]]::new()
        if ($data.StrictHandleExceptionPaths) {
            foreach ($e in @($data.StrictHandleExceptionPaths)) {
                $n = ConvertTo-BastionNormalizedPath -Raw ([string]$e)
                if ($n -and (Test-Path -LiteralPath $n -PathType Leaf) -and $n -match '\.exe$' -and -not $script:StrictHandleExceptionPaths.Contains($n)) {
                    [void]$script:StrictHandleExceptionPaths.Add($n)
                }
            }
        }
        $script:ConfigLoaded = $true
    } catch {
        Write-Log ("Config load failed: {0}" -f $_.Exception.Message) -Level Warning
    }
}

function Save-UndoData($Data) {
    if (-not (Ensure-BastionPaths)) { return }
    try {
        if ($Data -isnot [hashtable]) {
            Write-Log "Save-UndoData expected hashtable" -Level Warning
            return
        }

        # Never write plaintext DNS history; store DPAPI-protected blob only.
        $wroteNewDns = $false
        if ($Data.ContainsKey("DnsSnapshot") -and $Data["DnsSnapshot"]) {
            $snapJson = ($Data["DnsSnapshot"] | ConvertTo-Json -Depth 8 -Compress)
            $blob = Protect-BastionBlob -PlainText $snapJson
            if ($blob) {
                $Data["DnsSnapshotProtected"] = $blob
                $Data["HasDnsSnapshot"] = $true
                $wroteNewDns = $true
            } else {
                Write-Log "DNS snapshot encryption failed; will try preserve prior blob" -Level Warning
                $Data["HasDnsSnapshot"] = $false
            }
            [void]$Data.Remove("DnsSnapshot")
        }

        $wroteNewRdp = $false
        if ($Data.ContainsKey("RdpHostPrior") -and $Data["RdpHostPrior"]) {
            $priorJson = ($Data["RdpHostPrior"] | ConvertTo-Json -Depth 6 -Compress)
            $priorBlob = Protect-BastionBlob -PlainText $priorJson
            if ($priorBlob) {
                $Data["RdpHostPriorProtected"] = $priorBlob
                $wroteNewRdp = $true
            } else {
                Write-Log "RDP host prior encryption failed; will try preserve prior blob" -Level Warning
                $Data["RdpHostLocked"] = $false
            }
            [void]$Data.Remove("RdpHostPrior")
        }

        # Critical: do not wipe DNS/RDP secrets on later Applies that did not re-capture them
        # (e.g. DNS already matched provider, or RdpHostLock off this run).
        $existing = $null
        if (Test-Path -LiteralPath $script:undoFile) {
            try {
                $existing = Get-Content -LiteralPath $script:undoFile -Raw -ErrorAction Stop | ConvertFrom-Json
            } catch { $existing = $null }
        }
        if ($existing) {
            $hasNewDnsBlob = $wroteNewDns -or (
                $Data.ContainsKey("DnsSnapshotProtected") -and $Data["DnsSnapshotProtected"]
            )
            if (-not $hasNewDnsBlob -and $existing.DnsSnapshotProtected) {
                $Data["DnsSnapshotProtected"] = [string]$existing.DnsSnapshotProtected
                $Data["HasDnsSnapshot"] = $true
                Write-Log "Preserved existing DNS snapshot blob across Apply (no new capture this run)" -NoConsole
            }
            $hasNewRdpBlob = $wroteNewRdp -or (
                $Data.ContainsKey("RdpHostPriorProtected") -and $Data["RdpHostPriorProtected"]
            )
            if (-not $hasNewRdpBlob -and $existing.RdpHostPriorProtected) {
                $Data["RdpHostPriorProtected"] = [string]$existing.RdpHostPriorProtected
                $Data["RdpHostLocked"] = $true
                Write-Log "Preserved existing RDP host prior blob across Apply" -NoConsole
            }
        }

        if (-not $Data.ContainsKey("HasDnsSnapshot")) {
            $Data["HasDnsSnapshot"] = [bool]($Data["DnsSnapshotProtected"])
        }

        $Data | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $script:undoFile -Encoding utf8 -Force
        Set-BastionSensitiveFileAcl -Path $script:undoFile
    } catch {
        Write-Log ("Undo save failed: {0}" -f $_.Exception.Message) -Level Warning
    }
}

function Get-BastionDnsSnapshotPreviewText {
    param($UndoData)
    $snap = Get-BastionDnsSnapshotFromUndo -UndoData $UndoData
    if (-not $snap) { return "unavailable (cannot decrypt or missing)" }
    $parts = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($row in @($snap.Adapters)) {
            $name = [string]$row.Name
            $wasEmpty = $false
            try { $wasEmpty = [bool]$row.WasEmpty } catch {}
            $servers = @()
            try {
                if ($row.Servers -is [string]) { $servers = @([string]$row.Servers) }
                else { $servers = @($row.Servers | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
            } catch {}
            if ($wasEmpty -or $servers.Count -eq 0) {
                [void]$parts.Add(("{0}=DHCP/auto" -f $name))
            } else {
                [void]$parts.Add(("{0}={1}" -f $name, ($servers -join "/")))
            }
        }
    } catch {}
    if ($parts.Count -eq 0) { return "empty snapshot" }
    return ($parts -join "; ")
}

function Get-BastionRdpHostPriorFromUndo {
    param($UndoData)
    if ($null -eq $UndoData) { return $null }
    try {
        if ($UndoData.RdpHostPriorProtected) {
            $plain = Unprotect-BastionBlob -Base64 ([string]$UndoData.RdpHostPriorProtected)
            if ($plain) { return ($plain | ConvertFrom-Json) }
            Write-Status "Could not decrypt RDP host prior (wrong Windows user or damaged file)" "Warn"
            return $null
        }
        # Legacy / intermediate builds may have stored prior in plaintext.
        if ($UndoData.RdpHostPrior) { return $UndoData.RdpHostPrior }
    } catch {}
    return $null
}

function Read-BastionUndoData {
    if (-not (Test-Path -LiteralPath $script:undoFile)) { return $null }
    try {
        return (Get-Content -LiteralPath $script:undoFile -Raw -ErrorAction Stop | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Get-LastApplyInfo {
    $d = Read-BastionUndoData
    if (-not $d) { return $null }
    try {
        return [PSCustomObject]@{
            Timestamp = $d.Timestamp
            ScriptVersion = $d.ScriptVersion
            SectionsRun = @($d.SectionsRun)
            HasDnsSnapshot = [bool](Test-BastionUndoHasDnsSnapshot -UndoData $d)
            RdpHostLocked = [bool]($d.RdpHostLocked)
        }
    } catch { return $null }
}
