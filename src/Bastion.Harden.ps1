# Bastion.Harden.ps1 - modular domain (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.
#
# Role in modular architecture:
#   Section helper implementations used by Apply, Dry Run, Audit, and Recovery:
#   Game DVR silence, OneDrive removal, bloat Appx detection, Defender CFA allow paths,
#   World of Warcraft discovery for StrictHandle exceptions, registry soft-set helpers,
#   suggestion restore, and OS Remote Desktop host allow/deny.
#
# Load-order position: 8 of 11 (after Dns, before Apply).
#   Order: Init, Core, Config, Programs, Services, Browsers, Dns, Harden, Apply, Recovery, Menus.
#
# Dependencies on $script: state:
#   $script:ProgramDefs / ExtraCfaPaths     - CFA candidate paths
#   $script:BloatAppxList                  - curated package match list
#   $script:SuggestionRegistry             - Widgets/Suggestions keys
#   $script:WowInstallRoots                - config override WoW roots
#   $script:StrictHandleExceptionPaths     - explicit full EXE exception paths
#   $script:tempDir                        - reg.exe fallback I/O
#
# Honesty (StrictHandle):
#   System-wide StrictHandle hardens most processes. Some loaders (documented: WoW) break
#   until a per-app exception. Bastion auto-excepts discovered Wow*.exe; other titles may
#   still break until reported. Recovery > 6 is the supported reverse path. See issue #18.

function Test-BastionGameDvrSilenced {
    <#
      Purpose:
        True when common Game DVR / capture flags look off (user and/or policy).

      When called:
        Dry Run XboxGaming preview; Audit-style checks if needed.

      Side effects:
        Registry reads only (HKCU GameConfigStore/GameDVR, HKLM GameDVR policy).

      Undo implications:
        None (status only).
    #>
    # True when common Game DVR / capture flags are off (games titles less likely to open ms-gamingoverlay).
    try {
        $gcs = (Get-ItemProperty "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -ErrorAction SilentlyContinue).GameDVR_Enabled
        $cap = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -ErrorAction SilentlyContinue).AppCaptureEnabled
        $pol = $null
        try {
            $pol = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name AllowGameDVR -ErrorAction SilentlyContinue).AllowGameDVR
        } catch {}
        $userOff = ($gcs -eq 0 -or "$gcs" -eq "0") -and ($cap -eq 0 -or "$cap" -eq "0" -or $null -eq $cap)
        $polOff = ($pol -eq 0 -or "$pol" -eq "0")
        return [bool]($userOff -or $polOff)
    } catch {
        return $false
    }
}

function Disable-BastionGameDvrOverlay {
    <#
      Purpose:
        Silence ms-gamingoverlay prompts when Game Bar is gone but Game DVR flags still on.
        Does not reinstall Xbox; registry/policy only.

      When called:
        Apply XboxGaming section; Apply BloatApps when overlay removed/absent.
        Immediate during Apply (not Dry Run).

      Side effects / Windows objects touched:
        - HKCU GameDVR AppCaptureEnabled=0, GameConfigStore GameDVR_Enabled=0
        - HKCU GameBar AutoGameMode / nexus flags to 0
        - HKLM Policies\...\GameDVR AllowGameDVR=0 when elevated write succeeds

      Undo implications:
        Enable-BastionGameDvrOverlay (Recovery) reverses common flags. Policy key may need
        remove; Game Bar itself is Store reinstall, not Bastion.
    #>
    # Silence "Get an app to open this ms-gamingoverlay link" when Game Bar / XboxGamingOverlay is gone
    # but GameDVR is still enabled and games keep invoking the protocol.
    # Does not reinstall Xbox; only policy/registry so apps stop asking for the overlay.
    param([switch]$Quiet)
    $changed = 0
    try {
        if (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR")) {
            New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Force | Out-Null
        }
        $curCap = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -ErrorAction SilentlyContinue).AppCaptureEnabled
        if ($curCap -ne 0) {
            Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Value 0 -Type DWord -Force
            $changed++
        }
        if (-not (Test-Path "HKCU:\System\GameConfigStore")) {
            New-Item "HKCU:\System\GameConfigStore" -Force | Out-Null
        }
        $curG = (Get-ItemProperty "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -ErrorAction SilentlyContinue).GameDVR_Enabled
        if ($curG -ne 0) {
            Set-ItemProperty "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Value 0 -Type DWord -Force
            $changed++
        }
        if (-not (Test-Path "HKCU:\Software\Microsoft\GameBar")) {
            New-Item "HKCU:\Software\Microsoft\GameBar" -Force | Out-Null
        }
        foreach ($pair in @(
                @{ N = "AutoGameModeEnabled"; V = 0 },
                @{ N = "AllowAutoGameMode"; V = 0 },
                @{ N = "UseNexusForGameBarEnabled"; V = 0 }
            )) {
            try {
                $c = (Get-ItemProperty "HKCU:\Software\Microsoft\GameBar" -Name $pair.N -ErrorAction SilentlyContinue).($pair.N)
                if ($c -ne $pair.V) {
                    Set-ItemProperty "HKCU:\Software\Microsoft\GameBar" -Name $pair.N -Value $pair.V -Type DWord -Force
                    $changed++
                }
            } catch {
                Set-ItemProperty "HKCU:\Software\Microsoft\GameBar" -Name $pair.N -Value $pair.V -Type DWord -Force -ErrorAction SilentlyContinue
                $changed++
            }
        }
        # Machine policy (elevated Apply): discourages Game DVR system-wide for this user profile policy scope
        try {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
                New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
            }
            $pol = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name AllowGameDVR -ErrorAction SilentlyContinue).AllowGameDVR
            if ($pol -ne 0) {
                Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name AllowGameDVR -Value 0 -Type DWord -Force
                $changed++
            }
        } catch {
            Write-Log ("GameDVR policy write skipped: {0}" -f $_.Exception.Message) -Level Warning -NoConsole
        }
        if ($changed -gt 0) {
            Write-Status "Game DVR / Game Bar capture disabled (silences missing ms-gamingoverlay prompts)" "Applied"
        } else {
            if (-not $Quiet) {
                Write-Status "Game DVR / Game Bar capture already silenced" "Already"
            }
        }
        Write-Log "Disable-BastionGameDvrOverlay changed=$changed" -NoConsole
        return $changed
    } catch {
        Write-Status ("Game DVR silence failed: {0}" -f $_.Exception.Message) "Warn"
        return 0
    }
}

function Enable-BastionGameDvrOverlay {
    <#
      Purpose:
        Reverse silence: re-enable Game DVR user flags and remove AllowGameDVR policy value.

      When called:
        Recovery gaming / overlay path. Immediate apply.

      Side effects:
        HKCU GameDVR flags = 1; Remove-ItemProperty AllowGameDVR if present.

      Undo implications:
        Does not install XboxGamingOverlay; user may still need Store package.
    #>
    # Reverse of silence: re-enable Game DVR flags so Xbox Game Bar can work again if reinstalled from Store.
    try {
        if (-not (Test-Path "HKCU:\System\GameConfigStore")) {
            New-Item "HKCU:\System\GameConfigStore" -Force | Out-Null
        }
        Set-ItemProperty "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Value 1 -Type DWord -Force
        if (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR")) {
            New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Force | Out-Null
        }
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Value 1 -Type DWord -Force
        try {
            if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR") {
                Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name AllowGameDVR -Force -ErrorAction SilentlyContinue
            }
        } catch {}
        Write-Status "Game DVR flags re-enabled (install Xbox Game Bar from Microsoft Store if overlay is still missing)" "Applied"
        Write-Host "      Settings > Gaming > Xbox Game Bar, or Store package Microsoft.XboxGamingOverlay." -ForegroundColor DarkGray
        return $true
    } catch {
        Write-Status ("Could not re-enable Game DVR: {0}" -f $_.Exception.Message) "Warn"
        return $false
    }
}

function Get-OneDriveStatus {
    <#
      Purpose:
        Detect OneDrive client presence via process name and common install binary paths.

      When called:
        Dry Run OneDrive section, Audit, Remove-BastionOneDrive before/after.

      Side effects:
        Process and filesystem probes only.
    #>
    $signals = [System.Collections.Generic.List[string]]::new()
    if (Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue) {
        [void]$signals.Add("process")
    }
    $pf86 = ${env:ProgramFiles(x86)}
    foreach ($p in @(
        "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
        "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
        $(if ($pf86) { Join-Path $pf86 "Microsoft OneDrive\OneDrive.exe" } else { $null })
    )) {
        if ($p -and (Test-Path -LiteralPath $p)) {
            [void]$signals.Add(("binary:{0}" -f $p))
        }
    }
    return [PSCustomObject]@{
        Present = ($signals.Count -gt 0)
        Detail  = $(if ($signals.Count) { $signals -join ", " } else { "Not present" })
    }
}

function Remove-BastionOneDrive {
    <#
      Purpose:
        Uninstall OneDrive client via OneDriveSetup.exe /uninstall /allusers after stopping process.

      When called:
        Apply OneDrive section. Not Dry Run.

      Side effects / Windows objects touched:
        - Stop-Process OneDrive
        - OneDriveSetup.exe uninstall (machine)
        - Cloud files may remain on disk; client sync stops when binary removed

      Undo implications:
        Hard to reverse automatically; reinstall from Microsoft. Not stored as restore blob.
        Residual detection after uninstall reports Failed with manual next steps.
    #>
    $before = Get-OneDriveStatus
    if (-not $before.Present) {
        Write-Status "OneDrive not present" "Already"
        return
    }

    Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $setup = @(
        "$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
        "$env:SystemRoot\System32\OneDriveSetup.exe"
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if (-not $setup) {
        Write-Status "OneDriveSetup.exe not found. Next step: Settings > Apps > uninstall OneDrive manually." "Failed"
        return
    }

    try {
        $p = Start-Process -FilePath $setup -ArgumentList @("/uninstall","/allusers") -Wait -PassThru -ErrorAction Stop
        Write-Host ("      OneDriveSetup exit {0}" -f $p.ExitCode) -ForegroundColor DarkGray
    } catch {
        Write-Status ("OneDriveSetup failed: {0}. Next step: uninstall from Settings > Apps." -f $_.Exception.Message) "Failed"
        return
    }

    Start-Sleep -Seconds 2
    Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $after = Get-OneDriveStatus
    if ($after.Present) {
        Write-Status ("OneDrive residual still detected ({0}). Next step: reboot and re-run, or remove leftover package manually." -f $after.Detail) "Failed"
    } else {
        Write-Status "OneDrive removed (verified)" "Applied"
    }
}

function Get-BloatAppxStatus {
    <#
      Purpose:
        Find curated bloat packages: current user Appx, AllUsers Appx, and provisioned packages.

      When called:
        Dry Run BloatApps; Apply BloatApps removal list.

      Side effects:
        Package queries only (read).

      Undo implications:
        Detection only. Removal is hard to reverse (Store reinstall); Apply warns accordingly.
    #>
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $script:BloatAppxList) {
        $pkgs = @()
        try {
            $pkgs += @(Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ("{0}*" -f $item.Match) })
            $pkgs += @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ("{0}*" -f $item.Match) })
        } catch {}
        $pkgs = @($pkgs | Sort-Object PackageFullName -Unique)
        $prov = @()
        try {
            $prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -like ("{0}*" -f $item.Match) -or $_.PackageName -like ("{0}*" -f $item.Match)
            })
        } catch {}
        if ($pkgs.Count -or $prov.Count) {
            [void]$found.Add([PSCustomObject]@{ DisplayName = $item.Name; UserPkgs = $pkgs; Provisioned = $prov })
        }
    }
    return $found
}

function Get-CfaCandidatePaths {
    <#
      Purpose:
        Build Controlled Folder Access allow-list candidates from installed catalog paths
        plus ExtraCfaPaths that exist on disk.

      When called:
        Add-CfaAllowPaths during Defender Apply.

      Side effects:
        Path existence checks only.
    #>
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $script:ProgramDefs.Keys) {
        foreach ($p in @($script:ProgramDefs[$name].Paths)) {
            if ($p -and (Test-Path -LiteralPath $p) -and -not $paths.Contains($p)) {
                [void]$paths.Add($p)
            }
        }
    }
    foreach ($p in $script:ExtraCfaPaths) {
        if ($p -and (Test-Path -LiteralPath $p) -and -not $paths.Contains($p)) {
            [void]$paths.Add($p)
        }
    }
    return @($paths)
}

function Add-CfaAllowPaths {
    <#
      Purpose:
        Add-MpPreference ControlledFolderAccessAllowedApplications for each candidate path.

      When called:
        Apply Defender section after enabling CFA.

      Side effects:
        Defender preference mutations (allow list growth). Silent catch on individual fails.

      Undo implications:
        Bastion does not remove CFA allows on undo; user manages via Windows Security.
    #>
    $added = 0
    foreach ($p in (Get-CfaCandidatePaths)) {
        try {
            Add-MpPreference -ControlledFolderAccessAllowedApplications $p -ErrorAction Stop
            Write-Host ("      CFA allow: {0}" -f $p) -ForegroundColor DarkGray
            $added++
        } catch {}
    }
    if ($added -gt 0) {
        Write-Status (("CFA allow-list updated ({0} paths)" -f $added)) "Applied"
    } else {
        Write-Status "No new CFA paths to add" "Already"
    }
}

function ConvertTo-BastionNormalizedPath {
    <#
      Purpose:
        Normalize a raw path string for WoW/StrictHandle discovery (slashes, quotes, junk).

      When called:
        WoW root resolution and exception path collection.

      Side effects:
        May resolve FullName when path exists. No writes.
    #>
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $p = $Raw.Trim().Trim('"').Trim("'") -replace '/', '\'
    $p = $p -replace "[\x00-\x1F]", ""
    # Drop trailing junk sometimes glued by binary extractors
    if ($p -match '^([A-Za-z]:\\[^:*?\"<>|]+)') { $p = $Matches[1] }
    $p = $p.TrimEnd('\', ' ', "`t")
    if ($p -notmatch '^[A-Za-z]:\\') { return $null }
    try {
        # Resolve . and .. when path exists
        if (Test-Path -LiteralPath $p) {
            return (Get-Item -LiteralPath $p).FullName
        }
    } catch {}
    return $p
}

function Test-BastionLooksLikeWowRoot {
    <#
      Purpose:
        Heuristic: directory looks like a World of Warcraft install root (product folders,
        Wow.exe, .battle.net under Warcraft-named leaf). Avoids lone "data" false positives.

      When called:
        Resolve-BastionWowRootFromPath and metadata scans.

      Side effects:
        Filesystem existence checks only.
    #>
    param([string]$Dir)
    if ([string]::IsNullOrWhiteSpace($Dir) -or -not (Test-Path -LiteralPath $Dir -PathType Container)) { return $false }
    # Do NOT treat a lone "data" folder as enough (Battle.net Agent also has data\).
    $strong = @("_retail_", "_classic_", "_classic_era_", "_classic_ptr_", "_classic_beta_", "_ptr_", "_beta_", "_xptr_")
    foreach ($m in $strong) {
        if (Test-Path -LiteralPath (Join-Path $Dir $m)) { return $true }
    }
    if (Test-Path -LiteralPath (Join-Path $Dir "Wow.exe")) { return $true }
    # .battle.net beside product dirs is a Blizzard game install marker when under a Warcraft-named folder
    $leaf = Split-Path -Leaf $Dir
    if ($leaf -match 'Warcraft|WoW' -and (Test-Path -LiteralPath (Join-Path $Dir ".battle.net"))) { return $true }
    if ($leaf -match 'Warcraft|WoW' -and (Test-Path -LiteralPath (Join-Path $Dir "Data"))) { return $true }
    return $false
}

function Resolve-BastionWowRootFromPath {
    <#
      Purpose:
        Map a file/folder path from Battle.net metadata or uninstall keys to a WoW install root.

      When called:
        Metadata and registry root collectors.

      Side effects:
        Path walk only (up to 6 parents).
    #>
    # Map a file or folder path from Battle.net metadata to a WoW install root folder.
    param([string]$RawPath)
    $p = ConvertTo-BastionNormalizedPath -Raw $RawPath
    if (-not $p) { return $null }

    $candidate = $p
    if (Test-Path -LiteralPath $p -PathType Leaf) {
        $candidate = Split-Path -Parent $p
    }
    if (-not $candidate) { return $null }

    # Walk up a few levels from e.g. ...\World of Warcraft\_retail_ or ...\Launcher.exe
    $cur = $candidate
    for ($i = 0; $i -lt 6 -and $cur; $i++) {
        $leaf = Split-Path -Leaf $cur
        if ($leaf -match '^(World of Warcraft|_retail_|_classic_|_classic_era_|_classic_ptr_|_ptr_|_beta_|_xptr_|UTILS|Utils)$') {
            if ($leaf -eq "World of Warcraft" -and (Test-BastionLooksLikeWowRoot -Dir $cur)) {
                return $cur
            }
            if ($leaf -ne "World of Warcraft") {
                $parent = Split-Path -Parent $cur
                if ($parent -and (Test-BastionLooksLikeWowRoot -Dir $parent)) { return $parent }
                if ($parent -and ((Split-Path -Leaf $parent) -eq "World of Warcraft")) { return $parent }
            }
        }
        if ((Split-Path -Leaf $cur) -eq "World of Warcraft" -or (Test-BastionLooksLikeWowRoot -Dir $cur)) {
            return $cur
        }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    if (Test-BastionLooksLikeWowRoot -Dir $candidate) { return $candidate }
    return $null
}

function Get-BastionAsciiPathStringsFromFile {
    <#
      Purpose:
        Extract Windows path-like ASCII runs from binary/json metadata (product.db style).

      When called:
        Battle.net product.db scan for install locations.

      Side effects:
        Reads file up to MaxBytes (default 4MB). No writes.
    #>
    # Pull Windows path-like ASCII runs from Battle.net binary/json metadata (product.db is protobuf-ish).
    param([string]$FilePath, [int]$MaxBytes = 4MB)
    $out = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path -LiteralPath $FilePath)) { return @() }
    try {
        $item = Get-Item -LiteralPath $FilePath -Force -ErrorAction Stop
        if ($item.Length -le 0 -or $item.Length -gt $MaxBytes) { return @() }
        $bytes = [System.IO.File]::ReadAllBytes($item.FullName)
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        # Forward-slash form (common in product.db): C:/Program Files (x86)/World of Warcraft
        foreach ($m in [regex]::Matches($text, '[A-Za-z]:/(?:[^\\/:*?\"<>|\x00-\x1F]+/?)+')) {
            $s = $m.Value.TrimEnd('/', '\', ' ', '"', "'")
            if ($s.Length -ge 8 -and -not $out.Contains($s)) { [void]$out.Add($s) }
        }
        # Backslash form
        foreach ($m in [regex]::Matches($text, '[A-Za-z]:\\(?:[^\\/:*?\"<>|\x00-\x1F]+\\)*[^\\/:*?\"<>|\x00-\x1F]*')) {
            $s = $m.Value.TrimEnd('\', ' ', '"', "'")
            if ($s.Length -ge 8 -and -not $out.Contains($s)) { [void]$out.Add($s) }
        }
    } catch {}
    return @($out)
}

function Get-BastionWowRootsFromBattleNetMetadata {
    <#
      Purpose:
        Discover WoW install roots from Battle.net Agent product.db / aggregate.json.

      When called:
        Get-BastionWowInstallRoots merge path for StrictHandle exceptions.

      Side effects:
        Reads under ProgramData\Battle.net\Agent. No game files modified.
    #>
    # Battle.net Agent product.db / aggregate.json record real install locations (any drive / custom folder name nearby).
    $roots = [System.Collections.Generic.List[string]]::new()
    $metaFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($f in @(
            (Join-Path $env:ProgramData "Battle.net\Agent\product.db"),
            (Join-Path $env:ProgramData "Battle.net\Agent\.product.db"),
            (Join-Path $env:ProgramData "Battle.net\Agent\aggregate.json")
        )) {
        if ((Test-Path -LiteralPath $f) -and -not $metaFiles.Contains($f)) { [void]$metaFiles.Add($f) }
    }
    # Any nested product.db under Agent (versioned layouts)
    try {
        $agentRoot = Join-Path $env:ProgramData "Battle.net\Agent"
        if (Test-Path -LiteralPath $agentRoot) {
            Get-ChildItem -LiteralPath $agentRoot -Filter "product.db" -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 0 -and $_.Length -lt 4MB } |
                ForEach-Object {
                    if (-not $metaFiles.Contains($_.FullName)) { [void]$metaFiles.Add($_.FullName) }
                }
            Get-ChildItem -LiteralPath $agentRoot -Filter "aggregate.json" -Recurse -Force -ErrorAction SilentlyContinue |
                ForEach-Object {
                    if (-not $metaFiles.Contains($_.FullName)) { [void]$metaFiles.Add($_.FullName) }
                }
        }
    } catch {}

    foreach ($mf in $metaFiles) {
        try {
            if ($mf -like "*.json") {
                $raw = Get-Content -LiteralPath $mf -Raw -ErrorAction Stop
                # Paths in JSON often use forward slashes
                foreach ($m in [regex]::Matches($raw, '[A-Za-z]:(?:/|\\)(?:[^\"\\r\\n]+)+')) {
                    $cand = $m.Value
                    if ($cand -notmatch 'World of Warcraft|Warcraft|\\\\wow|_retail_|_classic_') { continue }
                    $root = Resolve-BastionWowRootFromPath -RawPath $cand
                    if ($root -and -not $roots.Contains($root)) { [void]$roots.Add($root) }
                }
            } else {
                foreach ($s in @(Get-BastionAsciiPathStringsFromFile -FilePath $mf)) {
                    if ($s -notmatch 'World of Warcraft') { continue }
                    # Skip pure Battle.net client / Agent paths
                    if ($s -match 'Battle\.net\\Agent|Battle\.net/Agent|ProgramData[/\\]Battle\.net') { continue }
                    if ($s -match 'Battle\.net' -and $s -notmatch 'World of Warcraft') { continue }
                    $root = Resolve-BastionWowRootFromPath -RawPath $s
                    if ($root -and (Test-BastionLooksLikeWowRoot -Dir $root) -and -not $roots.Contains($root)) {
                        [void]$roots.Add($root)
                    }
                }
            }
        } catch {
            Write-Log ("Battle.net metadata scan failed ({0}): {1}" -f $mf, $_.Exception.Message) -Level Warning -NoConsole
        }
    }
    return @($roots)
}

function Get-BastionWowRootsFromUninstallRegistry {
    <#
      Purpose:
        Find WoW roots from Uninstall DisplayName/Publisher and InstallLocation/Icon/UninstallString.

      When called:
        Get-BastionWowInstallRoots merge.

      Side effects:
        Registry reads (HKLM/HKCU Uninstall). No writes.
    #>
    $roots = [System.Collections.Generic.List[string]]::new()
    $hives = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($hive in $hives) {
        if (-not (Test-Path -LiteralPath $hive)) { continue }
        try {
            Get-ChildItem -LiteralPath $hive -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    $name = "$($p.DisplayName) $($p.Publisher)"
                    if ($name -notmatch 'World of Warcraft|Blizzard') { return }
                    if ($name -match 'Battle\.net' -and $name -notmatch 'Warcraft') { return }
                    foreach ($field in @($p.InstallLocation, $p.DisplayIcon, $p.UninstallString)) {
                        if (-not $field) { continue }
                        $s = [string]$field
                        # UninstallString may be quoted path + args
                        if ($s -match '"([^"]+)"') { $s = $Matches[1] }
                        elseif ($s -match '^([A-Za-z]:\\[^ ]+)') { $s = $Matches[1] }
                        $root = Resolve-BastionWowRootFromPath -RawPath $s
                        if ($root -and -not $roots.Contains($root)) { [void]$roots.Add($root) }
                    }
                } catch {}
            }
        } catch {}
    }
    return @($roots)
}

function Get-BastionWowInstallRoots {
    <#
      Purpose:
        Merge WoW roots: config overrides, Battle.net metadata, uninstall registry,
        well-known paths on fixed volumes.

      When called:
        Get-BastionStrictHandleExceptionPaths (Apply / Dry Run / Recovery refresh).

      Side effects:
        Discovery only. Large Data\ trees are not fully walked here (product dirs only later).
    #>
    # Merge: config overrides + Battle.net product.db/aggregate.json + uninstall registry + well-known paths on fixed drives.
    $roots = [System.Collections.Generic.List[string]]::new()
    function Add-Root([string]$r) {
        $n = ConvertTo-BastionNormalizedPath -Raw $r
        if (-not $n) { return }
        if (-not (Test-Path -LiteralPath $n -PathType Container)) { return }
        if (-not $roots.Contains($n)) { [void]$roots.Add($n) }
    }

    # 1) User/config overrides (any custom directory)
    if ($script:WowInstallRoots) {
        foreach ($r in @($script:WowInstallRoots)) { Add-Root $r }
    }

    # 2) Battle.net Agent metadata (handles non-default install folders Battle.net knows about)
    foreach ($r in @(Get-BastionWowRootsFromBattleNetMetadata)) { Add-Root $r }

    # 3) Windows uninstall keys
    foreach ($r in @(Get-BastionWowRootsFromUninstallRegistry)) { Add-Root $r }

    # 4) Well-known relative paths on every fixed volume
    foreach ($p in @(
            "${env:ProgramFiles(x86)}\World of Warcraft",
            "$env:ProgramFiles\World of Warcraft"
        )) { Add-Root $p }
    try {
        $vols = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object {
            $_.DriveLetter -and $_.DriveType -eq 'Fixed'
        })
        foreach ($v in $vols) {
            $letter = "$($v.DriveLetter):"
            foreach ($rel in @(
                    "World of Warcraft",
                    "Games\World of Warcraft",
                    "Games\Blizzard\World of Warcraft",
                    "Blizzard\World of Warcraft",
                    "Program Files (x86)\World of Warcraft",
                    "Program Files\World of Warcraft"
                )) {
                Add-Root (Join-Path $letter $rel)
            }
        }
    } catch {}

    return @($roots)
}

function Get-BastionStrictHandleExceptionPaths {
    <#
      Purpose:
        Collect full paths of EXEs that should get StrictHandle OFF: config list + Wow*.exe
        under known product subfolders of discovered WoW roots.

      When called:
        Dry Run ExploitProtection; Apply Set-BastionStrictHandleExceptions; Recovery status;
        Write-BastionStrictHandleGuidance Notice path count.

      Side effects:
        Filesystem scans limited to product dirs (not full Data\) for Apply performance.

      Honesty (StrictHandle):
        Exception on the EXE covers loader DLL crashes (Wow_loader.dll under issue #18).
        Undiscovered games are NOT excepted. Full path required (bare names collide).
        Empty list is normal when WoW is not installed.
    #>
    # Per-app StrictHandle OFF targets. System keeps StrictHandle ON for everything else.
    # Wow_loader.dll is loaded by Wow*.exe - exception on the EXE covers the loader crash (issue #18).
    # Only scan known product subfolders (not Data\) so Apply stays fast on large installs.
    $paths = [System.Collections.Generic.List[string]]::new()
    function Add-Exe([string]$e) {
        $n = ConvertTo-BastionNormalizedPath -Raw $e
        if (-not $n) { return }
        if (-not (Test-Path -LiteralPath $n -PathType Leaf)) { return }
        if ($n -notmatch '\.exe$') { return }
        if (-not $paths.Contains($n)) { [void]$paths.Add($n) }
    }

    # Explicit full EXE paths from config (any game or custom Wow path)
    if ($script:StrictHandleExceptionPaths) {
        foreach ($e in @($script:StrictHandleExceptionPaths)) { Add-Exe $e }
    }

    $productDirs = @(
        "_retail_", "_classic_", "_classic_era_", "_classic_ptr_", "_classic_beta_",
        "_ptr_", "_beta_", "_xptr_", "UTILS", "Utils"
    )
    foreach ($root in @(Get-BastionWowInstallRoots)) {
        try {
            foreach ($rel in $productDirs) {
                $dir = Join-Path $root $rel
                if (-not (Test-Path -LiteralPath $dir)) { continue }
                Get-ChildItem -LiteralPath $dir -Filter "Wow*.exe" -File -ErrorAction SilentlyContinue |
                    ForEach-Object { Add-Exe $_.FullName }
                Get-ChildItem -LiteralPath $dir -Directory -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        Get-ChildItem -LiteralPath $_.FullName -Filter "Wow*.exe" -File -ErrorAction SilentlyContinue |
                            ForEach-Object { Add-Exe $_.FullName }
                    }
            }
            Get-ChildItem -LiteralPath $root -Filter "Wow*.exe" -File -ErrorAction SilentlyContinue |
                ForEach-Object { Add-Exe $_.FullName }
        } catch {}
    }
    return @($paths)
}

function Set-BastionStrictHandleExceptions {
    <#
      Purpose:
        Set-ProcessMitigation -Disable StrictHandle for each discovered exception EXE path.

      When called:
        Apply ExploitProtection after system mitigations; Recovery refresh exceptions.

      Side effects / Windows objects touched:
        Per-image process mitigation policy for each full EXE path (StrictHandle OFF for that app only).
        System-wide StrictHandle remains ON if previously enabled.

      Undo implications:
        Recovery can disable system StrictHandle entirely or re-apply Bastion profile.
        Exceptions are re-applied on next Apply/refresh; not a permanent OS "undo file."

      Honesty (StrictHandle):
        Per-app OFF is a deliberate security trade-off for software that breaks under system
        StrictHandle. Not a silent failure: Info message when no paths found.
    #>
    # Disable StrictHandle only for discovered game EXEs (full path required; bare names collide).
    $paths = @(Get-BastionStrictHandleExceptionPaths)
    if ($paths.Count -eq 0) {
        Write-Status "StrictHandle system ON; no exception EXE paths found yet (WoW auto-discover when installed, or set WowInstallRoots / StrictHandleExceptionPaths in Bastion-Config.json, then re-Apply or Recovery > 6 > refresh)" "Info"
        return 0
    }
    $ok = 0
    Write-Host ("    StrictHandle exceptions: {0} target EXE(s)" -f $paths.Count) -ForegroundColor DarkGray
    foreach ($full in $paths) {
        try {
            Set-ProcessMitigation -Name $full -Disable StrictHandle -ErrorAction Stop
            Write-Status ("StrictHandle exception (OFF for this app): {0}" -f $full) "Applied"
            $ok++
        } catch {
            Write-Status ("StrictHandle exception failed for {0}: {1}" -f $full, $_.Exception.Message) "Warn"
        }
    }
    return $ok
}

function Write-BastionStrictHandleGuidance {
    <#
      Purpose:
        Single source of truth for StrictHandle honesty UI (Inline / Notice / Block styles).

      When called:
        Dry Run and Apply ExploitProtection (Inline/Notice); Recovery mitigations (Block).

      Side effects:
        Console output only. Notice style may query exception path count.

      Honesty (StrictHandle):
        Documents WoW as example (now auto-excepted), CS2 tested OK, other titles unknown.
        Reverse: Recovery > 6 disable system StrictHandle, reboot, report game + full .exe path.
        Prefer Recovery so Bastion status stays accurate vs ad-hoc Windows Security clicks.
    #>
    # Single source of truth: clear reverse path + WoW as example only + report so we can add exceptions.
    param(
        [ValidateSet("Inline", "Block", "Notice")]
        [string]$Style = "Block",
        [ConsoleColor]$Color = [ConsoleColor]::DarkYellow
    )
    if ($Style -eq "Inline") {
        Write-Host "      Example: World of Warcraft broke under system StrictHandle; Bastion auto-excepts discovered Wow*.exe now. CS2 tested OK." -ForegroundColor $Color
        Write-Host "      Other programs may break until we ship an exception for them. That is expected and not a silent failure." -ForegroundColor $Color
        Write-Host "      If something breaks: Recovery > 6 > StrictHandle > disable system StrictHandle, reboot, confirm it works." -ForegroundColor $Color
        Write-Host "      Then report game name + full .exe path on GitHub #18 or Discussions #23 so we can add an exception." -ForegroundColor $Color
        Write-Host "      Until that ships, keep system StrictHandle off (or add the full .exe under StrictHandleExceptionPaths yourself)." -ForegroundColor DarkGray
        return
    }
    if ($Style -eq "Notice") {
        Write-Host ""
        Write-Host "  ---------- Games / StrictHandle (read this) ----------" -ForegroundColor Yellow
        Write-Host "  What: system-wide StrictHandle (stricter process handle checks)." -ForegroundColor White
        Write-Host "  Why it can break software: some loaders and multi-process games use handles in ways that" -ForegroundColor DarkGray
        Write-Host "  are fine under default Windows policy but fatal under StrictHandle." -ForegroundColor DarkGray
        Write-Host "  Example (not the only case): World of Warcraft - Play/Wow.exe failed (Eidolon / INVALID_HANDLE" -ForegroundColor DarkGray
        Write-Host "  in Wow_loader.dll) until a per-app exception. Bastion now auto-excepts discovered Wow*.exe." -ForegroundColor DarkGray
        Write-Host "  CS2 was tested OK. Other titles: unknown. No exception means it may still break." -ForegroundColor DarkGray
        $wowEx = @()
        try { $wowEx = @(Get-BastionStrictHandleExceptionPaths) } catch { $wowEx = @() }
        if ($wowEx.Count -gt 0) {
            Write-Host ("  This PC: {0} exception path(s) will be applied/refreshed (mostly Wow*.exe / config)." -f $wowEx.Count) -ForegroundColor Green
        } else {
            Write-Host "  This PC: no exception EXE paths found yet (OK if WoW is not installed)." -ForegroundColor DarkGray
        }
        Write-Host "  If ANY program fails after Apply:" -ForegroundColor Cyan
        Write-Host "    1. Recovery > 6 Security mitigations > StrictHandle" -ForegroundColor Cyan
        Write-Host "    2. Disable system StrictHandle (whole PC), then reboot  -or-  add full .exe to" -ForegroundColor Cyan
        Write-Host "       StrictHandleExceptionPaths in Bastion-Config.json and re-Apply / refresh exceptions" -ForegroundColor Cyan
        Write-Host "    3. Confirm the program works" -ForegroundColor Cyan
        Write-Host "    4. Report name + full .exe path: github.com/jjames06/bastion-hardening/issues/18" -ForegroundColor Cyan
        Write-Host "       or Discussions #23 so we can ship an automatic exception" -ForegroundColor Cyan
        Write-Host "    5. After an update includes your exception, re-Apply or Recovery > 6 option 3 to restore" -ForegroundColor Cyan
        Write-Host "       system StrictHandle with exceptions" -ForegroundColor Cyan
        Write-Host "  Prefer Recovery so Bastion status and reverse paths stay accurate." -ForegroundColor DarkGray
        Write-Host "  -----------------------------------------------------------" -ForegroundColor Yellow
        Write-Host ""
        return
    }
    # Block (default): recovery-menu honesty block
    Write-Host "  Honest notes" -ForegroundColor Yellow
    Write-Host "    System StrictHandle hardens most apps. Some programs (especially games) can fail to start." -ForegroundColor DarkGray
    Write-Host "    World of Warcraft is a documented example (now auto-excepted when Wow*.exe is found)." -ForegroundColor DarkGray
    Write-Host "    Other titles may break with NO exception until someone reports them and we add one." -ForegroundColor DarkGray
    Write-Host "    Option 1: turn StrictHandle OFF for the whole PC (security trade-off). Reboot after." -ForegroundColor DarkGray
    Write-Host "    Option 2: refresh known exception EXEs only (keeps system StrictHandle ON)." -ForegroundColor DarkGray
    Write-Host "    Option 3: re-enable Bastion profile after you can run your software again." -ForegroundColor DarkGray
    Write-Host "    Report broken programs: GitHub issue #18 or Discussions #23 (game + full .exe path)." -ForegroundColor DarkGray
    Write-Host "    Until we ship your exception, use option 1 or a manual path in StrictHandleExceptionPaths." -ForegroundColor DarkGray
}

function Set-RegistryValueSafe {
    <#
      Purpose:
        Create registry path as needed and set a value; Soft mode warns and continues on
        access-denied optional keys. Hard path may fall back to reg.exe.

      When called:
        Apply Suggestions section; Restore-SuggestionDefaults for non-null defaults.

      Side effects / Windows objects touched:
        New-Item / New-ItemProperty or reg.exe add under HKLM/HKCU paths from callers.

      Undo implications:
        Restore-SuggestionDefaults uses Default values or removes policy values.
        Soft failures leave Windows defaults (not Bastion-owned).
    #>
    param(
        $Path,
        $Name,
        $Value,
        $Type = "DWord",
        $Desc = "",
        [bool]$Soft = $false
    )
    # Soft = optional keys Windows may deny even when elevated; warn quietly, never fail Apply
    try {
        $parts = @(($Path -replace '^HK(LM|CU):\\', '' -split '\\') | Where-Object { $_ })
        $root = if ($Path -match '^HKLM:') { "HKLM:" } else { "HKCU:" }
        $build = $root
        foreach ($part in $parts) {
            $build = Join-Path $build $part
            if (-not (Test-Path -LiteralPath $build)) {
                try {
                    New-Item -Path $build -Force -ErrorAction Stop | Out-Null
                } catch {
                    if ($Soft) {
                        Write-Status ("Optional skipped (key locked): {0}" -f $Desc) "Warn"
                        return $false
                    }
                    throw
                }
            }
        }
        $current = $null
        try { $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name } catch {}
        if ($null -ne $current -and $current -eq $Value) {
            Write-Status ("{0} already set" -f $Desc) "Already"
            return $true
        }
        try {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
            Write-Status ("Set: {0}" -f $Desc) "Applied"
            return $true
        } catch {
            $psErr = $_.Exception.Message
            # Access denied on Soft keys: do not run noisy reg.exe fallback
            if ($Soft -and ($psErr -match 'access is denied|unauthorized|Access is denied|denied')) {
                Write-Status ("Optional skipped (Windows locked): {0}" -f $Desc) "Warn"
                return $false
            }
            $regRoot = if ($Path -match '^HKLM:') { "HKLM" } else { "HKCU" }
            $regPath = ($Path -replace '^HK(LM|CU):\\', '')
            $regType = switch ($Type) {
                "DWord" { "REG_DWORD" }
                "String" { "REG_SZ" }
                "QWord" { "REG_QWORD" }
                default { "REG_DWORD" }
            }
            $outFile = Join-Path $script:tempDir "reg-out.txt"
            $errFile = Join-Path $script:tempDir "reg-err.txt"
            try {
                # Use argument array (avoids quote/parse issues; supports spaces in key paths)
                $regKey = "{0}\{1}" -f $regRoot, $regPath
                $proc = Start-Process -FilePath "reg.exe" -ArgumentList @(
                    "add", $regKey,
                    "/v", "$Name",
                    "/t", "$regType",
                    "/d", "$Value",
                    "/f"
                ) -Wait -PassThru -NoNewWindow `
                    -RedirectStandardOutput $outFile -RedirectStandardError $errFile -ErrorAction Stop
                if ($proc.ExitCode -eq 0) {
                    Write-Status ("Set via reg.exe: {0}" -f $Desc) "Applied"
                    return $true
                }
                $errText = ""
                if (Test-Path -LiteralPath $errFile) {
                    $errText = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
                }
                if ($Soft) {
                    Write-Status ("Optional skipped: {0}" -f $Desc) "Warn"
                    return $false
                }
                throw [System.Exception]::new(("reg exit {0}; {1}; PS: {2}" -f $proc.ExitCode, $errText, $psErr))
            } catch {
                if ($Soft) {
                    Write-Status ("Optional skipped: {0}" -f $Desc) "Warn"
                    return $false
                }
                throw
            }
        }
    } catch {
        $msg = $_.Exception.Message
        if ($Soft -or $msg -match 'unauthorized|access is denied|Access is denied|denied') {
            Write-Status ("Optional skipped: {0}" -f $Desc) "Warn"
            return $false
        }
        Write-Status ("Could not set: {0} ({1})" -f $Desc, $msg) "Warn"
        return $false
    }
}

function Restore-SuggestionDefaults {
    <#
      Purpose:
        Walk SuggestionRegistry and restore Default values or remove policy values.

      When called:
        Recovery suggestions restore. Immediate registry changes.

      Side effects:
        HKCU/HKLM suggestion/widget related values per registry list.

      Undo implications:
        This is the reverse of Apply Suggestions. Sign-out/Explorer restart may be needed.
    #>
    Write-Host "  Restoring Widgets / Suggestions toward defaults..." -ForegroundColor Cyan
    foreach ($item in $script:SuggestionRegistry) {
        $path = $item.Path
        $name = $item.Name
        try {
            if (-not (Test-Path -LiteralPath $path)) {
                Write-Status ("{0}: key absent (nothing to restore)" -f $item.Desc) "Already"
                continue
            }
            if ($null -eq $item.Default) {
                try {
                    Remove-ItemProperty -Path $path -Name $name -Force -ErrorAction Stop
                    Write-Status ("Removed policy value: {0}" -f $item.Desc) "Applied"
                } catch {
                    if ($_.Exception.Message -match 'cannot find|does not exist') {
                        Write-Status ("{0}: already absent" -f $item.Desc) "Already"
                    } else {
                        Write-Status ("Could not remove {0}: {1}" -f $item.Desc, $_.Exception.Message) "Warn"
                    }
                }
            } else {
                $soft = $false
                if ($item.ContainsKey("Soft")) { $soft = [bool]$item.Soft }
                [void](Set-RegistryValueSafe -Path $path -Name $name -Value $item.Default -Type $item.Type -Desc ("Restore {0}" -f $item.Desc) -Soft:$soft)
            }
        } catch {
            Write-Status ("Restore failed {0}: {1}" -f $item.Desc, $_.Exception.Message) "Warn"
        }
    }
    Write-Host "  Sign out or restart Explorer for full UI effect." -ForegroundColor Yellow
}

function Get-BastionRemoteDesktopSystemStatus {
    <#
      Purpose:
        Read OS RDP host switch (fDenyTSConnections) and TermService status/start type.

      When called:
        Dry Run RDP triad / RdpHostLock; Audit; Apply RdpHostLock prior capture; Recovery.

      Side effects:
        Registry and service queries only.
    #>
    $deny = $null
    try {
        $deny = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
            -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
    } catch {}
    $svc = $null
    try { $svc = Get-Service -Name TermService -ErrorAction SilentlyContinue } catch {}
    $allowed = ($deny -eq 0)
    $sysLabel = if ($null -eq $deny) { "UNKNOWN" } elseif ($allowed) { "ALLOWED" } else { "DENIED" }
    return [PSCustomObject]@{
        fDenyTSConnections = $deny
        SystemAllowed      = $allowed
        SystemLabel        = $sysLabel
        ServiceName        = "TermService"
        ServiceStatus      = if ($svc) { [string]$svc.Status } else { "Not found" }
        ServiceStartType   = if ($svc) { [string]$svc.StartType } else { "Not found" }
        ServicePresent     = [bool]$svc
    }
}

function Enable-BastionRemoteDesktopSystem {
    <#
      Purpose:
        Allow OS Remote Desktop (fDenyTSConnections=0) and start TermService Automatic.

      When called:
        Recovery remote access path. Immediate apply.

      Side effects:
        HKLM Terminal Server registry; TermService start type and Start-Service.

      Undo implications:
        Firewall group may still block; full RDP needs OPEN group + ALLOWED + service.
        Reverse: Disable-BastionRemoteDesktopSystem or RdpHostLock Apply.
    #>
    # Optional layer beyond firewall groups: Windows "allow remote connections to this computer".
    try {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Status "Terminal Server registry path missing on this edition/build" "Failed"
            return $false
        }
        Set-ItemProperty -Path $path -Name fDenyTSConnections -Value 0 -Type DWord -Force -ErrorAction Stop
        Write-Status "fDenyTSConnections=0 (system allows Remote Desktop connections)" "Applied"
        try {
            Set-Service -Name TermService -StartupType Automatic -ErrorAction Stop
            Start-Service -Name TermService -ErrorAction Stop
            Write-Status "TermService: Automatic and running" "Applied"
        } catch {
            Write-Status ("TermService start/config failed: {0}. Next step: services.msc -> Remote Desktop Services." -f $_.Exception.Message) "Warn"
        }
        Write-Log "Enable-BastionRemoteDesktopSystem done" -NoConsole
        return $true
    } catch {
        Write-Status ("Allow RDP system failed: {0}" -f $_.Exception.Message) "Failed"
        return $false
    }
}

function Disable-BastionRemoteDesktopSystem {
    <#
      Purpose:
        Deny OS RDP (fDenyTSConnections=1); optionally stop TermService and set Manual.

      When called:
        Recovery or helpers; Apply RdpHostLock uses similar logic inline with undo prior.

      Side effects:
        Registry deny; optional service stop/Manual.

      Undo implications:
        Prior values should be restored from Apply undo (RdpHostPrior) when available.
    #>
    param([switch]$StopService)
    try {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Status "Terminal Server registry path missing on this edition/build" "Failed"
            return $false
        }
        Set-ItemProperty -Path $path -Name fDenyTSConnections -Value 1 -Type DWord -Force -ErrorAction Stop
        Write-Status "fDenyTSConnections=1 (system denies Remote Desktop connections)" "Applied"
        if ($StopService) {
            try {
                Stop-Service -Name TermService -Force -ErrorAction SilentlyContinue
                Set-Service -Name TermService -StartupType Manual -ErrorAction Stop
                Write-Status "TermService: stopped and Manual (can be started later if needed)" "Applied"
            } catch {
                Write-Status ("TermService stop/config: {0}" -f $_.Exception.Message) "Warn"
            }
        }
        Write-Log ("Disable-BastionRemoteDesktopSystem stopService={0}" -f [bool]$StopService) -NoConsole
        return $true
    } catch {
        Write-Status ("Deny RDP system failed: {0}" -f $_.Exception.Message) "Failed"
        return $false
    }
}

function Get-BastionStrictHandleSystemStatus {
    <#
      Purpose:
        Snapshot system StrictHandle/DEP state and current exception path count/list.

      When called:
        Recovery mitigations menu status.

      Side effects:
        Get-ProcessMitigation -System and exception path discovery (read-only policy).

      Honesty (StrictHandle):
        UNKNOWN when query fails. ExceptionCount does not prove exceptions are already applied.
    #>
    $strictOn = $null
    $depOn = $null
    try {
        $mit = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        try { $strictOn = ($mit.StrictHandle.Enable -eq "ON" -or "$($mit.StrictHandle.Enable)" -eq "ON") } catch { $strictOn = $null }
        try { $depOn = ($mit.DEP.Enable -eq "ON" -or "$($mit.DEP.Enable)" -eq "ON") } catch { $depOn = $null }
    } catch {}
    $paths = @()
    try { $paths = @(Get-BastionStrictHandleExceptionPaths) } catch { $paths = @() }
    return [PSCustomObject]@{
        StrictHandleOn = $strictOn
        DepOn = $depOn
        ExceptionCount = $paths.Count
        ExceptionPaths = $paths
        StrictLabel = if ($null -eq $strictOn) { "UNKNOWN" } elseif ($strictOn) { "ON" } else { "OFF" }
    }
}
