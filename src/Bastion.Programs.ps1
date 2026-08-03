# Bastion.Programs.ps1 - modular domain (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.
#
# Role in modular architecture:
#   Catalog-only winget install/uninstall helpers, install path safety, and install
#   detection for the Programs section (menu 5) and Apply. Never installs arbitrary IDs.
#
# Load-order position: 4 of 11 (after Config, before Services).
#   Order: Init, Core, Config, Programs, Services, Browsers, Dns, Harden, Apply, Recovery, Menus.
#
# Dependencies on $script: state:
#   $script:ProgramDefs              - curated catalog (WingetId, Paths, ManualInstallOnly)
#   $script:SelectedApps             - install queue (names still missing)
#   $script:ProgramInstallRoots      - per-app custom roots
#   $script:GlobalInstallRoot        - one folder for all pending installs
#   $script:TrustedWingetSourceNames - winget/msstore names allowed by preflight
#   $script:BlockedPathFragments     - install-root deny list (Windows, System32, ...)
#   $script:tempDir                  - winget show/uninstall redirect files
#   $script:Stats                    - ProgramsInstalled during Apply

function Test-WingetAvailable {
    <#
      Purpose:
        Detect whether winget is on PATH and return path or a user-facing error string.

      When called:
        Preflight for install/uninstall; Audit tooling check (via Test-WingetSecurityPreflight).

      Side effects:
        None (Get-Command only).

      Undo implications:
        None.
    #>
    try {
        $cmd = Get-Command winget -ErrorAction Stop
        return [PSCustomObject]@{ Ok = $true; Path = $cmd.Source; Error = $null }
    } catch {
        return [PSCustomObject]@{
            Ok = $false
            Path = $null
            Error = "winget not found. Install App Installer from the Microsoft Store, then re-run."
        }
    }
}

function Test-WingetSecurityPreflight {
    <#
      Purpose:
        Confirm winget exists and that a trusted source name (winget and/or msstore from
        $script:TrustedWingetSourceNames) appears in `winget source list`.

      When called:
        Before every catalog install (Apply Programs section and Install-BastionCatalogApp),
        and read-only in Security Audit tooling row.

      Side effects:
        Spawns winget source list (stdout/stderr captured). No package install.

      Undo implications:
        None.

      Honesty (catalog-only / winget):
        This is not a full supply-chain guarantee. It only refuses installs when no trusted
        source name is visible. Source list check failures continue cautiously (Ok=true)
        rather than hard-blocking when winget is present but list parsing failed.
        Bastion never passes --ignore-security-hash. Installs are catalog-only (ProgramDefs).
    #>
    $wg = Test-WingetAvailable
    if (-not $wg.Ok) {
        return [PSCustomObject]@{ Ok = $false; Detail = $wg.Error }
    }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "winget"
        $psi.Arguments = "source list"
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $out = $p.StandardOutput.ReadToEnd()
        [void]$p.WaitForExit(15000)
        $sourceOk = $false
        foreach ($name in $script:TrustedWingetSourceNames) {
            if ($out -match [regex]::Escape($name)) { $sourceOk = $true; break }
        }
        if (-not $sourceOk) {
            return [PSCustomObject]@{
                Ok = $false
                Detail = "No trusted winget/msstore source visible. Refusing installs. Next step: winget source reset --force"
            }
        }
        # Do not echo the full winget binary path (often under a user profile).
        return [PSCustomObject]@{ Ok = $true; Detail = "winget OK; trusted winget/msstore source present" }
    } catch {
        return [PSCustomObject]@{
            Ok = $true
            Detail = ("winget present; source list check failed (continuing cautiously). {0}" -f $_.Exception.Message)
        }
    }
}

function Test-CatalogPackageId {
    <#
      Purpose:
        Fail closed if AppName is not in ProgramDefs, is ManualInstallOnly, WingetId does
        not match catalog, or ID fails a simple format regex.

      When called:
        Immediately before winget install for a catalog app.

      Side effects:
        None.

      Undo implications:
        None.

      Honesty (winget catalog-only):
        This is Bastion's primary install safety gate: only known app names and exact
        WingetId values from the curated catalog. User-typed package IDs are never accepted.
    #>
    param([string]$AppName, [string]$WingetId)
    if ([string]::IsNullOrWhiteSpace($AppName) -or -not $script:ProgramDefs.Contains($AppName)) {
        return [PSCustomObject]@{ Ok = $false; Detail = ("Not in Bastion catalog: {0}" -f $AppName) }
    }
    $def = $script:ProgramDefs[$AppName]
    if ($def.ManualInstallOnly) {
        return [PSCustomObject]@{ Ok = $false; Detail = ("Manual install only (not on winget): {0}" -f $AppName); Manual = $true }
    }
    $expected = $def.WingetId
    if ($WingetId -ne $expected) {
        return [PSCustomObject]@{ Ok = $false; Detail = ("Package ID mismatch for {0}" -f $AppName) }
    }
    if ([string]::IsNullOrWhiteSpace($WingetId) -or $WingetId -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{1,120}$') {
        return [PSCustomObject]@{ Ok = $false; Detail = ("Package ID failed format validation: {0}" -f $WingetId) }
    }
    return [PSCustomObject]@{ Ok = $true; Detail = $WingetId }
}

function Invoke-WingetShow([string]$WingetId) {
    <#
      Purpose:
        Run `winget show --id <id> -e` to verify the package is visible to winget before install.

      When called:
        Install-BastionCatalogApp after catalog ID and preflight checks.

      Side effects:
        Writes temp files under $script:tempDir (wg-show-out.txt / wg-show-err.txt).
        Network/source query via winget; no install.

      Undo implications:
        None.
    #>
    try {
        $outFile = Join-Path $script:tempDir "wg-show-out.txt"
        $errFile = Join-Path $script:tempDir "wg-show-err.txt"
        $p = Start-Process -FilePath "winget" -ArgumentList @("show","--id",$WingetId,"-e") `
            -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile -ErrorAction Stop
        $out = ""
        if (Test-Path -LiteralPath $outFile) {
            $out = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue
        }
        return [PSCustomObject]@{ ExitCode = $p.ExitCode; Output = $out }
    } catch {
        return [PSCustomObject]@{ ExitCode = -1; Output = $_.Exception.Message }
    }
}

function Test-AuthenticodeRelaxed([string]$Path) {
    <#
      Purpose:
        Report Authenticode status of an installed binary (Valid / NotSigned / other).
        "Relaxed" means unsigned is reported, not treated as automatic install failure.

      When called:
        After successful install detection, for informational console output.

      Side effects:
        None (signature read only).

      Undo implications:
        None.

      Honesty:
        Not all catalog apps are signed the same way. NotSigned is common and does not
        roll back the install. HashMismatch/NotTrusted only produces a Warn status.
    #>
    if (-not (Test-Path -LiteralPath $Path)) {
        return [PSCustomObject]@{ Status = "Missing"; Detail = "Path not found" }
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        switch ($sig.Status) {
            "Valid" { return [PSCustomObject]@{ Status = "Valid"; Detail = [string]$sig.SignerCertificate.Subject } }
            "NotSigned" { return [PSCustomObject]@{ Status = "NotSigned"; Detail = "Unsigned (common for some apps)" } }
            default { return [PSCustomObject]@{ Status = [string]$sig.Status; Detail = [string]$sig.StatusMessage } }
        }
    } catch {
        return [PSCustomObject]@{ Status = "Error"; Detail = $_.Exception.Message }
    }
}

function Get-AvailableInstallVolumes {
    <#
      Purpose:
        List fixed local logical disks (DriveType 3) with free space for install-root UI.

      When called:
        Select-InstallRootFromVolumes and path validation paths during Programs menu / Apply.

      Side effects:
        CIM query only (Win32_LogicalDisk).

      Undo implications:
        None. Network/USB volumes are intentionally excluded by DriveType filter.
    #>
    $list = [System.Collections.Generic.List[object]]::new()
    try {
        Get-CimInstance Win32_LogicalDisk -ErrorAction Stop |
            Where-Object { $_.DriveType -eq 3 -and $_.Size -gt 0 -and $null -ne $_.FreeSpace } |
            ForEach-Object {
                [void]$list.Add([PSCustomObject]@{
                    Root   = ($_.DeviceID.TrimEnd('\') + '\')
                    Label  = $(if ($_.VolumeName) { $_.VolumeName } else { "Local Disk" })
                    FreeGB = [math]::Round($_.FreeSpace / 1GB, 1)
                })
            }
    } catch {
        Write-Status ("Volume enumeration failed: {0}. Next step: check disk management." -f $_.Exception.Message) "Warn"
    }
    return @($list | Sort-Object Root)
}

function Test-SafeInstallRoot {
    <#
      Purpose:
        Validate a user-chosen install root: drive letter, no UNC, under an allowed fixed
        volume, and not under blocked system path fragments.

      When called:
        Before storing custom install roots and before passing --location to winget.

      Side effects:
        None (path string checks + GetFullPath).

      Undo implications:
        None.

      Honesty:
        Safety is path-shape + local volume only. It does not prove the folder is empty
        or owned by the user. Some winget packages ignore --location entirely.
    #>
    param([string]$Path, [object[]]$AllowedVolumes)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [PSCustomObject]@{ Ok = $false; Reason = "Empty path"; Path = $null }
    }
    $trimmed = $Path.Trim().Trim('"').Trim("'")
    if ($trimmed -match '[\x00-\x1F<>|?*]') {
        return [PSCustomObject]@{ Ok = $false; Reason = "Invalid path characters"; Path = $null }
    }
    if ($trimmed -match '^\\\\' -or $trimmed -match '^[A-Za-z]:\\\\') {
        return [PSCustomObject]@{ Ok = $false; Reason = "UNC / network paths are not allowed"; Path = $null }
    }
    if ($trimmed -notmatch '^[A-Za-z]:\\') {
        return [PSCustomObject]@{ Ok = $false; Reason = "Path must start with a drive letter (e.g. C:\\Apps)"; Path = $null }
    }
    try {
        $full = [System.IO.Path]::GetFullPath($trimmed)
    } catch {
        return [PSCustomObject]@{ Ok = $false; Reason = "Path resolve failed"; Path = $null }
    }
    $fullNorm = $full.TrimEnd('\')
    $under = $false
    foreach ($v in @($AllowedVolumes)) {
        if (-not $v) { continue }
        $rootNorm = $v.Root.TrimEnd('\')
        if ($fullNorm.Equals($rootNorm, [StringComparison]::OrdinalIgnoreCase) -or
            $fullNorm.StartsWith($rootNorm + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $under = $true
            break
        }
    }
    if (-not $under) {
        return [PSCustomObject]@{ Ok = $false; Reason = "Not on an allowed fixed local volume"; Path = $null }
    }
    $lower = $fullNorm.ToLowerInvariant()
    foreach ($frag in $script:BlockedPathFragments) {
        $f = $frag.ToLowerInvariant()
        if ($lower.Contains($f)) {
            return [PSCustomObject]@{ Ok = $false; Reason = ("Blocked system path ({0})" -f $frag); Path = $null }
        }
    }
    return [PSCustomObject]@{ Ok = $true; Reason = "OK"; Path = $fullNorm }
}

function Get-EffectiveInstallRoot([string]$AppName) {
    <#
      Purpose:
        Resolve install root preference: per-app map first, else global root, else $null
        (vendor default).

      When called:
        Test-Installed (search under custom root) and Apply Programs install loop.

      Side effects:
        None.

      Undo implications:
        None. Roots are preferences in Bastion-Config.json, not undo data.
    #>
    if ($AppName -and $script:ProgramInstallRoots.ContainsKey($AppName) -and $script:ProgramInstallRoots[$AppName]) {
        return $script:ProgramInstallRoots[$AppName]
    }
    if ($script:GlobalInstallRoot) { return $script:GlobalInstallRoot }
    return $null
}

function Test-Installed {
    <#
      Purpose:
        Heuristic install detection: catalog Paths (literal or simple wildcards), special
        cases for Blender/PostgreSQL trees, then recursive search under effective install root.

      When called:
        Dry Run Programs section, Get-SelectedMissingApps, Sync-ProgramInstallQueue,
        Install-BastionCatalogApp before/after install, uninstall detection lists.

      Side effects:
        Filesystem probes only.

      Undo implications:
        None. False negatives possible after winget exit 0 (installer delayed); Install
        treats that as Warn+Applied, not automatic rollback.
    #>
    param([string]$Name, [string[]]$Paths)
    foreach ($p in @($Paths)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        # Literal first; also allow simple * wildcards in a single path segment.
        try {
            if (Test-Path -LiteralPath $p) { return $true }
        } catch {}
        if ($p -match '\*') {
            try {
                $hit = Get-Item -Path $p -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($hit) { return $true }
            } catch {}
        }
    }
    if ($Name -eq "Blender" -and (Test-Path -LiteralPath "C:\Program Files\Blender Foundation")) {
        $hit = Get-ChildItem "C:\Program Files\Blender Foundation" -Filter blender.exe -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return $true }
    }
    if ($Name -eq "PostgreSQL" -and (Test-Path -LiteralPath "C:\Program Files\PostgreSQL")) {
        $hit = Get-ChildItem "C:\Program Files\PostgreSQL" -Filter psql.exe -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return $true }
    }
    $root = Get-EffectiveInstallRoot -AppName $Name
    if (-not $root -or -not (Test-Path -LiteralPath $root)) { return $false }
    foreach ($exe in @($Paths | ForEach-Object { Split-Path $_ -Leaf } | Select-Object -Unique | Where-Object { $_ -and $_ -ne '*' })) {
        $hit = Get-ChildItem -LiteralPath $root -Filter $exe -Recurse -Depth 5 -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return $true }
    }
    return $false
}

function Get-SelectedMissingApps {
    <#
      Purpose:
        List names from $script:SelectedApps that are still not detected as installed.

      When called:
        Dry Run, Apply Programs, Set-LocationsForPendingInstalls.

      Side effects:
        None beyond install detection queries.

      Undo implications:
        None.
    #>
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @($script:SelectedApps)) {
        if (-not $script:ProgramDefs.Contains($name)) { continue }
        if (-not (Test-Installed -Name $name -Paths $script:ProgramDefs[$name].Paths)) {
            [void]$list.Add($name)
        }
    }
    return @($list)
}

function Sync-ProgramInstallQueue {
    <#
      Purpose:
        Prune $script:SelectedApps to catalog names still missing; drop installed selections
        so menu checkboxes stay accurate. Clears stale per-app install roots.

      When called:
        After Apply install loop, and when menus refresh the programs queue.

      Side effects:
        Mutates $script:SelectedApps and $script:ProgramInstallRoots (via Clear-StaleInstallRoots).
        Does not install or uninstall software.

      Undo implications:
        None. Queue is preference/session state, not OS undo.
    #>
    # Install queue = catalog apps the user opted in to install that are still missing.
    # Never keep already-installed names selected (avoids green [X] on installed rows).
    $kept = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @($script:SelectedApps)) {
        if (-not $script:ProgramDefs.Contains($name)) { continue }
        if (-not (Test-Installed -Name $name -Paths $script:ProgramDefs[$name].Paths)) {
            if (-not ($kept -contains $name)) { [void]$kept.Add($name) }
        }
    }
    $script:SelectedApps.Clear()
    foreach ($n in $kept) { [void]$script:SelectedApps.Add($n) }
    Clear-StaleInstallRoots
}

function Get-CatalogProgramRows {
    <#
      Purpose:
        Build menu rows for every ProgramDefs entry with Installed/Selected flags.

      When called:
        Programs menu (menu 5) rendering.

      Side effects:
        Read-only detection against disk.

      Undo implications:
        None.
    #>
    # Live detect installed/missing for every catalog entry (order matches ProgramDefs).
    $rows = foreach ($name in $script:ProgramDefs.Keys) {
        $def = $script:ProgramDefs[$name]
        $installed = [bool](Test-Installed -Name $name -Paths $def.Paths)
        $queued = (-not $installed) -and ($script:SelectedApps -contains $name)
        [PSCustomObject]@{
            Name      = $name
            Paths     = $def.Paths
            WingetId  = $def.WingetId
            Installed = $installed
            Selected  = $queued
        }
    }
    return @($rows)
}

function Clear-StaleInstallRoots {
    <#
      Purpose:
        Remove ProgramInstallRoots keys for apps no longer in the selected queue.

      When called:
        Sync-ProgramInstallQueue and after location picker changes.

      Side effects:
        Mutates $script:ProgramInstallRoots only.

      Undo implications:
        None.
    #>
    foreach ($k in @($script:ProgramInstallRoots.Keys)) {
        if ($script:SelectedApps -notcontains $k) {
            $script:ProgramInstallRoots.Remove($k)
        }
    }
}

function Install-BastionCatalogApp {
    <#
      Purpose:
        Install one curated catalog app via winget with catalog-only gates, optional
        --location, and post-install path/signature checks.

      When called:
        Apply when Programs section is on and queue is non-empty. Not Dry Run (preview only).

      Side effects / Windows objects touched:
        - winget install process (package files under vendor or --location path)
        - May create parent directory for custom location
        - $script:Stats.ProgramsInstalled on success paths
        - Console status via Write-Status

      Undo implications:
        Apply records successful names in ProgramsInstalledList for informational undo/
        uninstall menus. Bastion does not auto-uninstall on Recovery full undo of all
        sections; Programs menu uninstall is the intentional reverse path.

      Honesty (winget catalog-only):
        - REFUSES non-catalog names and WingetId mismatches
        - Never uses --ignore-security-hash
        - ManualInstallOnly apps are not winget-installed (URL hint only)
        - winget exit 0 without binary detection is Warn, not silent success claim only:
          still counted Applied with manual verify guidance
        - Trusted source preflight is necessary but not sufficient for package integrity
    #>
    param([string]$AppName, [string]$LocationPath = $null)

    if (-not $script:ProgramDefs.Contains($AppName)) {
        Write-Status ("REFUSED non-catalog app '{0}'" -f $AppName) "Failed"
        return $false
    }
    $def = $script:ProgramDefs[$AppName]
    if (Test-Installed -Name $AppName -Paths $def.Paths) {
        Write-Status ("{0} already installed" -f $AppName) "Already"
        return $true
    }
    if ($def.ManualInstallOnly) {
        $url = if ($def.ManualUrl) { [string]$def.ManualUrl } else { "(vendor site)" }
        Write-Status ("{0} is not available via winget" -f $AppName) "Warn"
        Write-Host ("      Download/install from: {0}" -f $url) -ForegroundColor Cyan
        Write-Host "      After install, Bastion will detect it for uninstall if paths match." -ForegroundColor DarkGray
        return $false
    }
    $idCheck = Test-CatalogPackageId -AppName $AppName -WingetId $def.WingetId
    if (-not $idCheck.Ok) {
        Write-Status ("REFUSED: {0}" -f $idCheck.Detail) "Failed"
        return $false
    }

    $pre = Test-WingetSecurityPreflight
    if (-not $pre.Ok) {
        Write-Status ("Install blocked: {0}" -f $pre.Detail) "Failed"
        return $false
    }
    Write-Host ("      {0}" -f $pre.Detail) -ForegroundColor DarkGray

    $show = Invoke-WingetShow -WingetId $def.WingetId
    if ($show.ExitCode -ne 0) {
        Write-Status ("{0}: winget show failed (exit {1}). Next step: check network/source with winget source list." -f $AppName, $show.ExitCode) "Failed"
        return $false
    }

    $argList = [System.Collections.Generic.List[string]]::new()
    [void]$argList.AddRange([string[]]@(
        "install","--id",$def.WingetId,"-e",
        "--accept-package-agreements","--accept-source-agreements",
        "--disable-interactivity","--silent"
    ))
    # Never pass --ignore-security-hash

    if ($LocationPath) {
        $vols = @(Get-AvailableInstallVolumes)
        $check = Test-SafeInstallRoot -Path $LocationPath -AllowedVolumes $vols
        if ($check.Ok) {
            [void]$argList.Add("--location")
            [void]$argList.Add($check.Path)
            Write-Host ("      Location: {0}" -f $check.Path) -ForegroundColor DarkGray
        } else {
            Write-Status ("Custom location ignored ({0}); vendor default will be used. Next step: pick a folder under a fixed drive." -f $check.Reason) "Warn"
        }
    }

    Write-Host ("      Installing {0} ({1})..." -f $AppName, $def.WingetId) -ForegroundColor White
    try {
        $p = Start-Process -FilePath "winget" -ArgumentList $argList -Wait -PassThru -NoNewWindow -ErrorAction Stop
    } catch {
        Write-Status ("{0} process error: {1}" -f $AppName, $_.Exception.Message) "Failed"
        return $false
    }

    Start-Sleep -Seconds 2
    $found = Test-Installed -Name $AppName -Paths $def.Paths

    if (-not $found -and $p.ExitCode -ne 0) {
        Write-Status ("{0} failed (winget exit {1}, binary not found). Next step: run winget install -e --id {2} manually." -f $AppName, $p.ExitCode, $def.WingetId) "Failed"
        return $false
    }
    if (-not $found -and $p.ExitCode -eq 0) {
        Write-Status ("{0} winget exit 0 but expected binary not detected yet. Next step: reboot or launch once, then re-run Audit." -f $AppName) "Warn"
        $script:Stats.ProgramsInstalled++
        Write-Status ("{0} reported OK by winget (verify manually)" -f $AppName) "Applied"
        return $true
    }

    foreach ($path in $def.Paths) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            $sig = Test-AuthenticodeRelaxed -Path $path
            Write-Host ("      Signature: {0} - {1}" -f $sig.Status, $sig.Detail) -ForegroundColor DarkGray
            if ($sig.Status -match 'HashMismatch|NotTrusted') {
                Write-Status ("{0} signature concern ({1}). Next step: uninstall if unexpected." -f $AppName, $sig.Status) "Warn"
            }
            break
        }
    }

    $script:Stats.ProgramsInstalled++
    Write-Status ("{0} installed and verified" -f $AppName) "Applied"
    return $true
}

function Select-InstallRootFromVolumes {
    <#
      Purpose:
        Interactive picker: system default, per-volume BastionApps folder, or custom path
        under an allowed fixed volume.

      When called:
        Programs menu location flow (Set-LocationsForPendingInstalls). Immediate UI only.

      Side effects:
        Console prompts only; returns path string or $null. Does not create folders here
        (Apply may create the root when installing).

      Undo implications:
        None.
    #>
    param([string]$PromptTitle = "Select install folder")
    $vols = @(Get-AvailableInstallVolumes)
    if ($vols.Count -eq 0) {
        Write-Host "  No fixed volumes found." -ForegroundColor Red
        return $null
    }
    Write-Host ""
    Write-Host ("  {0}" -f $PromptTitle) -ForegroundColor Cyan
    Write-Host "   0. System default (vendor / Program Files)  [recommended unless you need another drive]" -ForegroundColor Green
    for ($i = 0; $i -lt $vols.Count; $i++) {
        Write-Host ("  {0,2}. {1}  {2}  Free {3} GB  (uses {1}BastionApps)" -f ($i + 1), $vols[$i].Root, $vols[$i].Label, $vols[$i].FreeGB)
    }
    Write-Host ("  {0,2}. Custom path under a listed drive" -f ($vols.Count + 1))
    $valid = @("0") + (1..($vols.Count + 1) | ForEach-Object { "$_" })
    $c = Read-MenuChoice -Prompt "  Choice" -Valid $valid
    $n = [int]$c
    if ($n -eq 0) { return $null }
    if ($n -ge 1 -and $n -le $vols.Count) {
        $suggested = Join-Path ($vols[$n - 1].Root.TrimEnd('\')) "BastionApps"
        $check = Test-SafeInstallRoot -Path $suggested -AllowedVolumes $vols
        if ($check.Ok) { return $check.Path }
        Write-Host ("  Rejected: {0}" -f $check.Reason) -ForegroundColor Red
        return $null
    }
    Write-Host ""
    Write-Host "  Custom path rules:" -ForegroundColor Yellow
    Write-Host "    - Must start with a drive letter on this PC (examples below)" -ForegroundColor DarkGray
    Write-Host "    - Fixed internal disks only (not USB / network UNC paths)" -ForegroundColor DarkGray
    Write-Host "    - Not under Windows, System32, or WindowsApps" -ForegroundColor DarkGray
    Write-Host "    - No illegal characters: < > | ? * or control chars" -ForegroundColor DarkGray
    Write-Host "  Examples:" -ForegroundColor Cyan
    foreach ($v in $vols) {
        Write-Host ("    {0}Apps" -f $v.Root) -ForegroundColor White
        Write-Host ("    {0}BastionApps" -f $v.Root) -ForegroundColor White
    }
    Write-Host "  Tip: folder is created if missing when install runs. Some apps ignore custom locations." -ForegroundColor DarkGray
    Write-Host "  Enter blank line to cancel and return." -ForegroundColor DarkGray
    $attempts = 0
    while ($attempts -lt 5) {
        $attempts++
        try {
            $custom = Read-Host "  Full path"
        } catch {
            Write-Host "  Input error; try again or leave blank to cancel." -ForegroundColor Red
            continue
        }
        if ($null -eq $custom -or [string]::IsNullOrWhiteSpace([string]$custom)) {
            Write-Host "  Empty path - cancelled." -ForegroundColor Yellow
            return $null
        }
        $custom = ([string]$custom).Trim().Trim('"').Trim("'")
        if ($custom.Length -gt 180) {
            Write-Host "  Path too long (max 180 characters). Try a shorter folder." -ForegroundColor Red
            continue
        }
        $check = Test-SafeInstallRoot -Path $custom -AllowedVolumes $vols
        if ($check.Ok) {
            Write-Host ("  Accepted: {0}" -f $check.Path) -ForegroundColor Green
            return $check.Path
        }
        Write-Host ("  Rejected: {0}" -f $check.Reason) -ForegroundColor Red
        Write-Host "  Try again using an example above, pick a listed drive option, or blank to cancel." -ForegroundColor Yellow
    }
    Write-Host "  Too many invalid attempts - cancelled." -ForegroundColor Red
    return $null
}

function Set-LocationsForPendingInstalls {
    <#
      Purpose:
        Menu to set system default, one shared folder, or per-app install roots for
        currently pending (selected + missing) apps; saves config.

      When called:
        Programs menu (location option). Preference only until Apply installs.

      Side effects:
        Mutates $script:GlobalInstallRoot and $script:ProgramInstallRoots; Save-BastionConfig.

      Undo implications:
        None for OS. Config file holds roots until cleared.
    #>
    $pending = @(Get-SelectedMissingApps)
    if ($pending.Count -eq 0) {
        Write-Host "  No pending installs - location step skipped." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }
    Clear-BastionScreen
    Write-Header "INSTALL LOCATIONS (PENDING ONLY)"
    Write-Host "  Only apps selected and not yet installed:" -ForegroundColor Cyan
    foreach ($p in $pending) { Write-Host ("    - {0}" -f $p) -ForegroundColor White }
    Write-Host ""
    Write-Host "  1 System default   2 One folder for all   3 Per app   0 Cancel"
    $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3")
    switch ($c) {
        "0" { return }
        "1" {
            $script:GlobalInstallRoot = $null
            foreach ($p in $pending) {
                if ($script:ProgramInstallRoots.ContainsKey($p)) { $script:ProgramInstallRoots.Remove($p) }
            }
            Write-Host "  Using vendor defaults for pending installs." -ForegroundColor Green
        }
        "2" {
            $script:GlobalInstallRoot = Select-InstallRootFromVolumes -PromptTitle "Folder for all pending installs"
            foreach ($p in $pending) {
                if ($script:ProgramInstallRoots.ContainsKey($p)) { $script:ProgramInstallRoots.Remove($p) }
            }
        }
        "3" {
            $script:GlobalInstallRoot = $null
            foreach ($app in $pending) {
                $root = Select-InstallRootFromVolumes -PromptTitle ("Folder for {0}" -f $app)
                if ($root) { $script:ProgramInstallRoots[$app] = $root }
                elseif ($script:ProgramInstallRoots.ContainsKey($app)) { $script:ProgramInstallRoots.Remove($app) }
            }
        }
    }
    Clear-StaleInstallRoots
    Save-BastionConfig
    Start-Sleep -Seconds 1
}

function Stop-BastionCatalogProcesses {
    <#
      Purpose:
        Force-stop processes matching catalog EXE basenames (and PowerToys helper patterns)
        so uninstall can unlock files.

      When called:
        Before winget/HKCU uninstall of a catalog app (Programs uninstall menu).

      Side effects / Windows objects touched:
        Stop-Process -Force on matching PIDs. Unsaved app data may be lost.

      Undo implications:
        Processes stay stopped; reinstall/relaunch is user responsibility.
    #>
    param([string]$AppName)
    if (-not $script:ProgramDefs.Contains($AppName)) { return }
    $stopped = @{}
    foreach ($path in @($script:ProgramDefs[$AppName].Paths)) {
        $procName = [System.IO.Path]::GetFileNameWithoutExtension($path)
        if ([string]::IsNullOrWhiteSpace($procName)) { continue }
        try {
            Get-Process -Name $procName -ErrorAction SilentlyContinue | ForEach-Object {
                if ($stopped.ContainsKey($_.Id)) { return }
                try {
                    Stop-Process -Id $_.Id -Force -ErrorAction Stop
                    $stopped[$_.Id] = $true
                    Write-Host ("    Stopped process: {0} (PID {1})" -f $_.ProcessName, $_.Id) -ForegroundColor DarkGray
                } catch {}
            }
        } catch {}
    }
    # PowerToys ships many helpers (Command Palette, FancyZones, Awake, etc.)
    if ($AppName -eq "PowerToys") {
        $patterns = @(
            'PowerToys',
            'PowerToys.',
            'CommandPalette',
            'WindowsCommandPalette'
        )
        try {
            Get-Process -ErrorAction SilentlyContinue | Where-Object {
                $n = $_.ProcessName
                $pathOk = $false
                try { if ($_.Path -and ($_.Path -match 'PowerToys|CommandPalette')) { $pathOk = $true } } catch {}
                $nameOk = $false
                foreach ($pat in $patterns) {
                    if ($n -like ($pat + '*') -or $n -match [regex]::Escape($pat)) { $nameOk = $true; break }
                }
                $nameOk -or $pathOk
            } | ForEach-Object {
                if ($stopped.ContainsKey($_.Id)) { return }
                try {
                    Stop-Process -Id $_.Id -Force -ErrorAction Stop
                    $stopped[$_.Id] = $true
                    Write-Host ("    Stopped PowerToys-related: {0} (PID {1})" -f $_.ProcessName, $_.Id) -ForegroundColor DarkGray
                } catch {
                    Write-Host ("    Could not stop {0} (PID {1}): still locked" -f $_.ProcessName, $_.Id) -ForegroundColor Yellow
                }
            }
        } catch {}
        Start-Sleep -Milliseconds 900
    }
}

function Get-HkcuUninstallCommands {
    <#
      Purpose:
        Collect per-user uninstall registry entries whose DisplayName matches app name /
        WingetId / PowerToys needles.

      When called:
        Uninstall fallback when winget fails for user-scoped installs.

      Side effects:
        Registry read under HKCU Uninstall hives only.

      Undo implications:
        None (discovery only).
    #>
    param([string]$AppName, [string]$WingetId)
    $results = New-Object System.Collections.Generic.List[object]
    $roots = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $needles = @($AppName, "PowerToys")
    if ($WingetId) { $needles += $WingetId }
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        try {
            Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    $dn = [string]$p.DisplayName
                    if ([string]::IsNullOrWhiteSpace($dn)) { return }
                    $hit = $false
                    foreach ($n in $needles) {
                        if ($dn -like ("*{0}*" -f $n)) { $hit = $true; break }
                    }
                    if (-not $hit) { return }
                    $u = [string]$p.UninstallString
                    $q = [string]$p.QuietUninstallString
                    if (-not $u -and -not $q) { return }
                    [void]$results.Add([PSCustomObject]@{
                        DisplayName = $dn
                        UninstallString = $u
                        QuietUninstallString = $q
                        InstallLocation = [string]$p.InstallLocation
                    })
                } catch {}
            }
        } catch {}
    }
    return @($results)
}

function Invoke-HkcuUninstallString {
    <#
      Purpose:
        Parse and run an UninstallString / QuietUninstallString from HKCU (quoted EXE + args).

      When called:
        Uninstall fallback after winget attempts.

      Side effects:
        Starts vendor uninstaller process; may remove app files and registry.

      Undo implications:
        Uninstall is the reverse of install; reinstall via catalog/Apply if needed.
    #>
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    try {
        # Typical: "C:\Path\setup.exe" /uninstall /silent
        if ($CommandLine -match '^\s*"([^"]+)"\s*(.*)$') {
            $exe = $Matches[1]
            $args = $Matches[2]
            if (-not (Test-Path -LiteralPath $exe)) { return $false }
            Write-Host ("    Running HKCU uninstaller: {0} {1}" -f $exe, $args) -ForegroundColor DarkGray
            $proc = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -ErrorAction Stop
            return ($proc.ExitCode -eq 0 -or $null -eq $proc.ExitCode)
        }
        if ($CommandLine -match '^\s*(\S+\.exe)(\s+.*)?$') {
            $exe = $Matches[1]
            $args = if ($Matches[2]) { $Matches[2].Trim() } else { "" }
            if (-not (Test-Path -LiteralPath $exe)) { return $false }
            Write-Host ("    Running HKCU uninstaller: {0} {1}" -f $exe, $args) -ForegroundColor DarkGray
            if ($args) {
                $proc = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -ErrorAction Stop
            } else {
                $proc = Start-Process -FilePath $exe -Wait -PassThru -ErrorAction Stop
            }
            return ($proc.ExitCode -eq 0 -or $null -eq $proc.ExitCode)
        }
        Write-Host ("    HKCU uninstall string not parseable: {0}" -f $CommandLine) -ForegroundColor Yellow
        return $false
    } catch {
        Write-Host ("    HKCU uninstall failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        return $false
    }
}

function Invoke-WingetUninstallCatalog {
    <#
      Purpose:
        Uninstall a catalog app: stop processes, try winget scopes (user/default/machine),
        then HKCU registry, then PowerToys-specific --uninstall fallbacks.

      When called:
        Programs uninstall menu for detected catalog installs. Immediate (not via Apply).

      Side effects / Windows objects touched:
        - winget uninstall (package removal)
        - HKCU uninstallers / PowerToys setup --uninstall
        - May open ms-settings:appsfeatures on total failure
        - Temp files under $script:tempDir for winget output

      Undo implications:
        Removes software Bastion may have installed. Re-queue via menu 5 + Apply to reinstall.
        Elevated session often cannot remove pure user-scope apps; honesty messages guide
        non-admin winget or Settings.

      Honesty (catalog-only):
        Only catalog WingetId values are used. Scope failures for per-user apps are expected
        when Bastion runs elevated; Bastion does not claim silent success in that case.
    #>
    param([string]$AppName, [string]$WingetId)
    $outFile = Join-Path $script:tempDir "wg-un-out.txt"
    $errFile = Join-Path $script:tempDir "wg-un-err.txt"

    function Invoke-One {
        param([string[]]$ExtraArgs)
        $argList = @("uninstall","--id",$WingetId,"-e","--silent","--disable-interactivity") + @($ExtraArgs)
        try { if (Test-Path -LiteralPath $outFile) { Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue } } catch {}
        try { if (Test-Path -LiteralPath $errFile) { Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue } } catch {}
        $proc = Start-Process -FilePath "winget" -ArgumentList $argList `
            -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile -ErrorAction Stop
        $text = ""
        try { if (Test-Path -LiteralPath $outFile) { $text += Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue } } catch {}
        try { if (Test-Path -LiteralPath $errFile) { $text += Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue } } catch {}
        return [PSCustomObject]@{ ExitCode = $proc.ExitCode; Text = [string]$text }
    }

    function Show-WingetSnippet([string]$Text) {
        if (-not $Text -or $Text.Trim().Length -eq 0) { return }
        $snippet = @(($Text -replace '\r','') -split "`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -Last 6)
        foreach ($line in $snippet) {
            Write-Host ("    {0}" -f $line.Trim()) -ForegroundColor DarkGray
        }
    }

    Write-Host ("  Uninstalling {0}..." -f $AppName)
    try { Stop-BastionCatalogProcesses -AppName $AppName } catch {}

    # Prefer user-scope first when elevated (PowerToys and many Store/user installs)
    $attempts = @(
        @{ Label = "scope user"; Args = @("--scope","user") },
        @{ Label = "default scope"; Args = @() },
        @{ Label = "scope machine"; Args = @("--scope","machine") }
    )

    $last = $null
    $userScopeBlocked = $false
    foreach ($attempt in $attempts) {
        Write-Host ("    Trying winget uninstall ({0})..." -f $attempt.Label) -ForegroundColor DarkGray
        try {
            $last = Invoke-One -ExtraArgs $attempt.Args
        } catch {
            Write-Host ("    winget launch error: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            continue
        }
        Show-WingetSnippet $last.Text
        Write-Host ("    Exit {0}" -f $last.ExitCode) -ForegroundColor DarkGray
        if ($last.ExitCode -eq 0) {
            Write-Status ("{0} uninstall requested OK ({1})" -f $AppName, $attempt.Label) "Applied"
            return $true
        }
        if ($last.Text -match 'user scope cannot be uninstalled when running with administrator' -or $last.ExitCode -eq -1978335107) {
            $userScopeBlocked = $true
            # skip repeating the same failure mode; continue list still tries other scopes
            continue
        }
        # "No installed package found" on machine scope is expected for pure user installs - keep going / fall through
    }

    # HKCU uninstall registry fallback (works for many per-user MSI/EXE installs)
    Write-Host "    winget did not complete; trying HKCU uninstall registry..." -ForegroundColor Yellow
    $regs = @(Get-HkcuUninstallCommands -AppName $AppName -WingetId $WingetId)
    if ($regs.Count -eq 0) {
        Write-Host "    No HKCU uninstall entries matched." -ForegroundColor DarkGray
    } else {
        foreach ($reg in $regs) {
            Write-Host ("    Found: {0}" -f $reg.DisplayName) -ForegroundColor DarkGray
            $cmd = $reg.QuietUninstallString
            if ([string]::IsNullOrWhiteSpace($cmd)) { $cmd = $reg.UninstallString }
            if (Invoke-HkcuUninstallString -CommandLine $cmd) {
                Write-Status ("{0} uninstall via HKCU entry OK" -f $AppName) "Applied"
                return $true
            }
        }
    }

    # PowerToys explicit setup path fallback
    if ($AppName -eq "PowerToys") {
        $candidates = @(
            "$env:LOCALAPPDATA\PowerToys\PowerToys.exe",
            "C:\Program Files\PowerToys\PowerToys.exe",
            "C:\Program Files\PowerToys\PowerToysSetup*.exe"
        )
        foreach ($c in $candidates) {
            $files = @()
            if ($c -match '\*') {
                try { $files = @(Get-Item -Path $c -ErrorAction SilentlyContinue) } catch {}
            } elseif (Test-Path -LiteralPath $c) {
                $files = @(Get-Item -LiteralPath $c)
            }
            foreach ($f in $files) {
                try {
                    Write-Host ("    Trying: {0} --uninstall" -f $f.FullName) -ForegroundColor DarkGray
                    $proc = Start-Process -FilePath $f.FullName -ArgumentList @("--uninstall") -Wait -PassThru -ErrorAction Stop
                    if ($proc.ExitCode -eq 0) {
                        Write-Status "PowerToys --uninstall exit 0" "Applied"
                        return $true
                    }
                } catch {}
            }
        }
    }

    Write-Status ("{0} could not be uninstalled from this elevated session." -f $AppName) "Warn"
    Write-Host "    Per-user apps (PowerToys) often require a non-admin winget or Settings." -ForegroundColor Yellow
    Write-Host "    Try in a normal (non-admin) PowerShell:" -ForegroundColor Yellow
    Write-Host ("      winget uninstall -e --id {0} --scope user" -f $WingetId) -ForegroundColor Cyan
    Write-Host "    Or: Settings > Apps > Installed apps > PowerToys > Uninstall" -ForegroundColor Cyan
    try {
        Start-Process "ms-settings:appsfeatures" -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    Opened Settings > Apps for manual uninstall." -ForegroundColor DarkGray
    } catch {}
    return $false
}

function Get-DetectedCatalogInstalls {
    <#
      Purpose:
        List catalog apps whose install paths/binaries are present (for uninstall menu).

      When called:
        Programs uninstall UI.

      Side effects:
        Disk probes only.

      Undo implications:
        None.
    #>
    # Only catalog apps whose install paths/binaries are present right now.
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $script:ProgramDefs.Keys) {
        $def = $script:ProgramDefs[$name]
        if (Test-Installed -Name $name -Paths $def.Paths) {
            [void]$list.Add([PSCustomObject]@{
                Name     = $name
                WingetId = $def.WingetId
                Paths    = $def.Paths
            })
        }
    }
    return @($list)
}
