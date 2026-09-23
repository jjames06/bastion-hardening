# =============================================================================
# Bastion.Cve.ps1 - known Windows 10/11 CVE checks (v16.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.
#
# Role in modular architecture:
#   Catalog of workstation issues Bastion can DETECT on this PC, and where a
#   reliable, reversible, non-exploit remediation exists, FIX after confirm.
#   Main menu C runs this category separately (like browser policies: NOW).
#   Optional Apply section CveChecks is off by default and not in Quick Harden.
#   Recovery hub 7 reverts Bastion-applied registry/protocol remediations.
#
# Load-order position: after Harden (uses Defender update health), before Apply.
#   Order: Init, Core, Config, Programs, Services, Browsers, Dns, Network,
#          Harden, Cve, Apply, Recovery, Menus.
#
# Honesty (read this before adding a catalog row):
#   Bastion cannot patch Microsoft's kernel, ALPC, Update Stack, or Defender
#   platform bugs. Those need Windows Update / Defender platform updates.
#   For those CVEs we detect build/KB/platform version and start an update
#   scan. We do not ship exploit payloads, PoCs, or attack any endpoint.
#   Compensating controls (registry, uninstall, disk/signature recovery) are
#   labelled as such. Third-party antivirus turning Defender RTP off is a
#   product conflict, not a CVE this catalog "fixes".
#
# Fail-safes:
#   Scan is read-only. Remediate always confirms. Registry changes snapshot
#   prior values into Bastion-CveUndo.json (not secrets; ACL like config).
#   Uninstalls and protocol deletes are extra-confirmed. Restore-point
#   reminder before a batch. Revert restores only what Bastion recorded.
# =============================================================================

# -----------------------------------------------------------------------------
# Compare-BastionDottedVersion
#   Numeric compare of dotted versions (4.18.26040.7 vs 4.18.26080.4).
#   Missing segments treat as 0. Non-digits in a segment become 0.
#   Returns -1 (left < right), 0 equal, 1 (left > right).
# -----------------------------------------------------------------------------
function Compare-BastionDottedVersion {
    param(
        [string]$Left,
        [string]$Right
    )
    if ([string]::IsNullOrWhiteSpace($Left) -and [string]::IsNullOrWhiteSpace($Right)) { return 0 }
    if ([string]::IsNullOrWhiteSpace($Left)) { return -1 }
    if ([string]::IsNullOrWhiteSpace($Right)) { return 1 }
    $al = @($Left.Split('.') | ForEach-Object {
        $d = ($_ -replace '[^\d]', '')
        if ([string]::IsNullOrWhiteSpace($d)) { [int]0 } else { [int]$d }
    })
    $ar = @($Right.Split('.') | ForEach-Object {
        $d = ($_ -replace '[^\d]', '')
        if ([string]::IsNullOrWhiteSpace($d)) { [int]0 } else { [int]$d }
    })
    $n = [Math]::Max($al.Count, $ar.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $l = 0; $r = 0
        if ($i -lt $al.Count) { $l = $al[$i] }
        if ($i -lt $ar.Count) { $r = $ar[$i] }
        if ($l -lt $r) { return -1 }
        if ($l -gt $r) { return 1 }
    }
    return 0
}

# -----------------------------------------------------------------------------
# Get-BastionOsBuildInfo
#   CurrentBuild + UBR from CurrentVersion. DisplayVersion / ProductName for UI.
# -----------------------------------------------------------------------------
function Get-BastionOsBuildInfo {
    $cv = $null
    try { $cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop } catch {}
    $build = 0
    $ubr = 0
    if ($cv) {
        try { $build = [int]$cv.CurrentBuild } catch {}
        try { $ubr = [int]$cv.UBR } catch {}
    }
    [pscustomobject]@{
        ProductName    = if ($cv) { [string]$cv.ProductName } else { "" }
        DisplayVersion = if ($cv) { [string]$cv.DisplayVersion } else { "" }
        CurrentBuild   = $build
        UBR            = $ubr
        Full           = "{0}.{1}" -f $build, $ubr
    }
}

# -----------------------------------------------------------------------------
# Registry dword helpers used by PrintNightmare / WDigest / cert padding /
# AlwaysInstallElevated. Prior value $null means the name was absent.
# -----------------------------------------------------------------------------
function Get-BastionRegDword {
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $p = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $p) { return $null }
        $v = $p.$Name
        if ($null -eq $v) { return $null }
        return [int]$v
    } catch { return $null }
}

function Set-BastionRegDword {
    <#
      Purpose:
        Create the key if missing, set a DWORD, return prior value for undo.

      Undo implications:
        Caller must record Prior (may be $null) and restore with Restore-BastionRegDword.
    #>
    param([string]$Path, [string]$Name, [int]$Value)
    $prior = Get-BastionRegDword -Path $Path -Name $Name
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    return $prior
}

function Restore-BastionRegDword {
    param([string]$Path, [string]$Name, $Prior)
    try {
        if ($null -eq $Prior) {
            if (Test-Path -LiteralPath $Path) {
                Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
            }
            return
        }
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value ([int]$Prior) -Force | Out-Null
    } catch {
        throw
    }
}

# -----------------------------------------------------------------------------
# CVE undo file (Bastion-CveUndo.json). Not secrets. Same ACL as config.
# -----------------------------------------------------------------------------
function Get-BastionCveUndoPath {
    if ($script:cveUndoFile) { return $script:cveUndoFile }
    $dir = $script:Config.LogDirectory
    if ([string]::IsNullOrWhiteSpace($dir)) { $dir = "C:\Temp\Bastion" }
    return (Join-Path $dir "Bastion-CveUndo.json")
}

function Save-BastionCveUndo {
    param($Batch)
    $path = Get-BastionCveUndoPath
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $items = @()
    if ($Batch) {
        if ($Batch -is [System.Array]) {
            $items = $Batch
        } elseif ($Batch.PSObject.Methods['ToArray']) {
            $items = $Batch.ToArray()
        } else {
            $items = @($Batch)
        }
    }
    $payload = [ordered]@{
        Timestamp     = (Get-Date).ToString("o")
        ScriptVersion = $script:Config.ScriptVersion
        Items         = $items
    }
    ($payload | ConvertTo-Json -Depth 8) | Out-File -LiteralPath $path -Encoding utf8 -Force
    try {
        $acl = Get-Acl -LiteralPath $path
        $acl.SetAccessRuleProtection($true, $false)
        $sys = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
        $adm = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
        $acl.AddAccessRule($sys)
        $acl.AddAccessRule($adm)
        Set-Acl -LiteralPath $path -AclObject $acl
    } catch {}
}

function Get-BastionCveUndo {
    $path = Get-BastionCveUndoPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch { return $null }
}

function Add-BastionCveUndoItem {
    param($List, [string]$Id, [string]$Kind, $Data)
    [void]$List.Add([pscustomobject]@{
        Id   = $Id
        Kind = $Kind
        Data = $Data
    })
}

# -----------------------------------------------------------------------------
# Write-CveProgress / Write-CveResult
#   Live operator-facing lines while a scan or remediate batch runs.
# -----------------------------------------------------------------------------
function Write-CveProgress {
    param(
        [int]$Index,
        [int]$Total,
        [string]$Title,
        [string]$Detail = ""
    )
    Write-Host ("  [{0}/{1}] {2}" -f $Index, $Total, $Title) -ForegroundColor Cyan
    if (-not [string]::IsNullOrWhiteSpace($Detail)) {
        Write-Host ("           {0}" -f $Detail) -ForegroundColor DarkGray
    }
}

function Write-CveResultLine {
    param(
        [ValidateSet("Healthy","Exposed","Compensating","Info","Unknown","NotPresent")]
        [string]$Status,
        [string]$Detail
    )
    $col = switch ($Status) {
        "Healthy"       { "Green" }
        "Exposed"       { "Red" }
        "Compensating"  { "Yellow" }
        "Info"          { "DarkGray" }
        "Unknown"       { "DarkGray" }
        "NotPresent"    { "DarkGray" }
    }
    Write-Host ("           {0}: {1}" -f $Status.ToUpper(), $Detail) -ForegroundColor $col
}

# -----------------------------------------------------------------------------
# Catalog: each row is a hashtable with Id, Title, Cves (string[]), Category,
# Honesty, AutoOnApply (safe enough for optional Apply section), Detect /
# Remediate / Revert scriptblock names (functions below).
# -----------------------------------------------------------------------------
function Get-BastionCveCatalog {
    @(
        [pscustomobject]@{
            Id          = "WIN-SEP2026"
            Title       = "September 2026 Windows security updates"
            Cves        = @("CVE-2026-85880","CVE-2026-81963","CVE-2026-62721","CVE-2026-85921")
            Category    = "Windows Update"
            Honesty     = "Kernel, ALPC, Update Stack, and UMPS bugs need Microsoft's cumulative/OOB packages. Bastion starts a Windows Update scan and opens Settings. It does not silently install KBs."
            AutoOnApply = $true
            CanRevert   = $false
        }
        [pscustomobject]@{
            Id          = "DEFENDER-UNDEFEND"
            Title       = "Defender platform UnDefend"
            Cves        = @("CVE-2026-45498")
            Category    = "Defender"
            Honesty     = "UnDefend (DoS of Defender updates) is fixed in Antimalware Platform 4.18.26040.7 and later. Bastion requests a signature/platform update. It cannot backport Microsoft's patch."
            AutoOnApply = $true
            CanRevert   = $false
        }
        [pscustomobject]@{
            Id          = "DEFENDER-REDSUN"
            Title       = "Defender engine RedSun"
            Cves        = @("CVE-2026-41091")
            Category    = "Defender"
            Honesty     = "RedSun (local privilege escalation via the engine) is fixed in engine 1.1.26040.8 and later. Same update path as UnDefend."
            AutoOnApply = $true
            CanRevert   = $false
        }
        [pscustomobject]@{
            Id          = "BIGDISKBUSTER"
            Title       = "Defender update starvation (disk fill)"
            Cves        = @("public PoC, no CVE")
            Category    = "Defender"
            Honesty     = "BigDiskBuster fills C: while Defender updates so signatures stay stale. No Microsoft patch in the Sep 2026 write-ups. Bastion shows disk/signature health, optional TEMP cleanup you confirm, and a signature update."
            AutoOnApply = $true
            CanRevert   = $false
        }
        [pscustomobject]@{
            Id          = "SMBV1"
            Title       = "SMBv1 (EternalBlue-class)"
            Cves        = @("CVE-2017-0144","CVE-2017-0145")
            Category    = "OS feature"
            Honesty     = "Disables the optional SMB1Protocol feature. Old NAS that only speaks SMB1 will fail until you upgrade the device."
            AutoOnApply = $true
            CanRevert   = $false
        }
        [pscustomobject]@{
            Id          = "PRINTNIGHTMARE"
            Title       = "PrintNightmare Point and Print"
            Cves        = @("CVE-2021-34527","CVE-2021-1675","CVE-2021-34481")
            Category    = "Print"
            Honesty     = "Microsoft's remaining hardening is RestrictDriverInstallationToAdministrators. Home USB printing still works. Installing a printer driver from the network then needs an administrator."
            AutoOnApply = $true
            CanRevert   = $true
        }
        [pscustomobject]@{
            Id          = "FOLLINA"
            Title       = "MSDT URL protocol (Follina workaround)"
            Cves        = @("CVE-2022-30190")
            Category    = "Office / MSDT"
            Honesty     = "Current Windows Update is the real fix. Removing the ms-msdt URL protocol is Microsoft's old workaround. Bastion only offers it when the protocol is still registered AND you confirm. Diagnostics Troubleshooting click-once from Office may break until reverted."
            AutoOnApply = $false
            CanRevert   = $true
        }
        [pscustomobject]@{
            Id          = "CERT-PADDING"
            Title       = "WinVerifyTrust certificate padding"
            Cves        = @("CVE-2013-3900")
            Category    = "Crypto"
            Honesty     = "EnableCertPaddingCheck is Microsoft's recommended Wintrust hardening. Rare old installers that ship malformed Authenticode may fail to verify."
            AutoOnApply = $true
            CanRevert   = $true
        }
        [pscustomobject]@{
            Id          = "WDIGEST"
            Title       = "WDigest cleartext credential cache"
            Cves        = @("mitigation (Mimikatz-class)")
            Category    = "Credentials"
            Honesty     = "UseLogonCredential=0 stops WDigest from keeping reversible logon credentials in LSASS. Default on modern Windows is already off; Bastion sets 0 if someone turned it on."
            AutoOnApply = $true
            CanRevert   = $true
        }
        [pscustomobject]@{
            Id          = "ALWAYSINSTALLELEVATED"
            Title       = "AlwaysInstallElevated (MSI as SYSTEM)"
            Cves        = @("misconfiguration")
            Category    = "Installer"
            Honesty     = "If both HKLM and HKCU AlwaysInstallElevated are 1, any user can install MSI as SYSTEM. Bastion sets them to 0. That is a misconfiguration fix, not a Microsoft CVE patch."
            AutoOnApply = $true
            CanRevert   = $true
        }
        [pscustomobject]@{
            Id          = "VLC-2026"
            Title       = "VLC 3.0.0-3.0.23 picture/RTSP bugs"
            Cves        = @("CVE-2026-56711","CVE-2026-73324")
            Category    = "App"
            Honesty     = "Affected versions are 3.0.0 through 3.0.23. If VideoLAN has not shipped a fixed 3.x build, uninstall is the compensating control. Bastion never force-uninstalls without Yes."
            AutoOnApply = $false
            CanRevert   = $false
        }
    )
}

# -----------------------------------------------------------------------------
# Detect implementations
# Status: Healthy | Exposed | Compensating | Info | Unknown | NotPresent
# -----------------------------------------------------------------------------
function Test-BastionCveWinSep2026 {
    $os = Get-BastionOsBuildInfo
    $need = $null
    $kb = ""
    switch ($os.CurrentBuild) {
        28000 { $need = 2956; $kb = "KB5129194" }
        26200 { $need = 9457; $kb = "KB5129195" }
        26100 { $need = 9457; $kb = "KB5129195" }
        22631 { $need = 7582; $kb = "KB5122880" }
        22621 { $need = 7582; $kb = "KB5122880" }
        19045 { $need = 7727; $kb = "KB5129236" }
        19044 { $need = 7727; $kb = "KB5129236" }
        default { $need = $null }
    }
    $hotfix = $false
    if ($kb) {
        try {
            if (Get-HotFix -Id $kb -ErrorAction SilentlyContinue) { $hotfix = $true }
        } catch {}
    }
    $detail = ("Build {0} ({1} {2})" -f $os.Full, $os.ProductName, $os.DisplayVersion)
    if ($null -eq $need) {
        return [pscustomobject]@{ Status = "Unknown"; Detail = ($detail + " - no floor in this catalog for this SKU; use Windows Update") }
    }
    if ($hotfix -or $os.UBR -ge $need) {
        return [pscustomobject]@{ Status = "Healthy"; Detail = ($detail + "; " + $kb + " / UBR floor met") }
    }
    return [pscustomobject]@{ Status = "Exposed"; Detail = ($detail + "; need " + $kb + " (UBR >= " + $need + ") for Sep 2026 CU/OOB") }
}

function Test-BastionCveDefenderPlatform {
    param([string]$MinVersion, [string]$Label)
    $st = $null
    try { $st = Get-MpComputerStatus -ErrorAction Stop } catch {}
    if (-not $st) {
        return [pscustomobject]@{ Status = "Unknown"; Detail = "Get-MpComputerStatus failed (third-party antivirus may own the slot)" }
    }
    $ver = [string]$st.AMProductVersion
    if ([string]::IsNullOrWhiteSpace($ver)) { $ver = [string]$st.AMEngineVersion }
    if ([string]::IsNullOrWhiteSpace($ver)) {
        return [pscustomobject]@{ Status = "Unknown"; Detail = "Defender did not report a platform version" }
    }
    $cmp = Compare-BastionDottedVersion -Left $ver -Right $MinVersion
    if ($cmp -ge 0) {
        return [pscustomobject]@{ Status = "Healthy"; Detail = ("{0} {1} (floor {2})" -f $Label, $ver, $MinVersion) }
    }
    return [pscustomobject]@{ Status = "Exposed"; Detail = ("{0} {1} is below {2}" -f $Label, $ver, $MinVersion) }
}

function Test-BastionCveDefenderEngine {
    param([string]$MinVersion)
    $st = $null
    try { $st = Get-MpComputerStatus -ErrorAction Stop } catch {}
    if (-not $st) {
        return [pscustomobject]@{ Status = "Unknown"; Detail = "Get-MpComputerStatus failed" }
    }
    $ver = [string]$st.AMEngineVersion
    if ([string]::IsNullOrWhiteSpace($ver)) {
        return [pscustomobject]@{ Status = "Unknown"; Detail = "Defender did not report an engine version" }
    }
    $cmp = Compare-BastionDottedVersion -Left $ver -Right $MinVersion
    if ($cmp -ge 0) {
        return [pscustomobject]@{ Status = "Healthy"; Detail = ("Engine {0} (floor {1})" -f $ver, $MinVersion) }
    }
    return [pscustomobject]@{ Status = "Exposed"; Detail = ("Engine {0} is below {1}" -f $ver, $MinVersion) }
}

function Test-BastionCveBigDiskBuster {
    $h = $null
    try { $h = Get-BastionDefenderUpdateHealth } catch {}
    if (-not $h) {
        return [pscustomobject]@{ Status = "Unknown"; Detail = "Defender update health query failed" }
    }
    $bits = @()
    if ($null -ne $h.FreeGiB -and $h.FreeGiB -lt 5) { $bits += ("C: {0} GiB free" -f $h.FreeGiB) }
    if ($null -ne $h.SignatureAgeDays -and $h.SignatureAgeDays -gt 7) { $bits += ("signatures {0:N0} days old" -f $h.SignatureAgeDays) }
    if ($h.FillSuspects.Count -gt 0) { $bits += ("{0} oversized hidden TEMP file(s)" -f $h.FillSuspects.Count) }
    if ($h.RecentUpdateFailures.Count -gt 0) { $bits += ("{0} recent update-failure event(s)" -f $h.RecentUpdateFailures.Count) }
    if ($bits.Count -gt 0) {
        return [pscustomobject]@{ Status = "Exposed"; Detail = ($bits -join "; ") }
    }
    $ok = ("C: {0} GiB; signatures {1:N1}d; TEMP fill files 0" -f $h.FreeGiB, $h.SignatureAgeDays)
    return [pscustomobject]@{ Status = "Healthy"; Detail = $ok }
}

function Test-BastionCveSmbv1 {
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($f.State -eq "Enabled") {
            return [pscustomobject]@{ Status = "Exposed"; Detail = "SMB1Protocol is Enabled" }
        }
        return [pscustomobject]@{ Status = "Healthy"; Detail = ("SMB1Protocol is {0}" -f $f.State) }
    } catch {
        return [pscustomobject]@{ Status = "Unknown"; Detail = $_.Exception.Message }
    }
}

function Test-BastionCvePrintNightmare {
    $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $v = Get-BastionRegDword -Path $p -Name "RestrictDriverInstallationToAdministrators"
    if ($v -eq 1) {
        return [pscustomobject]@{ Status = "Healthy"; Detail = "RestrictDriverInstallationToAdministrators=1" }
    }
    if ($null -eq $v) {
        return [pscustomobject]@{ Status = "Exposed"; Detail = "Point and Print restriction is not set (Microsoft remaining hardening)" }
    }
    return [pscustomobject]@{ Status = "Exposed"; Detail = ("RestrictDriverInstallationToAdministrators={0}" -f $v) }
}

function Test-BastionCveFollina {
    $hkcr = "Registry::HKEY_CLASSES_ROOT\ms-msdt"
    $present = Test-Path -LiteralPath $hkcr
    $os = Get-BastionOsBuildInfo
    if (-not $present) {
        return [pscustomobject]@{ Status = "Healthy"; Detail = "ms-msdt URL protocol is not registered" }
    }
    if ($os.CurrentBuild -ge 19045) {
        return [pscustomobject]@{ Status = "Info"; Detail = "Protocol still registered; current Windows Update is the real Follina fix. Workaround (delete protocol) is optional." }
    }
    return [pscustomobject]@{ Status = "Exposed"; Detail = "ms-msdt protocol present on an older build; Windows Update first, optional protocol removal as workaround" }
}

function Test-BastionCveCertPadding {
    $a = Get-BastionRegDword -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck"
    if ($a -eq 1) {
        return [pscustomobject]@{ Status = "Healthy"; Detail = "EnableCertPaddingCheck=1" }
    }
    return [pscustomobject]@{ Status = "Exposed"; Detail = "EnableCertPaddingCheck is not 1 (CVE-2013-3900 recommended hardening)" }
}

function Test-BastionCveWdigest {
    $v = Get-BastionRegDword -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential"
    if ($null -eq $v -or $v -eq 0) {
        return [pscustomobject]@{ Status = "Healthy"; Detail = $(if ($null -eq $v) { "UseLogonCredential absent (default off)" } else { "UseLogonCredential=0" }) }
    }
    return [pscustomobject]@{ Status = "Exposed"; Detail = "UseLogonCredential=1 (WDigest may cache cleartext credentials)" }
}

function Test-BastionCveAlwaysInstallElevated {
    $hklm = Get-BastionRegDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated"
    $hkcu = Get-BastionRegDword -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated"
    if ($hklm -eq 1 -and $hkcu -eq 1) {
        return [pscustomobject]@{ Status = "Exposed"; Detail = "Both HKLM and HKCU AlwaysInstallElevated=1 (MSI as SYSTEM)" }
    }
    if ($hklm -eq 1 -or $hkcu -eq 1) {
        return [pscustomobject]@{ Status = "Info"; Detail = "One hive is 1; both must be 1 for the classic abuse. Bastion can still set both to 0." }
    }
    return [pscustomobject]@{ Status = "Healthy"; Detail = "AlwaysInstallElevated is not enabled" }
}

function Get-BastionVlcInstall {
    $paths = @(
        (Join-Path ${env:ProgramFiles} "VideoLAN\VLC\vlc.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "VideoLAN\VLC\vlc.exe")
    )
    foreach ($p in $paths) {
        if ($p -and (Test-Path -LiteralPath $p)) {
            $ver = $null
            try { $ver = [string](Get-Item -LiteralPath $p).VersionInfo.ProductVersion } catch {}
            if (-not $ver) {
                try { $ver = [string](Get-Item -LiteralPath $p).VersionInfo.FileVersion } catch {}
            }
            return [pscustomobject]@{ Path = $p; Version = $ver }
        }
    }
    return $null
}

function Test-BastionCveVlc {
    $vlc = Get-BastionVlcInstall
    if (-not $vlc) {
        return [pscustomobject]@{ Status = "NotPresent"; Detail = "VLC is not installed in Program Files" }
    }
    $ver = $vlc.Version
    if ([string]::IsNullOrWhiteSpace($ver)) {
        return [pscustomobject]@{ Status = "Unknown"; Detail = ("VLC present at {0} (version unread)" -f $vlc.Path) }
    }
    $cmpLow = Compare-BastionDottedVersion -Left $ver -Right "3.0.0"
    $cmpHigh = Compare-BastionDottedVersion -Left $ver -Right "3.0.24"
    if ($cmpLow -ge 0 -and $cmpHigh -lt 0) {
        return [pscustomobject]@{ Status = "Exposed"; Detail = ("VLC {0} is in 3.0.0-3.0.23 (CVE-2026-56711 / CVE-2026-73324)" -f $ver) }
    }
    return [pscustomobject]@{ Status = "Healthy"; Detail = ("VLC {0}" -f $ver) }
}

function Invoke-BastionCveDetect {
    param($Entry)
    switch ($Entry.Id) {
        "WIN-SEP2026"        { return Test-BastionCveWinSep2026 }
        "DEFENDER-UNDEFEND"  { return Test-BastionCveDefenderPlatform -MinVersion "4.18.26040.7" -Label "Platform" }
        "DEFENDER-REDSUN"    { return Test-BastionCveDefenderEngine -MinVersion "1.1.26040.8" }
        "BIGDISKBUSTER"      { return Test-BastionCveBigDiskBuster }
        "SMBV1"              { return Test-BastionCveSmbv1 }
        "PRINTNIGHTMARE"     { return Test-BastionCvePrintNightmare }
        "FOLLINA"            { return Test-BastionCveFollina }
        "CERT-PADDING"       { return Test-BastionCveCertPadding }
        "WDIGEST"            { return Test-BastionCveWdigest }
        "ALWAYSINSTALLELEVATED" { return Test-BastionCveAlwaysInstallElevated }
        "VLC-2026"           { return Test-BastionCveVlc }
        default              { return [pscustomobject]@{ Status = "Unknown"; Detail = "No detector" } }
    }
}

# -----------------------------------------------------------------------------
# Invoke-BastionCveScan
#   Read-only pass over the catalog. Prints live progress. Returns result rows.
# -----------------------------------------------------------------------------
function Invoke-BastionCveScan {
    param([switch]$Quiet)
    $cat = @(Get-BastionCveCatalog)
    $out = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($e in $cat) {
        $i++
        if (-not $Quiet) {
            Write-CveProgress -Index $i -Total $cat.Count -Title $e.Title -Detail ($e.Cves -join ", ")
        }
        $r = $null
        try {
            $r = Invoke-BastionCveDetect -Entry $e
        } catch {
            $r = [pscustomobject]@{ Status = "Unknown"; Detail = $_.Exception.Message }
        }
        if (-not $r) { $r = [pscustomobject]@{ Status = "Unknown"; Detail = "Detector returned nothing" } }
        if (-not $Quiet) { Write-CveResultLine -Status $r.Status -Detail $r.Detail }
        [void]$out.Add([pscustomobject]@{
            Id          = $e.Id
            Title       = $e.Title
            Cves        = $e.Cves
            Category    = $e.Category
            Honesty     = $e.Honesty
            AutoOnApply = [bool]$e.AutoOnApply
            CanRevert   = [bool]$e.CanRevert
            Status      = $r.Status
            Detail      = $r.Detail
        })
    }
    return @($out.ToArray())
}

# -----------------------------------------------------------------------------
# Remediations (confirm happens in the menu unless -NoConfirm for Apply auto
# items that are already gated by Apply YES).
# -----------------------------------------------------------------------------
function Invoke-BastionStartWindowsUpdateScan {
    $started = $false
    $uso = Join-Path $env:SystemRoot "System32\UsoClient.exe"
    if (Test-Path -LiteralPath $uso) {
        try {
            Start-Process -FilePath $uso -ArgumentList "StartInteractiveScan" -WindowStyle Hidden | Out-Null
            $started = $true
            Write-Status "UsoClient StartInteractiveScan requested." "Applied"
        } catch {
            Write-Status ("UsoClient: {0}" -f $_.Exception.Message) "Warn"
        }
    }
    try {
        Start-Process "ms-settings:windowsupdate" | Out-Null
        Write-Status "Opened Windows Update settings. Complete the download there and reboot if Windows asks." "Info"
        $started = $true
    } catch {
        Write-Status ("Could not open Settings: {0}" -f $_.Exception.Message) "Warn"
    }
    return $started
}

function Invoke-BastionCveRemediate {
    param(
        $Entry,
        $UndoList,
        [switch]$NoConfirm
    )
    $id = $Entry.Id
    Write-Host ("    Remediate: {0}" -f $Entry.Title) -ForegroundColor Yellow
    Write-Host ("    {0}" -f $Entry.Honesty) -ForegroundColor DarkGray
    switch ($id) {
        "WIN-SEP2026" {
            [void](Invoke-BastionStartWindowsUpdateScan)
            return
        }
        "DEFENDER-UNDEFEND" {
            Invoke-BastionDefenderSignatureUpdate -NoConfirm:$NoConfirm
            return
        }
        "DEFENDER-REDSUN" {
            Invoke-BastionDefenderSignatureUpdate -NoConfirm:$NoConfirm
            return
        }
        "BIGDISKBUSTER" {
            $h = Get-BastionDefenderUpdateHealth
            if ($h.FillSuspects.Count -gt 0) {
                Invoke-BastionClearSuspectedFillFiles -Health $h
            }
            Invoke-BastionDefenderSignatureUpdate -NoConfirm:$NoConfirm
            return
        }
        "SMBV1" {
            try {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
                Write-Status "SMB1Protocol disable requested (reboot may be needed)." "Applied"
            } catch {
                Write-Status ("SMBv1 disable: {0}" -f $_.Exception.Message) "Failed"
            }
            return
        }
        "PRINTNIGHTMARE" {
            $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
            $prior = Set-BastionRegDword -Path $path -Name "RestrictDriverInstallationToAdministrators" -Value 1
            Add-BastionCveUndoItem -List $UndoList -Id $id -Kind "RegDword" -Data @{ Path = $path; Name = "RestrictDriverInstallationToAdministrators"; Prior = $prior }
            $p2 = Set-BastionRegDword -Path $path -Name "NoWarningNoElevationOnInstall" -Value 0
            Add-BastionCveUndoItem -List $UndoList -Id $id -Kind "RegDword" -Data @{ Path = $path; Name = "NoWarningNoElevationOnInstall"; Prior = $p2 }
            Write-Status "Point and Print: RestrictDriverInstallationToAdministrators=1." "Applied"
            return
        }
        "FOLLINA" {
            $key = "Registry::HKEY_CLASSES_ROOT\ms-msdt"
            if (-not (Test-Path -LiteralPath $key)) {
                Write-Status "ms-msdt protocol already absent." "Already"
                return
            }
            $dir = $script:Config.LogDirectory
            if (-not $dir) { $dir = "C:\Temp\Bastion" }
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $bak = Join-Path $dir "ms-msdt-follina-backup.reg"
            try {
                & reg.exe export "HKCR\ms-msdt" $bak /y 2>$null | Out-Null
                Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Stop
                Add-BastionCveUndoItem -List $UndoList -Id $id -Kind "RegExport" -Data @{ Backup = $bak; Key = "HKCR\ms-msdt" }
                Write-Status ("Removed ms-msdt protocol. Backup: {0}" -f $bak) "Applied"
            } catch {
                Write-Status ("Follina workaround failed: {0}" -f $_.Exception.Message) "Failed"
            }
            return
        }
        "CERT-PADDING" {
            $p1 = "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config"
            $p2 = "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
            $a = Set-BastionRegDword -Path $p1 -Name "EnableCertPaddingCheck" -Value 1
            Add-BastionCveUndoItem -List $UndoList -Id $id -Kind "RegDword" -Data @{ Path = $p1; Name = "EnableCertPaddingCheck"; Prior = $a }
            try {
                $b = Set-BastionRegDword -Path $p2 -Name "EnableCertPaddingCheck" -Value 1
                Add-BastionCveUndoItem -List $UndoList -Id $id -Kind "RegDword" -Data @{ Path = $p2; Name = "EnableCertPaddingCheck"; Prior = $b }
            } catch {}
            Write-Status "EnableCertPaddingCheck=1 (Wintrust)." "Applied"
            return
        }
        "WDIGEST" {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
            $prior = Set-BastionRegDword -Path $path -Name "UseLogonCredential" -Value 0
            Add-BastionCveUndoItem -List $UndoList -Id $id -Kind "RegDword" -Data @{ Path = $path; Name = "UseLogonCredential"; Prior = $prior }
            Write-Status "WDigest UseLogonCredential=0." "Applied"
            return
        }
        "ALWAYSINSTALLELEVATED" {
            $p1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
            $p2 = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
            $a = Set-BastionRegDword -Path $p1 -Name "AlwaysInstallElevated" -Value 0
            $b = Set-BastionRegDword -Path $p2 -Name "AlwaysInstallElevated" -Value 0
            Add-BastionCveUndoItem -List $UndoList -Id $id -Kind "RegDword" -Data @{ Path = $p1; Name = "AlwaysInstallElevated"; Prior = $a }
            Add-BastionCveUndoItem -List $UndoList -Id $id -Kind "RegDword" -Data @{ Path = $p2; Name = "AlwaysInstallElevated"; Prior = $b }
            Write-Status "AlwaysInstallElevated set to 0 in HKLM and HKCU." "Applied"
            return
        }
        "VLC-2026" {
            $vlc = Get-BastionVlcInstall
            if (-not $vlc) {
                Write-Status "VLC is not installed." "Already"
                return
            }
            $ok = $false
            try {
                $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
                if ($winget) {
                    $p = Start-Process -FilePath $winget.Source -ArgumentList @("uninstall","--id","VideoLAN.VLC","-e","--accept-source-agreements","--disable-interactivity") -Wait -PassThru -WindowStyle Hidden
                    if ($p.ExitCode -eq 0) { $ok = $true }
                    Write-Status ("winget uninstall VideoLAN.VLC exit {0}" -f $p.ExitCode) $(if ($ok) { "Applied" } else { "Warn" })
                }
            } catch {
                Write-Status ("winget VLC uninstall: {0}" -f $_.Exception.Message) "Warn"
            }
            if (-not $ok) {
                Write-Status "If VLC remains, use Settings > Apps or Recovery is not available for a reinstall (vendor installer)." "Warn"
            }
            return
        }
        default {
            Write-Status ("No remediate handler for {0}" -f $id) "Warn"
        }
    }
}

function Invoke-BastionCveRevertItem {
    param($Item)
    $kind = [string]$Item.Kind
    $data = $Item.Data
    if ($kind -eq "RegDword") {
        Restore-BastionRegDword -Path ([string]$data.Path) -Name ([string]$data.Name) -Prior $data.Prior
        Write-Status ("Restored {0}\{1}" -f $data.Path, $data.Name) "Applied"
        return
    }
    if ($kind -eq "RegExport") {
        $bak = [string]$data.Backup
        if ($bak -and (Test-Path -LiteralPath $bak)) {
            $p = Start-Process -FilePath "reg.exe" -ArgumentList @("import", $bak) -Wait -PassThru -WindowStyle Hidden
            Write-Status ("reg import {0} exit {1}" -f $bak, $p.ExitCode) $(if ($p.ExitCode -eq 0) { "Applied" } else { "Failed" })
        } else {
            Write-Status "Follina backup .reg is missing; cannot restore ms-msdt." "Failed"
        }
        return
    }
    Write-Status ("Unknown undo kind {0}" -f $kind) "Warn"
}

function Invoke-BastionCveRevertAll {
    $u = Get-BastionCveUndo
    if (-not $u -or -not $u.Items -or @($u.Items).Count -eq 0) {
        Write-Status "No Bastion CVE undo file (nothing to reverse)." "Already"
        return
    }
    Write-Host ("    Reverting {0} recorded item(s) from {1}" -f @($u.Items).Count, $u.Timestamp) -ForegroundColor Yellow
    foreach ($item in @($u.Items)) {
        try {
            Invoke-BastionCveRevertItem -Item $item
        } catch {
            Write-Status ("Revert {0} failed: {1}" -f $item.Id, $_.Exception.Message) "Failed"
        }
    }
}

# -----------------------------------------------------------------------------
# Invoke-BastionCveRemediateBatch
#   Runs remediations for selected catalog rows. Saves undo when any reversible
#   registry/protocol change is recorded.
# -----------------------------------------------------------------------------
function Invoke-BastionCveRemediateBatch {
    param(
        $Entries,
        [switch]$NoConfirm,
        [switch]$AutoOnly
    )
    $list = New-Object System.Collections.Generic.List[object]
    $n = 0
    $total = @($Entries).Count
    foreach ($e in @($Entries)) {
        $n++
        if ($AutoOnly -and -not $e.AutoOnApply) {
            Write-CveProgress -Index $n -Total $total -Title $e.Title -Detail "Skipped (not an Apply-safe auto item; use menu C)"
            continue
        }
        Write-CveProgress -Index $n -Total $total -Title $e.Title -Detail "Remediating"
        try {
            Invoke-BastionCveRemediate -Entry $e -UndoList $list -NoConfirm:$NoConfirm
        } catch {
            Write-Status ("{0}: {1}" -f $e.Id, $_.Exception.Message) "Failed"
        }
    }
    if ($list.Count -gt 0) {
        Save-BastionCveUndo -Batch $list.ToArray()
        Write-Status ("CVE undo saved ({0} item(s)). Recovery > 7 can reverse Bastion registry/protocol changes." -f $list.Count) "Info"
    }
}

# -----------------------------------------------------------------------------
# Show-CveChecksMenu
#   Main menu C. Scan is read-only. Remediate after Yes + restore reminder.
# -----------------------------------------------------------------------------
function Show-CveChecksMenu {
    $last = $null
    while ($true) {
        Clear-BastionScreen
        Write-Header "KNOWN CVE CHECKS"
        Write-AppliesWhen -Mode Now -Extra "Scan is read-only. Remediations run from this menu after you confirm. Optional Apply section CveChecks is off by default."
        Write-Host ""
        Write-Host "  Honest scope" -ForegroundColor Yellow
        Write-Host "    Bastion cannot patch Microsoft kernel or Defender platform bugs." -ForegroundColor DarkGray
        Write-Host "    Those rows start Windows Update or a Defender signature update." -ForegroundColor DarkGray
        Write-Host "    Registry/protocol/app rows are compensating controls you can reverse from Recovery > 7." -ForegroundColor DarkGray
        Write-Host "    No exploit payloads. Personal PC you administer only." -ForegroundColor DarkGray
        Write-Host ""
        if ($last) {
            Write-Host "  Last scan" -ForegroundColor Cyan
            foreach ($r in $last) {
                $col = switch ($r.Status) {
                    "Healthy" { "Green" }
                    "Exposed" { "Red" }
                    "Compensating" { "Yellow" }
                    default { "DarkGray" }
                }
                Write-Host ("    {0,-22} {1,-12} {2}" -f $r.Id, $r.Status, $r.Detail) -ForegroundColor $col
            }
            Write-Host ""
        }
        Write-Host "  1  Scan this PC (read-only, live status)" -ForegroundColor Green
        Write-Host "  2  Remediate Exposed items (confirm; restore point first)" -ForegroundColor Yellow
        Write-Host "  3  Remediate one item by number from the last scan" -ForegroundColor Yellow
        Write-Host "  4  Show honesty notes for the catalog" -ForegroundColor White
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3","4")
        switch ($c) {
            "0" { return }
            "1" {
                Write-Host ""
                Write-Host "  Scanning..." -ForegroundColor Cyan
                $last = @(Invoke-BastionCveScan)
                $ex = @($last | Where-Object { $_.Status -eq "Exposed" }).Count
                Write-Host ""
                Write-Host ("  Scan complete. Exposed: {0} of {1}." -f $ex, $last.Count) -ForegroundColor $(if ($ex -gt 0) { "Yellow" } else { "Green" })
                Wait-ForKey "Press any key to return to CVE checks..."
            }
            "2" {
                if (-not $last) {
                    Write-Host "  Run a scan first (option 1)." -ForegroundColor Yellow
                    Wait-ForKey "Press any key..."
                    continue
                }
                $need = @($last | Where-Object { $_.Status -eq "Exposed" })
                if ($need.Count -eq 0) {
                    Write-Status "Nothing in Exposed state." "Already"
                    Wait-ForKey "Press any key..."
                    continue
                }
                Write-Host "  Create a System Restore Point (main menu 13 / R) before a batch when you can." -ForegroundColor Yellow
                Write-Host ("  About to remediate {0} Exposed item(s)." -f $need.Count) -ForegroundColor Yellow
                if ((Read-YesNo -Prompt "  Continue with remediations (Y/N)?") -ne "Y") { continue }
                $cat = Get-BastionCveCatalog
                $entries = @($need | ForEach-Object { $id = $_.Id; $cat | Where-Object { $_.Id -eq $id } | Select-Object -First 1 })
                Invoke-BastionCveRemediateBatch -Entries $entries -NoConfirm
                Write-Host "  Re-scan recommended." -ForegroundColor DarkGray
                Wait-ForKey "Press any key..."
            }
            "3" {
                if (-not $last) {
                    Write-Host "  Run a scan first (option 1)." -ForegroundColor Yellow
                    Wait-ForKey "Press any key..."
                    continue
                }
                for ($i = 0; $i -lt $last.Count; $i++) {
                    Write-Host ("    {0,2}. {1}  [{2}]" -f ($i + 1), $last[$i].Title, $last[$i].Status)
                }
                $valid = @("0") + (1..$last.Count | ForEach-Object { "$_" })
                $pick = Read-MenuChoice -Prompt "  Item (0 cancel)" -Valid $valid
                if ($pick -eq "0") { continue }
                $row = $last[[int]$pick - 1]
                if ((Read-YesNo -Prompt ("  Remediate {0} (Y/N)?" -f $row.Title)) -ne "Y") { continue }
                $entry = Get-BastionCveCatalog | Where-Object { $_.Id -eq $row.Id } | Select-Object -First 1
                Invoke-BastionCveRemediateBatch -Entries @($entry) -NoConfirm
                Wait-ForKey "Press any key..."
            }
            "4" {
                Clear-BastionScreen
                Write-Header "CVE CATALOG NOTES"
                foreach ($e in Get-BastionCveCatalog) {
                    Write-Host ("  {0}  ({1})" -f $e.Title, ($e.Cves -join ", ")) -ForegroundColor White
                    Write-Host ("    {0}" -f $e.Honesty) -ForegroundColor DarkGray
                    Write-Host ""
                }
                Wait-ForKey "Press any key..."
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Show-CveRecoveryMenu
#   Recovery hub 7. Revert Bastion-applied CVE remediations only.
# -----------------------------------------------------------------------------
function Show-CveRecoveryMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header "CVE CHECKS RECOVERY"
        Write-AppliesWhen -Mode Now -Extra "This reverses registry/protocol changes Bastion recorded in Bastion-CveUndo.json. It cannot uninstall a Windows Update or reinstall VLC."
        $u = Get-BastionCveUndo
        Write-Host "  Live status" -ForegroundColor Cyan
        if ($u) {
            Write-Host ("    Undo file: {0} ({1} item(s))" -f $u.Timestamp, @($u.Items).Count) -ForegroundColor White
        } else {
            Write-Host "    Undo file: none (no Bastion CVE remediations recorded)" -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-Host "  1  Scan now (read-only)" -ForegroundColor Green
        Write-Host "  2  Revert Bastion CVE remediations (registry/protocol)" -ForegroundColor Yellow
        Write-Host "  3  Open the full CVE checks menu (same as main C)" -ForegroundColor White
        Write-Host "  0  Back" -ForegroundColor DarkGray
        Write-Host ""
        $c = Read-MenuChoice -Prompt "  Select" -Valid @("0","1","2","3")
        switch ($c) {
            "0" { return }
            "1" {
                [void](Invoke-BastionCveScan)
                Wait-ForKey "Press any key..."
            }
            "2" {
                if ((Read-YesNo -Prompt "  Restore recorded CVE registry/protocol values (Y/N)?") -eq "Y") {
                    Invoke-BastionCveRevertAll
                }
                Wait-ForKey "Press any key..."
            }
            "3" { Show-CveChecksMenu }
        }
    }
}
