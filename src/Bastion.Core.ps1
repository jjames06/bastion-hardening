# Bastion.Core.ps1 - modular domain (v15.9.0)
# Dot-sourced by Bastion-Hardening.ps1 into the same runspace ($script: scope).
# Plain text GPLv3 source - never encrypt. Do not run standalone.

function Write-Log {
    param(
        [string]$Message,
        [string]$Color = "White",
        [ValidateSet("Information","Warning","Error")][string]$Level = "Information",
        [switch]$NoConsole
    )
    $line = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Message
    if (-not $NoConsole) {
        try { Write-Host $line -ForegroundColor $Color } catch { try { Write-Host $line } catch {} }
    }
    [void](Ensure-BastionPaths)
    try { Add-Content -LiteralPath $script:logFile -Value $line -ErrorAction SilentlyContinue } catch {}
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:Config.EventSource)) {
            New-EventLog -LogName Application -Source $script:Config.EventSource -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName Application -Source $script:Config.EventSource -EventId 1000 -EntryType $Level -Message ("Bastion: {0}" -f $Message) -ErrorAction SilentlyContinue
    } catch {}
}

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Already","Applied","Failed","Info","Skip","Warn")][string]$Type = "Info"
    )
    # Console once here; Write-Log uses -NoConsole to avoid duplicate lines
    switch ($Type) {
        "Already" {
            Write-Host ("    {0}" -f $Message) -ForegroundColor DarkGray
            if ($null -ne $script:Stats) { $script:Stats.AlreadyConfigured++ }
            Write-Log $Message -Color DarkGray -NoConsole
        }
        "Applied" {
            Write-Host ("    {0}" -f $Message) -ForegroundColor Green
            if ($null -ne $script:Stats) { $script:Stats.Applied++ }
            Write-Log $Message -Color Green -NoConsole
        }
        "Failed"  {
            Write-Host ("    {0}" -f $Message) -ForegroundColor Red
            if ($null -ne $script:Stats) { $script:Stats.Failed++ }
            if ($null -ne $script:ApplyFailures) { [void]$script:ApplyFailures.Add($Message) }
            Write-Log $Message -Color Red -Level Error -NoConsole
        }
        "Warn" {
            Write-Host ("    {0}" -f $Message) -ForegroundColor Yellow
            Write-Log $Message -Color Yellow -Level Warning -NoConsole
        }
        "Skip" {
            Write-Host ("    {0}" -f $Message) -ForegroundColor DarkYellow
            Write-Log $Message -Color DarkYellow -NoConsole
        }
        default {
            Write-Host ("    {0}" -f $Message) -ForegroundColor White
            Write-Log $Message -NoConsole
        }
    }
}

function Wait-ForKey([string]$Message = "Press any key to return...") {
    Write-Host ""
    Write-Host ("  {0}" -f $Message) -ForegroundColor Gray
    try { [void][System.Console]::ReadKey($true) } catch { [void](Read-Host "  Press Enter") }
}

function Write-Banner {
    # External Bastion-Banner.utf8.txt (UTF-8) next to script if present; else ASCII fallback
    Write-Host ""
    $bannerFile = $null
    try {
        if ($PSScriptRoot) { $bannerFile = Join-Path $PSScriptRoot "Bastion-Banner.utf8.txt" }
        if (-not $bannerFile -or -not (Test-Path -LiteralPath $bannerFile)) {
            if ($MyInvocation.MyCommand.Path) {
                $bannerFile = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "Bastion-Banner.utf8.txt"
            }
        }
    } catch { $bannerFile = $null }

    $usedUnicode = $false
    if ($bannerFile -and (Test-Path -LiteralPath $bannerFile)) {
        try {
            $lines = Get-Content -LiteralPath $bannerFile -Encoding UTF8 -ErrorAction Stop
            Write-Host "  ================================================================" -ForegroundColor DarkCyan
            foreach ($line in $lines) {
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    Write-Host $line -ForegroundColor Cyan
                }
            }
            $usedUnicode = $true
        } catch { $usedUnicode = $false }
    }

    if (-not $usedUnicode) {
        $logo = @(
            '      ____    _    ____ _____ ___ ___  _   _',
            '     | __ )  / \  / ___|_   _|_ _/ _ \| \ | |',
            '     |  _ \ / _ \ \___ \ | |  | | | | |  \| |',
            '     | |_) / ___ \ ___) || |  | | |_| | |\  |',
            '     |____/_/   \_\____/ |_| |___\___/|_| \_|'
        )
        Write-Host "  ================================================================" -ForegroundColor DarkCyan
        foreach ($line in $logo) { Write-Host $line -ForegroundColor Cyan }
    }

    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    # Fixed-width frame: "  " + 64x'=' = 66 columns. Inner body width 62 between edges.
    $boxInner = 62
    function Write-BastionBoxLine {
        param([string]$Text, [string]$Color = "White", [string]$Edge = "|")
        $body = if ($null -eq $Text) { "" } else { [string]$Text }
        if ($body.Length -gt $boxInner) { $body = $body.Substring(0, $boxInner) }
        $body = $body.PadRight($boxInner)
        Write-Host ("  {0}{1}{0}" -f $Edge, $body) -ForegroundColor $Color
    }
    $ver = [string]$script:Config.ScriptVersion
    Write-BastionBoxLine ("  WINDOWS HARDENING FRAMEWORK          v{0} FINAL" -f $ver) "White" "|"
    Write-BastionBoxLine "  Selective  /  State-aware  /  Safety-first" "DarkGray" "|"
    Write-BastionBoxLine ("  {0}" -f (Get-Date -Format "yyyy-MM-dd  HH:mm")) "DarkGray" "|"
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-BastionBoxLine "  Create a System Restore Point before Apply / BloatApps." "Yellow" "!"
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host ""
}

function Get-BastionConsoleWidth {
    try {
        $w = [int]$Host.UI.RawUI.WindowSize.Width
        if ($w -lt 50) { return 78 }
        # Leave a small margin so wrap does not touch the border
        return [Math]::Min(120, [Math]::Max(60, $w - 2))
    } catch {
        return 78
    }
}

function Get-BastionConsoleHeight {
    try {
        $h = [int]$Host.UI.RawUI.WindowSize.Height
        if ($h -lt 16) { return 30 }
        return $h
    } catch {
        return 30
    }
}

function Clear-BastionScreen {
    # Clear visible buffer and pin cursor to top so the user always starts at the header
    try { Clear-Host } catch {}
    try {
        $ui = $Host.UI.RawUI
        $origin = New-Object System.Management.Automation.Host.Coordinates 0, 0
        $ui.CursorPosition = $origin
    } catch {}
}

function Maximize-BastionConsole {
    # Maximize host window for readability. Not exclusive Alt+Enter fullscreen.
    # Fails softly in ISE, some Windows Terminal profiles, remoting, or constrained hosts.
    try {
        if (-not ("BastionNative.ConsoleWin" -as [type])) {
            Add-Type -Namespace BastionNative -Name ConsoleWin -MemberDefinition @"
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
"@ -ErrorAction Stop
        }
        $hwnd = [BastionNative.ConsoleWin]::GetConsoleWindow()
        if ($hwnd -ne [IntPtr]::Zero) {
            # SW_MAXIMIZE = 3
            [void][BastionNative.ConsoleWin]::ShowWindow($hwnd, 3)
        }
    } catch { }

    try {
        $ui = $Host.UI.RawUI
        $max = $ui.MaxPhysicalWindowSize
        if ($max -and $max.Width -ge 40 -and $max.Height -ge 15) {
            $bufW = [Math]::Max([int]$ui.BufferSize.Width, [int]$max.Width)
            $bufH = [Math]::Max([int]$ui.BufferSize.Height, 3000)
            try {
                $ui.BufferSize = New-Object System.Management.Automation.Host.Size $bufW, $bufH
            } catch { }
            try {
                $ui.WindowSize = New-Object System.Management.Automation.Host.Size ([int]$max.Width, [int]$max.Height)
            } catch { }
        }
    } catch { }
}

function Get-WrappedLines {
    param(
        [string]$Text,
        [int]$Indent = 2,
        [int]$Width = 0
    )
    if ($null -eq $Text) { $Text = "" }
    if ($Width -le 0) { $Width = Get-BastionConsoleWidth }
    $pad = " " * [Math]::Max(0, $Indent)
    $maxBody = [Math]::Max(24, $Width - $Indent)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @("") }
    $words = @($Text.Trim() -split '\s+' | Where-Object { $_ })
    if ($words.Count -eq 0) { return @("") }
    $lines = New-Object System.Collections.Generic.List[string]
    $line = $pad + $words[0]
    for ($i = 1; $i -lt $words.Count; $i++) {
        $w = $words[$i]
        if ($w.Length -gt $maxBody) {
            if ($line.Trim().Length -gt 0) { [void]$lines.Add($line); $line = $pad }
            $chunk = $w
            while ($chunk.Length -gt $maxBody) {
                [void]$lines.Add($pad + $chunk.Substring(0, $maxBody))
                $chunk = $chunk.Substring($maxBody)
            }
            $line = $pad + $chunk
            continue
        }
        if (($line.Length + 1 + $w.Length) -le $Width) {
            $line = $line + " " + $w
        } else {
            [void]$lines.Add($line)
            $line = $pad + $w
        }
    }
    if ($line.Length -gt 0) { [void]$lines.Add($line) }
    return @($lines)
}

function Write-Wrapped {
    param(
        [string]$Text,
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::White,
        [int]$Indent = 2,
        [int]$Width = 0
    )
    if ($null -eq $Text) { $Text = "" }
    if ($Width -le 0) { $Width = Get-BastionConsoleWidth }
    $pad = " " * [Math]::Max(0, $Indent)
    $maxBody = [Math]::Max(24, $Width - $Indent)
    if ($Text.Trim().Length -eq 0) {
        Write-Host ""
        return
    }
    # Preserve leading marker spaces in original by trimming only for word split content
    $words = @($Text.Trim() -split '\s+' | Where-Object { $_ -and $_.Length -gt 0 })
    if ($words.Count -eq 0) {
        Write-Host ""
        return
    }
    $line = $pad + $words[0]
    for ($i = 1; $i -lt $words.Count; $i++) {
        $w = $words[$i]
        # Hard-break very long tokens (paths/URLs) so they never blow the width
        if ($w.Length -gt $maxBody) {
            if ($line.Trim().Length -gt 0) {
                Write-Host $line -ForegroundColor $ForegroundColor
                $line = $pad
            }
            $chunk = $w
            while ($chunk.Length -gt $maxBody) {
                Write-Host ($pad + $chunk.Substring(0, $maxBody)) -ForegroundColor $ForegroundColor
                $chunk = $chunk.Substring($maxBody)
            }
            $line = $pad + $chunk
            continue
        }
        if (($line.Length + 1 + $w.Length) -le $Width) {
            $line = $line + " " + $w
        } else {
            Write-Host $line -ForegroundColor $ForegroundColor
            $line = $pad + $w
        }
    }
    if ($line.Length -gt 0) {
        Write-Host $line -ForegroundColor $ForegroundColor
    }
}

function Write-WrappedBlock {
    param(
        [string]$Label,
        [string]$Body,
        [ConsoleColor]$LabelColor = [ConsoleColor]::Cyan,
        [ConsoleColor]$BodyColor = [ConsoleColor]::Gray
    )
    if ([string]::IsNullOrWhiteSpace($Body)) { return }
    Write-Host ("  {0}" -f $Label) -ForegroundColor $LabelColor
    Write-Wrapped -Text $Body -Indent 4 -ForegroundColor $BodyColor
}

function Write-Header([string]$Title) {
    Write-Host ""
    Write-Host "  ==============================================================" -ForegroundColor DarkCyan
    Write-Host ("  {0}" -f $Title.ToUpper()) -ForegroundColor Cyan
    Write-Host ("  Bastion v{0} | {1}" -f $script:Config.ScriptVersion, (Get-Date -Format "yyyy-MM-dd HH:mm")) -ForegroundColor DarkGray
    Write-Host "  ==============================================================" -ForegroundColor DarkCyan
}

function Write-MenuGroup([string]$Label) {
    Write-Host ""
    Write-Host ("  -- {0} --" -f $Label) -ForegroundColor DarkCyan
}

function Write-UxDivider {
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
}

function Write-AppliesWhen {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Now", "MainMenu8", "PreferenceOrApply")]
        [string]$Mode,
        [string]$Extra = ""
    )
    switch ($Mode) {
        "Now" {
            Write-Host "  Takes effect: NOW from this menu (no main menu 8 needed)." -ForegroundColor Green
        }
        "MainMenu8" {
            Write-Host "  Takes effect: after main menu 8 (Apply Hardening)." -ForegroundColor Yellow
        }
        "PreferenceOrApply" {
            Write-Host "  Preference: saved immediately." -ForegroundColor Cyan
            Write-Host "  Windows DNS: only after Apply - press A here, or main menu 8 (DNS section on)." -ForegroundColor Yellow
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($Extra)) {
        Write-Host ("  {0}" -f $Extra) -ForegroundColor DarkGray
    }
}

function Write-UxBullets {
    param(
        [string[]]$Items,
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::White,
        [string]$Bullet = "-"
    )
    foreach ($item in @($Items)) {
        if ([string]::IsNullOrWhiteSpace($item)) { continue }
        Write-Host ("    {0} {1}" -f $Bullet, $item) -ForegroundColor $ForegroundColor
    }
}

function Read-YesNo([string]$Prompt) {
    $tries = 0
    while ($true) {
        $tries++
        if ($tries -gt 12) {
            Write-Host "  Too many invalid inputs; defaulting to N." -ForegroundColor Red
            return "N"
        }
        try {
            $raw = Read-Host $Prompt
            $a = if ($null -eq $raw) { "" } else { ([string]$raw).Trim() }
        } catch {
            Write-Host "  Input error. Enter Y or N." -ForegroundColor Red
            continue
        }
        if ($a -match '^[Yy]$') { return "Y" }
        if ($a -match '^[Nn]$') { return "N" }
        Write-Host "  Invalid input. Enter Y or N only." -ForegroundColor Red
    }
}

function Read-ConfirmYes([string]$Prompt = "  Type YES to proceed") {
    $tries = 0
    while ($true) {
        $tries++
        if ($tries -gt 12) {
            Write-Host "  Too many invalid inputs; cancelling." -ForegroundColor Red
            return $false
        }
        try {
            $raw = Read-Host $Prompt
            $a = if ($null -eq $raw) { "" } else { ([string]$raw).Trim() }
        } catch {
            Write-Host "  Input error. Type YES to confirm, or NO to cancel." -ForegroundColor Red
            continue
        }
        if ($a -eq "YES") { return $true }
        if ($a -eq "NO" -or $a -match '^[Nn]$') { return $false }
        Write-Host "  Invalid input. Type YES (all caps) to confirm, or NO to cancel." -ForegroundColor Red
    }
}

function Read-MenuChoice {
    param([string]$Prompt = "  Select", [string[]]$Valid)
    if (-not $Valid -or @($Valid).Count -eq 0) {
        Write-Host "  Internal error: no valid choices configured." -ForegroundColor Red
        return "0"
    }
    $tries = 0
    while ($true) {
        $tries++
        if ($tries -gt 20) {
            Write-Host "  Too many invalid inputs; returning cancel (0) if available." -ForegroundColor Red
            foreach ($v in $Valid) {
                if ([string]$v -eq "0") { return "0" }
            }
            return [string]$Valid[0]
        }
        try {
            $raw = Read-Host $Prompt
        } catch {
            Write-Host ("  Input error. Choose one of: {0}" -f ($Valid -join ", ")) -ForegroundColor Red
            continue
        }
        if ($null -eq $raw -or [string]::IsNullOrWhiteSpace([string]$raw)) {
            Write-Host ("  Empty input. Choose one of: {0}" -f ($Valid -join ", ")) -ForegroundColor Red
            continue
        }
        $n = ([string]$raw).Trim()
        if ($n.Length -gt 32) {
            Write-Host "  Invalid input (too long)." -ForegroundColor Red
            continue
        }
        $hasControl = $false
        foreach ($ch in $n.ToCharArray()) {
            if ([int][char]$ch -lt 32) { $hasControl = $true; break }
        }
        if ($hasControl) {
            Write-Host "  Invalid input (control characters not allowed)." -ForegroundColor Red
            continue
        }
        foreach ($v in $Valid) {
            if ($n -eq [string]$v -or $n.ToUpperInvariant() -eq ([string]$v).ToUpperInvariant()) {
                return [string]$v
            }
        }
        Write-Host ("  Invalid choice '{0}'. Allowed: {1}" -f $n, ($Valid -join ", ")) -ForegroundColor Red
    }
}

function Open-UrlSafe([string]$Url) {
    if ([string]::IsNullOrWhiteSpace($Url)) {
        Write-Host "  No URL to open." -ForegroundColor Yellow
        return
    }
    try {
        Start-Process $Url -ErrorAction Stop | Out-Null
    } catch {
        Write-Host ("  Could not open browser: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        Write-Host ("  Open manually: {0}" -f $Url) -ForegroundColor Cyan
    }
}
