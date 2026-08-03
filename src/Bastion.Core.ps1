# =============================================================================
# Bastion.Core.ps1 - console UX primitives, logging, and input helpers
# =============================================================================
#
# PURPOSE
#   Shared presentation and logging layer used by menus, Apply, Recovery, and
#   domain modules. No hardening mutations live here; this module only writes
#   to console, log file, and optional Application event log.
#
# LOAD ORDER / ROLE
#   Loaded second (after Bastion.Init.ps1) so $script:Config, Stats, and paths
#   exist. Dot-sourced by Bastion-Hardening.ps1 into the same runspace.
#   Later modules call Write-Log / Write-Status / menu helpers freely.
#
# DO NOT
#   - Run this file standalone (depends on Init state and Config path helpers).
#   - Encrypt or obfuscate this source (GPLv3; open for audit).
#   - Treat logging as a security boundary; logs are plain text on disk.
#
# SECURITY NOTES
#   - Source is plain text. MANIFEST.sha256 integrity only.
#   - DPAPI is never used here; undo encryption lives in Bastion.Config.ps1.
#   - Write-Log may create the Event Log source when elevated; failures are soft.
#   - Open-UrlSafe only starts a process for the given URL string; callers must
#     pass fixed product URLs, not untrusted free text.
#
# ELEVATION
#   Expected to run elevated after the bat/bootstrap admin gate. Console theme
#   and maximize soft-fail on constrained hosts (ISE, remoting, locked tokens).
# =============================================================================

# -----------------------------------------------------------------------------
# Logging and status lines
# -----------------------------------------------------------------------------

function Write-Log {
    <#
    .SYNOPSIS
      Append a timestamped line to the Bastion log file and optionally the console
      and Windows Application event log.
    .DESCRIPTION
      WHAT: Formats [HH:mm:ss] Message, writes Host unless -NoConsole, ensures
            data paths, appends to $script:logFile, and best-effort Write-EventLog.
      WHY: Single channel so Apply/menus do not diverge between console and file.
      SIDE EFFECTS: May create Event Log source BastionHardening; may call
            Ensure-BastionPaths (creates dirs). Event log failures are silent.
      RETURN: None (void). Does not throw to callers.
    #>
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
    <#
    .SYNOPSIS
      Emit a colored status line for Dry Run / Apply steps and update $script:Stats.
    .DESCRIPTION
      WHAT: Prints an indented message by Type (Already/Applied/Failed/Info/Skip/Warn)
            and mirrors to Write-Log with -NoConsole to avoid duplicate console lines.
      WHY: Consistent step accounting and color language across all hardening sections.
      SIDE EFFECTS: Increments Stats counters; Failed also appends to ApplyFailures.
      RETURN: None.
    #>
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
    <#
    .SYNOPSIS
      Pause until the user presses a key (or Enter as fallback).
    .DESCRIPTION
      WHAT: Shows a gray prompt then ReadKey, falling back to Read-Host.
      WHY: Menus and fatal paths need a pause so double-click consoles do not flash-close.
      RETURN: None. Does not exit the process.
    #>
    Write-Host ""
    Write-Host ("  {0}" -f $Message) -ForegroundColor Gray
    try { [void][System.Console]::ReadKey($true) } catch { [void](Read-Host "  Press Enter") }
}

# -----------------------------------------------------------------------------
# Banner and console chrome
# -----------------------------------------------------------------------------

function Write-Banner {
    <#
    .SYNOPSIS
      Draw the product banner, version frame, and restore-point reminder.
    .DESCRIPTION
      WHAT: Loads Bastion-Banner.utf8.txt from product root when present; else
            prints a fixed ASCII logo. Then draws a fixed-width info box.
      WHY: Consistent branding and a hard-to-miss System Restore reminder before Apply.
      SIDE EFFECTS: Console output only. Nested helper Write-BastionBoxLine is local.
      PATHS: Prefers $script:BastionRoot; if Core is under src\, parent is product root.
    #>
    # External Bastion-Banner.utf8.txt (UTF-8) next to product root (not src\). Prefer $script:BastionRoot.
    Write-Host ""
    $bannerFile = $null
    try {
        $root = $null
        if ($script:BastionRoot) { $root = [string]$script:BastionRoot }
        if (-not $root -and $PSScriptRoot) {
            # When Core is under src\, parent of PSScriptRoot is product root
            $leaf = Split-Path -Leaf $PSScriptRoot
            if ($leaf -ieq "src") { $root = Split-Path -Parent $PSScriptRoot } else { $root = $PSScriptRoot }
        }
        if ($root) { $bannerFile = Join-Path $root "Bastion-Banner.utf8.txt" }
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
    <#
    .SYNOPSIS
      Safe console width for word-wrap (clamped 60-120, default 78).
    .DESCRIPTION
      WHAT: Reads Host.UI.RawUI.WindowSize.Width with margin and floors.
      WHY: Menus/help wrap cleanly without touching the window border.
      RETURN: [int] column count.
    #>
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
    <#
    .SYNOPSIS
      Safe console height for layout hints (minimum 16, default 30).
    .RETURN
      [int] row count from host or 30 on failure.
    #>
    try {
        $h = [int]$Host.UI.RawUI.WindowSize.Height
        if ($h -lt 16) { return 30 }
        return $h
    } catch {
        return 30
    }
}

function Set-BastionConsoleTheme {
    <#
    .SYNOPSIS
      Force black background / gray foreground and repaint the buffer.
    .DESCRIPTION
      WHAT: Sets RawUI colors and fills the visible buffer with black cells.
      WHY: Classic conhost and many Terminal profiles flash host-default blue;
           menus look inconsistent without a dark theme.
      SIDE EFFECTS: Soft-fail on ISE / remoting / locked hosts (returns $false).
      RETURN: $true if theme applied enough to continue; $false on hard failure.
    #>
    # Consistent dark UI for almost all hosts (classic conhost + many Terminal profiles).
    # Soft-fail: ISE / remoting / locked hosts keep their own theme.
    try {
        $ui = $Host.UI.RawUI
        if (-not $ui) { return $false }
        try { $ui.BackgroundColor = [ConsoleColor]::Black } catch {}
        try { $ui.ForegroundColor = [ConsoleColor]::Gray } catch {}
        # Paint the whole buffer so leftover host blue/white does not flash through.
        try {
            $buf = $ui.BufferSize
            if ($buf -and $buf.Width -gt 0 -and $buf.Height -gt 0) {
                $origin = New-Object System.Management.Automation.Host.Coordinates 0, 0
                $rect = New-Object System.Management.Automation.Host.Rectangle 0, 0, ($buf.Width - 1), ($buf.Height - 1)
                $cell = New-Object System.Management.Automation.Host.BufferCell
                $cell.Character = ' '
                $cell.ForegroundColor = [ConsoleColor]::Gray
                $cell.BackgroundColor = [ConsoleColor]::Black
                $cell.BufferCellType = [System.Management.Automation.Host.BufferCellType]::Complete
                $ui.SetBufferContents($rect, $cell)
                $ui.CursorPosition = $origin
            }
        } catch {
            try { Clear-Host } catch {}
        }
        return $true
    } catch {
        return $false
    }
}

function Clear-BastionScreen {
    <#
    .SYNOPSIS
      Re-apply dark theme, Clear-Host, and home the cursor.
    .DESCRIPTION
      WHAT: Theme then clear so host-default blue does not reappear between menus.
      WHY: Every major menu entry should look the same after redraw.
      RETURN: None. Soft-fail per step.
    #>
    # Re-apply dark theme then clear so menus stay black (not host-default blue).
    try { [void](Set-BastionConsoleTheme) } catch {}
    try { Clear-Host } catch {}
    try {
        $ui = $Host.UI.RawUI
        $origin = New-Object System.Management.Automation.Host.Coordinates 0, 0
        $ui.CursorPosition = $origin
    } catch {}
}

function Maximize-BastionConsole {
    <#
    .SYNOPSIS
      Dark theme, maximize the console window, grow buffer for scrollback.
    .DESCRIPTION
      WHAT: P/Invoke ShowWindow(SW_MAXIMIZE=3), expand BufferSize/WindowSize,
            re-paint theme after resize.
      WHY: Help text and Dry Run need a readable full-screen width when allowed.
      SIDE EFFECTS: Soft-fail entirely on constrained hosts; never throws to caller.
      ELEVATION: Works best in a real elevated conhost; not required for function to return.
    #>
    # Dark theme first, then maximize for readability. Soft-fail on constrained hosts.
    try { [void](Set-BastionConsoleTheme) } catch {}

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
        # Re-paint after resize so new buffer cells are black too.
        try { [void](Set-BastionConsoleTheme) } catch {}
    } catch { }
}

# -----------------------------------------------------------------------------
# Text wrapping helpers
# -----------------------------------------------------------------------------

function Get-WrappedLines {
    <#
    .SYNOPSIS
      Word-wrap text into an array of indented lines without printing.
    .DESCRIPTION
      WHAT: Splits on whitespace, hard-breaks overlong tokens (paths/URLs).
      WHY: Callers that need line counts or custom emission (not Write-Host).
      RETURN: [string[]] of wrapped lines (may include empty string for blank input).
    #>
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
    <#
    .SYNOPSIS
      Word-wrap and Write-Host a paragraph with indent and color.
    .DESCRIPTION
      WHAT: Same wrap rules as Get-WrappedLines but emits each line immediately.
      WHY: Help body text and long status notes on variable-width consoles.
      RETURN: None.
    #>
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
    <#
    .SYNOPSIS
      Print a label line then a wrapped body (help section pattern).
    .DESCRIPTION
      WHAT: Skips empty bodies. Label at indent 2, body at indent 4.
      WHY: SectionDocs-style Intent/Changes/Impact blocks stay scannable.
      RETURN: None.
    #>
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

# -----------------------------------------------------------------------------
# Menu chrome and "when does this take effect" cues
# -----------------------------------------------------------------------------

function Write-Header([string]$Title) {
    <#
    .SYNOPSIS
      Standard menu header bar with title, version, and timestamp.
    .RETURN
      None. Console output only.
    #>
    Write-Host ""
    Write-Host "  ==============================================================" -ForegroundColor DarkCyan
    Write-Host ("  {0}" -f $Title.ToUpper()) -ForegroundColor Cyan
    Write-Host ("  Bastion v{0} | {1}" -f $script:Config.ScriptVersion, (Get-Date -Format "yyyy-MM-dd HH:mm")) -ForegroundColor DarkGray
    Write-Host "  ==============================================================" -ForegroundColor DarkCyan
}

function Write-MenuGroup([string]$Label) {
    <#
    .SYNOPSIS
      Small subsection label inside a menu (e.g. "-- Network --").
    #>
    Write-Host ""
    Write-Host ("  -- {0} --" -f $Label) -ForegroundColor DarkCyan
}

function Write-UxDivider {
    <#
    .SYNOPSIS
      Horizontal dashed rule for visual separation in menus.
    #>
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
}

function Write-AppliesWhen {
    <#
    .SYNOPSIS
      Tell the user whether a menu action is live now or needs main menu Apply.
    .DESCRIPTION
      WHAT: Prints standardized "Takes effect" lines for Now / MainMenu8 /
            PreferenceOrApply modes, plus optional Extra gray note.
      WHY: DNS and section toggles confused users when preference alone did not
            change Windows; this cue is intentional product UX.
      RETURN: None.
    #>
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
    <#
    .SYNOPSIS
      Print a simple indented bullet list.
    .DESCRIPTION
      WHAT: Skips blank items. Bullet character defaults to "-".
      RETURN: None.
    #>
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

# -----------------------------------------------------------------------------
# Validated interactive input
# -----------------------------------------------------------------------------

function Read-YesNo([string]$Prompt) {
    <#
    .SYNOPSIS
      Read Y/N only; after too many bad inputs default to N.
    .DESCRIPTION
      WHAT: Loop until Y/y or N/n; max 12 tries then returns "N".
      WHY: Prevents stuck menus on garbage input; fail-safe is cancel (N).
      RETURN: "Y" or "N" (uppercase strings).
    #>
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
    <#
    .SYNOPSIS
      Require exact YES (all caps) for destructive confirms; NO or N cancels.
    .DESCRIPTION
      WHAT: After 12 invalid tries returns $false (cancel).
      WHY: Apply / BloatApps / Undo paths need intentional confirmation.
      RETURN: $true only for YES; $false for NO/N or give-up.
    #>
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
    <#
    .SYNOPSIS
      Read a menu selection constrained to an explicit Valid set.
    .DESCRIPTION
      WHAT: Trims input, rejects empty/long/control chars, case-insensitive match
            against Valid. After 20 failures returns "0" if present else Valid[0].
      WHY: Stops garbage keys from falling through into unintended branches.
      RETURN: Matched string from Valid (original casing of the Valid entry).
    #>
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
    <#
    .SYNOPSIS
      Open a URL in the default browser/handler, with a manual fallback line.
    .DESCRIPTION
      WHAT: Start-Process on the URL string; on failure print the URL in cyan.
      WHY: Help links and manual install pages without crashing the menu loop.
      SECURITY: Callers must pass fixed product URLs only (not user-controlled).
      RETURN: None.
    #>
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
