# =============================================================================
# publish-wiki.ps1
# =============================================================================
# Publish docs/wiki Markdown pages to the GitHub Wiki remote (*.wiki.git).
#
# Prerequisite:
#   - Wiki enabled on the GitHub repository settings
#   - Wiki has been created at least once in the web UI
#     (GitHub creates owner/repo.wiki.git only after the first page exists)
#   - Network access and credentials that can push to that remote
#
# Usage (from repo root):
#   powershell -File tools/publish-wiki.ps1
#
# Flow:
#   1) Resolve repo root (parent of tools\)
#   2) Fresh clone of the wiki remote into %TEMP%
#   3) Overwrite the known handbook page set from docs\wiki\
#   4) Commit and push only when the working tree has changes
# =============================================================================

$ErrorActionPreference = "Stop"

# tools\ -> repo root (two parents from this script path).
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not (Test-Path (Join-Path $root "docs\wiki\Home.md"))) {
    throw "docs/wiki/Home.md not found. Run from bastion-hardening repo."
}

# Disposable clone directory; wipe any prior publish attempt for a clean tree.
$wikiDir = Join-Path $env:TEMP "bastion-hardening.wiki-publish"
if (Test-Path $wikiDir) { Remove-Item $wikiDir -Recurse -Force }

$remote = "https://github.com/jjames06/bastion-hardening.wiki.git"
try {
    git clone $remote $wikiDir
} catch {
    # First-time wiki remote is often missing until a page is saved in the UI.
    throw @"
Could not clone the wiki remote.
Open https://github.com/jjames06/bastion-hardening/wiki and click Create the first page
(title: Home, any short body), Save once. Then re-run this script.
"@
}

# Keep this list in sync with docs/wiki sources you want on the public wiki.
$pages = @(
    "Home.md", "Quick-start.md", "Hardening-workflow.md",
    "Recovery-cookbook.md", "Games-and-StrictHandle.md", "FAQ.md",
    "Modular-source.md", "_Sidebar.md", "_Footer.md"
)
foreach ($p in $pages) {
    Copy-Item (Join-Path $root "docs\wiki\$p") (Join-Path $wikiDir $p) -Force
}

Push-Location $wikiDir
try {
    # Local identity for this temp clone only (does not change global git config).
    # Avoids "Author identity unknown" on machines without user.name/email set.
    git config user.email "Info@operationlockedin.com"
    git config user.name "Operation Locked In"

    git add $pages
    git status
    if (git status --porcelain) {
        # Only commit/push when handbook content actually changed.
        git commit -m "Sync handbook from docs/wiki"
        git push
        Write-Host "Wiki published: https://github.com/jjames06/bastion-hardening/wiki"
    } else {
        Write-Host "Wiki already up to date."
    }
} finally {
    Pop-Location
}
