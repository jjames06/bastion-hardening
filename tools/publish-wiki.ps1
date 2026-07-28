# Publish docs/wiki to the GitHub Wiki remote.
# Prerequisite: Wiki enabled on the repo, and the wiki has been created at least once
# (GitHub creates owner/repo.wiki.git only after the first page exists in the web UI).
# Usage (from repo root, with network + credentials):
#   powershell -File tools/publish-wiki.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not (Test-Path (Join-Path $root "docs\wiki\Home.md"))) {
    throw "docs/wiki/Home.md not found. Run from bastion-hardening repo."
}

$wikiDir = Join-Path $env:TEMP "bastion-hardening.wiki-publish"
if (Test-Path $wikiDir) { Remove-Item $wikiDir -Recurse -Force }

$remote = "https://github.com/jjames06/bastion-hardening.wiki.git"
try {
    git clone $remote $wikiDir
} catch {
    throw @"
Could not clone the wiki remote.
Open https://github.com/jjames06/bastion-hardening/wiki and click Create the first page
(title: Home, any short body), Save once. Then re-run this script.
"@
}

$pages = @(
    "Home.md", "Quick-start.md", "Recovery-cookbook.md",
    "Games-and-StrictHandle.md", "FAQ.md", "_Sidebar.md", "_Footer.md"
)
foreach ($p in $pages) {
    Copy-Item (Join-Path $root "docs\wiki\$p") (Join-Path $wikiDir $p) -Force
}

Push-Location $wikiDir
git add $pages
git status
if (git status --porcelain) {
    git commit -m "Sync handbook from docs/wiki"
    git push
    Write-Host "Wiki published: https://github.com/jjames06/bastion-hardening/wiki"
} else {
    Write-Host "Wiki already up to date."
}
Pop-Location
