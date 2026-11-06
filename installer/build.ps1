# Builds every component, stages the install tree in installer\stage and, if Inno Setup 6 is
# installed, compiles installer\output\AdHushSetup-<version>.exe.
#   powershell -ExecutionPolicy Bypass -File installer\build.ps1 [-SkipBuild] [-FeedUrl <url>] [-Notes <text>]
# -FeedUrl: where installed copies look for updates, e.g.
#   https://github.com/<you>/<repo>/releases/latest/download/latest.json
# When keys\update-signing.pem exists, output\latest.json(.sig) are signed for upload next to the setup.
param([switch]$SkipBuild, [string]$FeedUrl = '', [string]$Notes = '')

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$stage = Join-Path $PSScriptRoot 'stage'
$version = (Get-Content -Raw (Join-Path $root 'package.json') | ConvertFrom-Json).version

if (-not $SkipBuild) {
    & node (Join-Path $root 'scripts\make-icons.mjs')
    foreach ($crate in 'core', 'tray', 'service') {
        Write-Host "building $crate"
        Push-Location (Join-Path $root $crate)
        & cargo build --release
        if ($LASTEXITCODE) { Pop-Location; throw "cargo build failed in $crate" }
        Pop-Location
    }
}

if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
$dirs = 'app', 'node', 'bin', 'host', 'extension', 'scripts', 'installer', 'licenses'
foreach ($d in $dirs) { New-Item -ItemType Directory -Force (Join-Path $stage $d) | Out-Null }

# Node service (source, UI, package.json); no node_modules: there are no dependencies.
Copy-Item -Recurse (Join-Path $root 'src'), (Join-Path $root 'ui') (Join-Path $stage 'app')
Copy-Item (Join-Path $root 'package.json') (Join-Path $stage 'app')

# Node runtime from this machine (MIT; its LICENSE ships alongside).
$nodeExe = (Get-Command node).Source
Copy-Item $nodeExe (Join-Path $stage 'node\node.exe')
$nodeLicense = Join-Path (Split-Path $nodeExe) 'LICENSE'
if (Test-Path $nodeLicense) { Copy-Item $nodeLicense (Join-Path $stage 'licenses\node-LICENSE.txt') }

# Rust binaries
$rel = Join-Path $root 'core\target\release'
Copy-Item (Join-Path $rel 'adhush-core.exe'), (Join-Path $rel 'WinDivert.dll'), (Join-Path $rel 'WinDivert64.sys'), (Join-Path $rel 'resources.json') (Join-Path $stage 'bin')
Copy-Item (Join-Path $root 'core\vendor\windivert\LICENSE') (Join-Path $stage 'licenses\WinDivert-LICENSE.txt')
# AdHush's own licence and the third-party notices (regenerate with: node scripts\notices.mjs).
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $stage 'LICENSE.txt')
Copy-Item (Join-Path $root 'THIRD-PARTY-NOTICES.md') (Join-Path $stage 'licenses\THIRD-PARTY-NOTICES.md')
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $stage 'licenses\uBlock-Origin-resources-GPL-3.0.txt')
Copy-Item (Join-Path $root 'tray\target\release\adhush-tray.exe') $stage
Copy-Item (Join-Path $root 'service\target\release\adhush-service.exe') $stage

# Browser extension + native host
Copy-Item (Join-Path $root 'host\host.mjs'), (Join-Path $root 'host\adhush-host.cmd') (Join-Path $stage 'host')
Copy-Item -Recurse (Join-Path $root 'extension\*') (Join-Path $stage 'extension')

# Setup helpers
Copy-Item (Join-Path $root 'scripts\set-system-dns.ps1'), (Join-Path $root 'scripts\restore-system-dns.ps1'), (Join-Path $root 'scripts\restore-internet.ps1'), (Join-Path $root 'scripts\restore-internet.cmd') (Join-Path $stage 'scripts')
Copy-Item (Join-Path $PSScriptRoot 'configure.mjs'), (Join-Path $PSScriptRoot 'post-install.ps1'), (Join-Path $PSScriptRoot 'pre-uninstall.ps1'), (Join-Path $PSScriptRoot 'stop-windivert.ps1'), (Join-Path $PSScriptRoot 'restore-windows.mjs') (Join-Path $stage 'installer')
# Remember the feed between builds so a plain rebuild keeps updates working.
$feedFile = Join-Path $PSScriptRoot 'update-feed.txt'
if ($FeedUrl) { Set-Content -NoNewline -Encoding ascii $feedFile $FeedUrl }
if (Test-Path $feedFile) {
    Copy-Item $feedFile (Join-Path $stage 'installer')
    Write-Host "update feed: $(Get-Content -Raw $feedFile)"
} else {
    Write-Warning 'no update feed set (-FeedUrl): installed copies will not update automatically.'
}

$size = (Get-ChildItem -Recurse -File $stage | Measure-Object Length -Sum).Sum / 1MB
Write-Host ("staged {0:N1} MB in {1}" -f $size, $stage)

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    Write-Warning 'Inno Setup 6 not found: staged only. Install it (winget install JRSoftware.InnoSetup) and re-run with -SkipBuild.'
    return
}
$env:ADHUSH_VERSION = $version
& $iscc (Join-Path $PSScriptRoot 'adhush.iss')
if ($LASTEXITCODE) { throw 'ISCC failed' }
$setupExe = Join-Path $PSScriptRoot "output\AdHushSetup-$version.exe"

# Source archive for the release (GPL-3.0: offer the source next to the binaries). Built from an
# explicit exclusion list, so the signing key, local data and build output can never be in it.
$exclude = '\\(keys|data|target|node_modules|\.claude|\.git)(\\|$)|\\installer\\(stage|output)(\\|$)|\.(pem|key|pfx|p12|log)$|\\api-token$|\\update-feed\.txt$'
$srcZip = Join-Path $PSScriptRoot "output\AdHush-$version-source.zip"
$files = Get-ChildItem $root -Recurse -File -Force | Where-Object { $_.FullName.Substring($root.Length) -notmatch $exclude }
if (Test-Path $srcZip) { Remove-Item $srcZip }
# .NET directly: Compress-Archive in Windows PowerShell writes '\' in entry names, which other unzip tools mangle.
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::Open($srcZip, 'Create')
try {
    foreach ($f in $files) {
        $entry = "AdHush-$version/" + $f.FullName.Substring($root.Length + 1).Replace('\', '/')
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $entry, 'Optimal')
    }
} finally { $zip.Dispose() }
Write-Host ("source archive: {0} files, {1:N1} MB" -f $files.Count, ((Get-Item $srcZip).Length / 1MB))
if (Test-Path (Join-Path $root 'keys\update-signing.pem')) {
    & node (Join-Path $root 'scripts\release.mjs') sign --setup $setupExe --notes $Notes
    if ($LASTEXITCODE) { throw 'signing failed' }
} else {
    Write-Warning 'keys\update-signing.pem missing: latest.json not signed (run: node scripts\release.mjs keygen)'
}
Get-ChildItem (Join-Path $PSScriptRoot 'output') | Select-Object Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } }
