# Copies the audited source archive of the current version (made by build.ps1) into the local
# clone that GitHub Desktop publishes from. The clone mirrors the archive exactly: new and changed
# files are copied, files deleted from AdHush are deleted there, and git's own .git folder is left
# alone. Because it copies from the archive, the signing key and local data can never reach GitHub.
#   powershell -ExecutionPolicy Bypass -File installer\publish-source.ps1 [-Repo C:\dev\adhush-upload\AdHush]
param([string]$Repo = 'C:\dev\adhush-upload\AdHush')

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$version = (Get-Content -Raw (Join-Path $root 'package.json') | ConvertFrom-Json).version
$zip = Join-Path $PSScriptRoot "output\AdHush-$version-source.zip"
if (-not (Test-Path $zip)) { throw "No $zip. Run installer\build.ps1 first." }
if (-not (Test-Path (Join-Path $Repo '.git'))) { throw "$Repo is not a git clone. Clone D3MON999/AdHush there with GitHub Desktop first." }

$tmp = Join-Path $env:TEMP "adhush-publish-$version"
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
Expand-Archive $zip $tmp
$src = Join-Path $tmp "AdHush-$version"
$leak = Get-ChildItem $src -Recurse -Force -File | Where-Object { $_.Name -match '\.(pem|key|pfx|p12)$|^api-token$' -or $_.FullName -match '\\keys\\' }
if ($leak) { throw "refusing to publish: secret-looking files in the archive: $($leak.FullName -join ', ')" }

# /MIR mirrors (including deletions); /XD .git keeps the repository's history untouched.
robocopy $src $Repo /MIR /XD .git /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }
Remove-Item -Recurse -Force $tmp
Write-Host "Source for $version copied to $Repo. In GitHub Desktop: write a summary (e.g. 'AdHush $version'), Commit to main, Push origin."
