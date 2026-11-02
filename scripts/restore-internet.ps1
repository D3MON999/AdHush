#Requires -RunAsAdministrator
# "Restore normal internet": the manual emergency switch (Start menu, tray menu).
# Turns off whole-PC protection so the AdHush service stops pointing Windows at itself, then puts
# every adapter's previous DNS servers back. Turn protection on again in AdHush > Settings.
param([string]$DataDir = "$env:ProgramData\AdHush")

$ErrorActionPreference = 'Continue'
$settingsFile = Join-Path $DataDir 'settings.json'
$tokenFile = Join-Path $DataDir 'api-token'

# Prefer the running service (it owns settings.json); edit the file only if it is not answering.
$viaApi = $false
if (Test-Path $tokenFile) {
    try {
        $port = 8899
        if (Test-Path $settingsFile) { $s = Get-Content -Raw $settingsFile | ConvertFrom-Json; if ($s.api.port) { $port = $s.api.port } }
        Invoke-RestMethod -Method Patch -Uri "http://127.0.0.1:$port/api/settings" -TimeoutSec 5 `
            -Headers @{ 'x-adhush-token' = (Get-Content -Raw $tokenFile).Trim() } -ContentType 'application/json' `
            -Body '{"system":{"manageDns":false}}' | Out-Null
        $viaApi = $true
    } catch {}
}
if (-not $viaApi -and (Test-Path $settingsFile)) {
    $s = Get-Content -Raw $settingsFile | ConvertFrom-Json
    if (-not $s.system) { $s | Add-Member -NotePropertyName system -NotePropertyValue ([pscustomobject]@{}) }
    $s.system | Add-Member -NotePropertyName manageDns -NotePropertyValue $false -Force
    # No byte-order mark: AdHush's JSON parser would reject it.
    [IO.File]::WriteAllText($settingsFile, ($s | ConvertTo-Json -Depth 20), (New-Object Text.UTF8Encoding($false)))
}

& (Join-Path $PSScriptRoot 'restore-system-dns.ps1') -DataDir $DataDir
Write-Host ''
Write-Host 'Normal internet restored. AdHush whole-PC protection is now off; turn it back on in AdHush > Settings.'
