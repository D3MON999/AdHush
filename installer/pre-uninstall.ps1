# Run by the uninstaller as administrator before files are removed. Puts Windows back the way
# it was: DNS, trusted certificates, service, browser host registration.
param([string]$AppDir = (Split-Path $PSScriptRoot -Parent))

$ErrorActionPreference = 'Continue'
$data = Join-Path $env:ProgramData 'AdHush'

# DNS first: once the service stops, a PC still pointed at 127.0.0.1 has no name resolution.
if (Test-Path (Join-Path $data 'dns-backup.json')) {
    & (Join-Path $AppDir 'scripts\restore-system-dns.ps1') -DataDir $data
}

Get-Process adhush-tray -ErrorAction SilentlyContinue | Stop-Process -Force
if (Get-Service AdHush -ErrorAction SilentlyContinue) {
    Stop-Service AdHush -Force -ErrorAction SilentlyContinue
    & sc.exe delete AdHush | Out-Null
}
Get-Process adhush-core -ErrorAction SilentlyContinue | Stop-Process -Force

$thumbFile = Join-Path $data 'ca\installed-thumbprint'
if (Test-Path $thumbFile) {
    $thumb = (Get-Content -Raw $thumbFile).Trim()
    Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $thumb | Remove-Item
}

& netsh advfirewall firewall delete rule name='AdHush transparent proxy' | Out-Null

foreach ($k in 'HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.adhush.host',
               'HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.adhush.host',
               'HKLM:\SOFTWARE\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.adhush.host') {
    if (Test-Path $k) { Remove-Item $k -Force }
}
