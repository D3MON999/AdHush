# Registers the AdHush native messaging host for the current user in Chrome, Edge and Brave,
# so the AdHush Assistant extension can talk to the service. Undo with -Uninstall.
# (The setup installer registers it machine-wide instead; this script is for development.)
param([switch]$Uninstall)

$ErrorActionPreference = 'Stop'
$name = 'com.adhush.host'
$extensionId = 'ffcidpjioddohnenfclgdineaimihlmd'
$hostDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'host'
$manifest = Join-Path $hostDir "$name.json"
$keys = @(
  "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$name",
  "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$name",
  "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\$name"
)

if ($Uninstall) {
  foreach ($k in $keys) { if (Test-Path $k) { Remove-Item $k -Force; Write-Host "removed $k" } }
  if (Test-Path $manifest) { Remove-Item $manifest -Force }
  return
}

@{
  name = $name
  description = 'AdHush ad blocker'
  path = (Join-Path $hostDir 'adhush-host.cmd')
  type = 'stdio'
  allowed_origins = @("chrome-extension://$extensionId/")
} | ConvertTo-Json | Out-File -Encoding ascii $manifest

foreach ($k in $keys) {
  New-Item -Path $k -Force | Out-Null
  Set-Item -Path $k -Value $manifest
  Write-Host "registered $k"
}
Write-Host "Load the extension unpacked from $(Join-Path (Split-Path $PSScriptRoot -Parent) 'extension') (developer mode). Its ID will be $extensionId."
