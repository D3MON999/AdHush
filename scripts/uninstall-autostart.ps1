#Requires -RunAsAdministrator
# Stops and removes the AdHush scheduled task, then restores system DNS.
$ErrorActionPreference = 'Continue'
Stop-ScheduledTask -TaskName 'AdHush' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'AdHush' -Confirm:$false -ErrorAction SilentlyContinue
Write-Host 'AdHush task removed.'
& (Join-Path $PSScriptRoot 'restore-system-dns.ps1')
