#Requires -RunAsAdministrator
# Runs AdHush at boot as SYSTEM (a scheduled task acts as the Windows service; no extra software needed).
# Restarts automatically if it crashes.
param([string]$DataDir = "$env:ProgramData\AdHush")

$ErrorActionPreference = 'Stop'
$node = (Get-Command node -ErrorAction Stop).Source
$entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'src\index.js'
New-Item -ItemType Directory -Force $DataDir | Out-Null

$action = New-ScheduledTaskAction -Execute $node -Argument "`"$entry`" --data `"$DataDir`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName 'AdHush' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'AdHush'
Write-Host "AdHush registered and started. Data: $DataDir"
Write-Host 'UI: http://127.0.0.1:8899/'
