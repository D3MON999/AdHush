#Requires -RunAsAdministrator
# Undoes set-system-dns.ps1: every adapter that still points at AdHush gets its previous DNS
# servers back (or automatic/DHCP DNS if it had none). Adapters someone changed by hand since
# are left alone.
param([string]$DataDir = "$env:ProgramData\AdHush")

$ErrorActionPreference = 'Stop'
$ours = @('127.0.0.1', '::1')
$backupFile = Join-Path $DataDir 'dns-backup.json'
$backup = @()
if (Test-Path $backupFile) { $backup = @(Get-Content -Raw $backupFile | ConvertFrom-Json) }

function Test-PointsAtAdHush($ifIndex) {
    $v4 = @((Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
    return [bool]($v4 | Where-Object { $_ -in $ours })
}

$restored = @{}
foreach ($b in $backup) {
    if (-not (Get-NetAdapter -InterfaceIndex $b.InterfaceIndex -ErrorAction SilentlyContinue)) { continue }
    if (-not (Test-PointsAtAdHush $b.InterfaceIndex)) { continue }
    $servers = @(@($b.IPv4) + @($b.IPv6) | Where-Object { $_ -and $_ -notin $ours })
    if ($servers) {
        Set-DnsClientServerAddress -InterfaceIndex $b.InterfaceIndex -ServerAddresses $servers -ErrorAction Continue
        Write-Host "  $($b.Name): DNS -> $($servers -join ', ')"
    } else {
        Set-DnsClientServerAddress -InterfaceIndex $b.InterfaceIndex -ResetServerAddresses -ErrorAction Continue
        Write-Host "  $($b.Name): DNS -> automatic (DHCP)"
    }
    $restored[[int]$b.InterfaceIndex] = $true
}

# An adapter still pointing at AdHush without a backup entry goes back to automatic DNS.
foreach ($a in Get-NetAdapter | Where-Object Status -eq 'Up') {
    if ($restored[[int]$a.ifIndex] -or -not (Test-PointsAtAdHush $a.ifIndex)) { continue }
    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction Continue
    Write-Host "  $($a.Name): DNS -> automatic (DHCP)"
}

if (Test-Path $backupFile) { Remove-Item $backupFile }
Clear-DnsClientCache
Write-Host 'System DNS restored.'
