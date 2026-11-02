#Requires -RunAsAdministrator
# Points every active network adapter's DNS at AdHush (127.0.0.1 / ::1). Safe to run repeatedly
# (the AdHush service re-runs it every few minutes so newly connected adapters are covered):
# adapters already pointing at AdHush are left alone, and each adapter's previous DNS servers are
# added to the backup the first time it is switched, so restore-system-dns.ps1 can undo exactly this.
param([string]$DataDir = "$env:ProgramData\AdHush")

$ErrorActionPreference = 'Stop'
$ours = @('127.0.0.1', '::1')
New-Item -ItemType Directory -Force $DataDir | Out-Null
$backupFile = Join-Path $DataDir 'dns-backup.json'

$backup = @()
if (Test-Path $backupFile) { $backup = @(Get-Content -Raw $backupFile | ConvertFrom-Json) }

$adapters = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and -not $_.Virtual })
if (-not $adapters) { Write-Host 'No active physical network adapters.'; exit 0 }

$changed = 0
foreach ($a in $adapters) {
    $v4 = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
    $v6 = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses)
    if ($v4.Count -eq 1 -and $v4[0] -eq '127.0.0.1') { continue }   # already ours
    if (-not ($backup | Where-Object { $_.InterfaceIndex -eq $a.ifIndex })) {
        $backup += [pscustomobject]@{
            InterfaceIndex = $a.ifIndex
            Name           = $a.Name
            IPv4           = @($v4 | Where-Object { $_ -notin $ours })
            IPv6           = @($v6 | Where-Object { $_ -notin $ours })
        }
        # Save the backup before switching, so a restore is always possible.
        ConvertTo-Json -InputObject @($backup) -Depth 4 | Set-Content -Encoding utf8 $backupFile
    }
    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $ours
    Write-Host "  $($a.Name): DNS -> 127.0.0.1, ::1"
    $changed++
}

if ($changed) { Clear-DnsClientCache }
Write-Host "changed $changed adapter(s)"
