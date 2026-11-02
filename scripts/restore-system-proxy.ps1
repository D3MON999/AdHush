# Restores the proxy settings saved by set-system-proxy.ps1 (or turns the proxy off if there is no backup).
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$backup = Join-Path $env:LOCALAPPDATA 'AdHush\proxy-backup.json'

if (Test-Path $backup) {
    $b = Get-Content -Raw $backup | ConvertFrom-Json
    Set-ItemProperty $key ProxyEnable ([int]($b.ProxyEnable -as [int]))
    foreach ($name in 'ProxyServer', 'ProxyOverride', 'AutoConfigURL') {
        if ($b.$name) { Set-ItemProperty $key $name $b.$name } else { Remove-ItemProperty $key $name -ErrorAction SilentlyContinue }
    }
    Remove-Item $backup
} else {
    Set-ItemProperty $key ProxyEnable 0
}

Add-Type -Namespace AdHush -Name WinInet -MemberDefinition '[DllImport("wininet.dll")] public static extern bool InternetSetOption(System.IntPtr h, int o, System.IntPtr b, int l);'
[AdHush.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
[AdHush.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
Write-Host 'System proxy restored.'
