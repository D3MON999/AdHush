# Points the current user's Windows proxy (used by Edge, Chrome and most apps) at AdHush.
# The previous settings are saved so restore-system-proxy.ps1 can undo this. No admin needed.
param([int]$Port = 8080)
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$backup = Join-Path $env:LOCALAPPDATA 'AdHush\proxy-backup.json'
New-Item -ItemType Directory -Force (Split-Path $backup) | Out-Null

if (-not (Test-Path $backup)) {
    $p = Get-ItemProperty $key
    [pscustomobject]@{ ProxyEnable = $p.ProxyEnable; ProxyServer = $p.ProxyServer; ProxyOverride = $p.ProxyOverride; AutoConfigURL = $p.AutoConfigURL } |
        ConvertTo-Json | Set-Content -Encoding utf8 $backup
    Write-Host "Saved current proxy settings to $backup"
}

Set-ItemProperty $key ProxyEnable 1
Set-ItemProperty $key ProxyServer "127.0.0.1:$Port"
Set-ItemProperty $key ProxyOverride '<local>;localhost;127.*;10.*;192.168.*;172.16.*;*.local'
Remove-ItemProperty $key AutoConfigURL -ErrorAction SilentlyContinue

# Tell running applications that the settings changed.
Add-Type -Namespace AdHush -Name WinInet -MemberDefinition '[DllImport("wininet.dll")] public static extern bool InternetSetOption(System.IntPtr h, int o, System.IntPtr b, int l);'
[AdHush.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null  # SETTINGS_CHANGED
[AdHush.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null  # REFRESH
Write-Host "System proxy set to 127.0.0.1:$Port"
