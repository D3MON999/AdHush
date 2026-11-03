# Unloads and unregisters AdHush's WinDivert kernel driver so bin\WinDivert64.sys can be
# replaced (upgrade) or deleted (uninstall). Windows keeps the driver loaded after adhush-core
# exits, which locks the file. Other programs ship their own WinDivert under the same service
# name, so only a driver loaded from an AdHush folder is touched. adhush-core reinstalls the
# driver automatically the next time it starts.
$ErrorActionPreference = 'Continue'
$drv = Get-CimInstance Win32_SystemDriver -Filter "Name='WinDivert'" -ErrorAction SilentlyContinue
if (-not $drv -or $drv.PathName -notlike '*\AdHush\bin\WinDivert64.sys') { return }
& sc.exe stop WinDivert | Out-Null
& sc.exe delete WinDivert | Out-Null
for ($i = 0; $i -lt 40; $i++) {
    $d = Get-CimInstance Win32_SystemDriver -Filter "Name='WinDivert'" -ErrorAction SilentlyContinue
    if (-not $d -or $d.State -ne 'Running') { break }
    Start-Sleep -Milliseconds 250
}
