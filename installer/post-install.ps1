# Run by setup as administrator after the files are copied. Each step logs to
# %ProgramData%\AdHush\logs\setup.log; a failed optional step never aborts the install.
param(
    [string]$AppDir = (Split-Path $PSScriptRoot -Parent),
    [switch]$Dns,
    [switch]$Web
)

$ErrorActionPreference = 'Stop'
$data = Join-Path $env:ProgramData 'AdHush'
New-Item -ItemType Directory -Force (Join-Path $data 'logs') | Out-Null
$logFile = Join-Path $data 'logs\setup.log'
function Log($msg) { "[$(Get-Date -Format s)] $msg" | Out-File -Append -Encoding utf8 $logFile }
function Step($name, [scriptblock]$body) {
    try { & $body; Log "ok: $name" } catch { Log "FAILED: $name - $($_.Exception.Message)" }
}

$node = Join-Path $AppDir 'node\node.exe'
$service = 'AdHush'

Step 'seed settings' {
    $feedFile = Join-Path $AppDir 'installer\update-feed.txt'
    $feed = if (Test-Path $feedFile) { @('--feed', (Get-Content -Raw $feedFile).Trim()) } else { @() }
    $out = & $node (Join-Path $AppDir 'installer\configure.mjs') --data $data --web $(if ($Web) { '1' } else { '0' }) --dns $(if ($Dns) { '1' } else { '0' }) @feed 2>&1
    Log ($out -join ' ')
    if ($LASTEXITCODE) { throw "configure.mjs exited $LASTEXITCODE" }
}

if ($Web) {
    Step 'create and trust this PC''s root certificate' {
        $pem = & (Join-Path $AppDir 'bin\adhush-core.exe') --data $data --init-ca
        if ($LASTEXITCODE) { throw "adhush-core --init-ca exited $LASTEXITCODE" }
        # The private key stays readable by administrators and SYSTEM only.
        & icacls (Join-Path $data 'ca') /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList ([string]$pem).Trim()
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store 'Root', 'LocalMachine'
        $store.Open('ReadWrite'); $store.Add($cert); $store.Close()
        Set-Content -Encoding ascii (Join-Path $data 'ca\installed-thumbprint') $cert.Thumbprint
        Log "trusted $($cert.Subject) $($cert.Thumbprint)"
    }
}

Step 'register service' {
    $bin = '"' + (Join-Path $AppDir 'adhush-service.exe') + '"'
    if (Get-Service $service -ErrorAction SilentlyContinue) {
        & sc.exe config $service binPath= $bin start= auto | Out-Null
    } else {
        & sc.exe create $service binPath= $bin start= auto DisplayName= 'AdHush ad blocker' | Out-Null
        if ($LASTEXITCODE) { throw "sc create exited $LASTEXITCODE" }
    }
    & sc.exe description $service 'Blocks ads, trackers and malicious websites for the whole PC.' | Out-Null
    & sc.exe failure $service reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
    Start-Service $service
}

Step 'wait for the service' {
    $deadline = (Get-Date).AddSeconds(45)
    $token = Join-Path $data 'api-token'
    do {
        Start-Sleep -Milliseconds 500
        $ready = $false
        if (Test-Path $token) {
            try {
                $r = Invoke-RestMethod -Uri 'http://127.0.0.1:8899/api/status' -Headers @{ 'x-adhush-token' = (Get-Content -Raw $token).Trim() } -TimeoutSec 3
                $ready = $r.dns.listening.Count -gt 0
            } catch {}
        }
    } until ($ready -or (Get-Date) -gt $deadline)
    if (-not $ready) { throw 'service did not start listening for DNS within 45 s' }
}

# The service's DNS guard points Windows at AdHush once it answers (within ~15 s); just report it.
if ($Dns) {
    Step 'whole-PC protection active' {
        $deadline = (Get-Date).AddSeconds(60)
        $stateFile = Join-Path $data 'dns-state.json'
        do {
            Start-Sleep -Seconds 1
            $mode = if (Test-Path $stateFile) { (Get-Content -Raw $stateFile | ConvertFrom-Json).mode } else { '' }
        } until ($mode -eq 'filtering' -or (Get-Date) -gt $deadline)
        if ($mode -ne 'filtering') { throw "DNS guard state is '$mode' after 60 s" }
    }
}

Step 'register browser extension host' {
    $hostDir = Join-Path $AppDir 'host'
    $manifest = Join-Path $hostDir 'com.adhush.host.json'
    @{
        name = 'com.adhush.host'; description = 'AdHush ad blocker'; type = 'stdio'
        path = (Join-Path $hostDir 'adhush-host.cmd')
        allowed_origins = @('chrome-extension://ffcidpjioddohnenfclgdineaimihlmd/')
    } | ConvertTo-Json | Out-File -Encoding ascii $manifest
    foreach ($k in 'HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.adhush.host',
                   'HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.adhush.host',
                   'HKLM:\SOFTWARE\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.adhush.host') {
        New-Item -Path $k -Force | Out-Null
        Set-Item -Path $k -Value $manifest
    }
}
Log 'post-install finished'
