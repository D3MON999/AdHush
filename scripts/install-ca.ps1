# Trusts the AdHush root certificate for the current user (Windows shows a confirmation dialog).
# Use -Machine (as administrator) to trust it for all users and services.
param(
    [string]$DataDir = $(if (Test-Path "$env:ProgramData\AdHush\ca") { "$env:ProgramData\AdHush" } else { Join-Path (Split-Path $PSScriptRoot -Parent) 'data' }),
    [switch]$Machine
)
$ErrorActionPreference = 'Stop'
$pem = Join-Path $DataDir 'ca\adhush-ca.pem'
if (-not (Test-Path $pem)) { throw "No certificate at $pem. Enable Web filtering in AdHush first so it creates one." }

$cer = Join-Path $env:TEMP 'adhush-ca.cer'
Copy-Item $pem $cer -Force
$store = if ($Machine) { 'Cert:\LocalMachine\Root' } else { 'Cert:\CurrentUser\Root' }
$cert = Import-Certificate -FilePath $cer -CertStoreLocation $store
Remove-Item $cer
Write-Host "Trusted '$($cert.Subject)' (thumbprint $($cert.Thumbprint)) in $store"
