# Removes every AdHush root certificate from the current user's (and, if admin, the machine's) trusted roots.
$ErrorActionPreference = 'Continue'
foreach ($store in 'Cert:\CurrentUser\Root', 'Cert:\LocalMachine\Root') {
    Get-ChildItem $store | Where-Object Subject -like 'CN=AdHush Personal CA*' | ForEach-Object {
        try {
            Remove-Item $_.PSPath -ErrorAction Stop
            Write-Host "Removed $($_.Thumbprint) from $store"
        } catch {
            Write-Warning "Could not remove $($_.Thumbprint) from $store (run as administrator for the machine store)."
        }
    }
}
