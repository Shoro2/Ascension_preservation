# restart-shim.ps1 -- stop any shim listening on 3799, then start the UPDATED shim
# (serves the real 42-record Ascension realm list with every address localized to the
# archive world server -- see archive_ports.py; it is 127.0.0.1:8087, NOT 8085, which
# belongs to the hub's AzerothCore realms).
# Run ELEVATED (the shim reads the client's per-session key via ReadProcessMemory, which needs
# equal integrity to the client). Stays open so you can watch output and Ctrl-C later.
$py = 'python'   # must be on PATH (Python 3.x); or set to your python.exe
Get-NetTCPConnection -LocalPort 3799 -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host ("stopping old shim (PID {0})..." -f $_.OwningProcess)
    Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 400
Set-Location 'C:\AzerothRealm\realms\ascension'
Write-Host 'starting updated shim -- real localized realm list...' -ForegroundColor Green
& $py shim3799.py
