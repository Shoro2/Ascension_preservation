# run-world-server.ps1 -- stop any old archive world server, then start one in this window.
# The login shim on 3799 must ALSO be running in its own window. Stays open; Ctrl-C to stop.
#
# UNELEVATED, same user as the client: the server passively ReadProcessMemory's the
# client's own 40-byte world SessionKey, and an elevated server cannot read an
# unelevated client.  The client launches with __COMPAT_LAYER=RunAsInvoker for exactly
# this reason.
#
# It selects the old listener by COMMAND LINE, not by port.  Selecting by port was safe
# only while the archive owned 8085; it now runs on 8087 and 8085 belongs to whichever
# AzerothCore realm is being played, so a port-based kill would have force-killed a live
# worldserver -- no character save -- the first time both stacks were up together.
$py = 'python'   # must be on PATH (Python 3.x); or set to your python.exe
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like '*world_server.py*' } |
    ForEach-Object {
        Write-Host ("stopping old archive world server (PID {0})..." -f $_.ProcessId) -ForegroundColor Yellow
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
Start-Sleep -Milliseconds 400
Set-Location 'C:\AzerothRealm\realms\ascension'
Write-Host 'starting MINIMAL WORLD SERVER on 127.0.0.1:8087 ...' -ForegroundColor Green
& $py world_server.py
