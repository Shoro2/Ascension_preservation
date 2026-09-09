<#
    restart-world-mode.ps1 -Mode <full|none|spec|known|budget>

    Restart the archive world server DETACHED with ARCHIVE_CA_MODE set, so the
    Character Advancement block can be bisected against the in-world crash
    without editing world_server.py between runs.  See TROUBLESHOOTING.md,
    "ERROR #132 ... (3) Intermittent crash once already in the world".

    UNELEVATED, same user as the client -- the server RPM-reads the client's
    session key and an elevated server cannot read an unelevated client.

    Selects the old listener by COMMAND LINE, never by port: 8085 now belongs to
    whichever AzerothCore realm is being played, and a port-based kill would
    force-kill a live worldserver with no character save.
#>
param(
    [ValidateSet('full', 'none', 'spec', 'known', 'budget')]
    [string]$Mode = 'full'
)

$ErrorActionPreference = 'Stop'
$py  = 'python'   # must be on PATH (Python 3.x); or set to your python.exe
$dir = 'C:\AzerothRealm\realms\ascension'

Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like '*world_server.py*' } |
    ForEach-Object {
        Write-Host ("stopping old archive world server (PID {0})..." -f $_.ProcessId) -ForegroundColor Yellow
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
Start-Sleep -Milliseconds 400

# The child inherits this; it is not set for the whole session.
$env:ARCHIVE_CA_MODE = $Mode
$p = Start-Process -FilePath $py -ArgumentList 'world_server.py' -WorkingDirectory $dir `
        -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput "$dir\world_server_stdout.txt" `
        -RedirectStandardError  "$dir\world_server_stderr.txt"
Remove-Item Env:\ARCHIVE_CA_MODE

Write-Host ("started archive world server PID {0}, ARCHIVE_CA_MODE={1}" -f $p.Id, $Mode) -ForegroundColor Green

# Fail loudly rather than leave the caller waiting on a listener that never came up.
$deadline = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $deadline) {
    $c = Get-NetTCPConnection -State Listen -LocalPort 8095 -ErrorAction SilentlyContinue
    if ($c) { Write-Host 'listening on 127.0.0.1:8095' -ForegroundColor Green; exit 0 }
    Start-Sleep -Milliseconds 300
}
Write-Host 'FAILED: nothing is listening on 8095 after 15s' -ForegroundColor Red
Get-Content "$dir\world_server_stderr.txt" -Tail 20 -ErrorAction SilentlyContinue
exit 1
