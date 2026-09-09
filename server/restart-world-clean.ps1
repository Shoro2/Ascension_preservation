# restart-world-clean.ps1 -- kill every stray archive world server, then start exactly one.
#
# This USED to find its victims with `Get-NetTCPConnection -LocalPort 8085` and
# Stop-Process -Force them.  That was safe only while the archive owned 8085 alone.
# It no longer does: 8085 is AzerothCore's default WorldServerPort, so once a real
# realm is up (the progression realm, SpellDraft, either of them being PLAYED), the
# old script's first act would have been to force-kill a live worldserver -- no
# CTRL_BREAK, no World::StopNow, no character save.  It would have looked like a
# crash and cost whatever had not been flushed.
#
# So: never select by port.  Select by command line, the way tools/reboot-world.ps1
# already does.  Only a python.exe running world_server.py is ours, and no realm
# binary can ever match that.
$log = 'C:\AzerothRealm\realms\ascension\restart-world-clean.log'
"[$(Get-Date -Format HH:mm:ss)] clean restart begin" | Out-File -FilePath $log -Encoding utf8

$mine = Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like '*world_server.py*' }
foreach ($p in $mine) {
    try {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
        "[$(Get-Date -Format HH:mm:ss)] killed PID $($p.ProcessId) (world_server.py)" | Add-Content $log
    } catch {
        "[$(Get-Date -Format HH:mm:ss)] could not kill PID $($p.ProcessId) : $_" | Add-Content $log
    }
}
Start-Sleep -Seconds 1

# Report -- never kill -- whoever holds our port, so a genuine clash is visible
# instead of being silently resolved by shooting the wrong process.
$port = 8087
$held = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if ($held) {
    "[$(Get-Date -Format HH:mm:ss)] WARNING port $port is still held by:" | Add-Content $log
    $held | ForEach-Object {
        $o = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        "    pid=$($_.OwningProcess) ($o)" | Add-Content $log
    }
} else {
    "[$(Get-Date -Format HH:mm:ss)] port $port clear" | Add-Content $log
}

"[$(Get-Date -Format HH:mm:ss)] starting world_server.py" | Add-Content $log
Set-Location 'C:\AzerothRealm\realms\ascension'
& 'python' world_server.py   # 'python' must be on PATH (Python 3.x); or set to your python.exe
