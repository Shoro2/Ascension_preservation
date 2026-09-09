<#
  reboot-world.ps1 -- restart world_server.py and drive the client back into the world.

  Iterating on the world server costs a client relog every time, and doing that by hand
  (kill, start, ENTER, ENTER, ENTER, check the log) is both slow and easy to get wrong in
  a way that looks like a code bug.  This does the whole cycle and FAILS LOUDLY if the
  client did not actually reach the world, so a red result means "relog failed", never
  "your change is broken".

  Usage:
      .\tools\reboot-world.ps1 -ProcId <clientpid>
      .\tools\reboot-world.ps1 -ProcId <clientpid> -NoRestart     # just relog
      .\tools\reboot-world.ps1 -ProcId <clientpid> -TailLines 40  # more log on success

  Notes:
   * UNELEVATED, same user as the client.  The shim and world server RPM-read the
     client's session key, so an elevated server cannot read an unelevated client.
     Elevation is permitted for other things (handoff section 8) -- not for this.
   * Glue screens are keyboard-navigable: ENTER dismisses the disconnect popup, ENTER
     logs in, ENTER enters the world.  We cannot ghost-CLICK; WoW polls the real cursor.
   * The shim on 3799 is left alone -- it survives a world restart fine.

  READING THE LOG.  Do not reach for Get-Content -Raw here.  This log runs to tens of
  megabytes, so slurping the whole thing once per poll made the wait itself slow; worse,
  the file offset we record is in BYTES while a decoded string is indexed in CHARACTERS,
  and a single multi-byte character anywhere in 140 MB makes the string shorter than the
  offset -- which threw "startIndex cannot be larger than length of string" and lost a
  perfectly good relog.  Read-New-Bytes seeks and reads only what is new, and treats a
  file that has SHRUNK as a rotation and starts from zero.
#>
param(
  [Parameter(Mandatory = $true)][int]$ProcId,
  [switch]$NoRestart,
  [int]$TailLines = 12
)
$ErrorActionPreference = 'Stop'

$Base   = 'C:\AzerothRealm\realms\ascension'
$LogPath = Join-Path $Base 'world_server_log.txt'
$Ghost  = Join-Path $Base 'tools\ghostinput.ps1'
$Python = 'python'   # must be on PATH (Python 3.x); or set to your python.exe

function Get-LogLength {
  if (Test-Path $LogPath) { (Get-Item $LogPath).Length } else { 0 }
}

function Read-NewBytes([long]$From) {
  if (-not (Test-Path $LogPath)) { return '' }
  $fs = [System.IO.File]::Open($LogPath, 'Open', 'Read', 'ReadWrite')
  try {
    # A shorter file than when we started means world_server rotated it; everything
    # in the new file is ours.
    $start = if ($fs.Length -lt $From) { 0 } else { $From }
    [void]$fs.Seek($start, 'Begin')
    $buf = New-Object byte[] ($fs.Length - $start)
    $n = $fs.Read($buf, 0, $buf.Length)
    return [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
  } finally { $fs.Dispose() }
}

if (-not (Get-Process -Id $ProcId -ErrorAction SilentlyContinue)) {
  throw "No process $ProcId -- is the client still running?"
}

# Everything already in the log is history; only bytes after this marker are ours.
$startLen = Get-LogLength

if (-not $NoRestart) {
  $old = Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like '*world_server.py*' }
  foreach ($p in $old) {
    Write-Output "kill world_server PID $($p.ProcessId)"
    Stop-Process -Id $p.ProcessId -Force
  }
  Start-Sleep -Milliseconds 700
  $new = Start-Process -FilePath $Python -ArgumentList 'world_server.py' `
    -WorkingDirectory $Base -PassThru -WindowStyle Hidden
  Start-Sleep -Seconds 2
  if ($new.HasExited) {
    Write-Output "--- world_server died on startup, tail: ---"
    Get-Content $LogPath -Tail 25
    throw "world_server.py exited immediately (exit $($new.ExitCode)) -- syntax error?"
  }
  Write-Output "world_server PID $($new.Id)"
}

# ENTER x3: dismiss "disconnected", log in, enter world.  Generous waits -- the char
# list has to round-trip before the third one means anything.
foreach ($wait in 1.2, 4.5, 2.0) {
  & $Ghost -ProcId $ProcId -Action key -Text ENTER | Out-Null
  Start-Sleep -Seconds $wait
}

# Wait for the world-entry burst rather than guessing at a sleep.
$deadline = (Get-Date).AddSeconds(25)
$entered = $false
while ((Get-Date) -lt $deadline) {
  if ((Read-NewBytes $startLen) -match 'WORLD-ENTRY burst sent') { $entered = $true; break }
  Start-Sleep -Milliseconds 800
}

$tail = Read-NewBytes $startLen
if (-not $entered) {
  Write-Output "--- log since restart (last 60 lines) ---"
  ($tail -split "`r?`n" | Select-Object -Last 60) -join "`n"
  throw "Client did not reach the world within 25s. Screenshot it: ghostinput.ps1 -Action shot"
}

Write-Output "OK: client is in the world."
$tail -split "`r?`n" | Where-Object { $_ -match 'WORLD-ENTRY|CHAR-SELECT|bars:|ERROR|Traceback' } |
  Select-Object -Last $TailLines
