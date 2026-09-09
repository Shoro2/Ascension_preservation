<#
    Launch the Ascension client against the local archive realm.

    The official Electron launcher is bypassed on purpose: it authenticates
    against https://api.ascension.gg/api, which is switched off with the rest
    of the service on 2026-09-04, so going through it would fail exactly when
    this archive starts to matter.  Grepping the launcher package (app.asar,
    which contains the bytenode-compiled main.jsc) for "realmlist" /
    "realmList" / "Config.wtf" returns zero hits, so it has no realm argument
    to hook either way.

    Setting the realm takes two halves, and the first one is not enough:

      1. WTF\Config.wtf.  The client reads it - realmName from it reaches the
         login screen - but it does NOT keep the realmList out of it.  Measured
         2026-08-29: with Config.wtf holding 127.0.0.1, glue Lua read the
         realmList CVar at the login screen and got 51.210.230.10 back, before
         a key was pressed.  Something native restores the official address
         after the file is parsed.  So Config.wtf alone sends every login to
         the live service, which is exactly what happened until now.

      2. Interface\GlueXML\AccountLogin.lua, a LOOSE file in the client root.
         The client prefers a loose Interface file over the copy in
         Data\patch-B.MPQ, so the archive itself is untouched and deleting the
         loose file restores stock behaviour exactly.  Glue Lua is the last
         code that runs before ConnectToServer(), so it forces the realmList
         CVar there - once when the login screen appears and again immediately
         before the connect.  This is the same mechanism Ascension's own realm
         dropdown uses (AccountLoginDropDown_OnClick calls SetCVar("realmList",
         ...) and lets the engine dial it).

    Config.wtf is still written, because realmName is what labels the login
    screen and it is honoured.

    Both halves are put back on exit, so the official launcher keeps working
    for as long as it still can.

    Note that the client's NATIVE autologin (-login/-password, the arguments
    the official launcher passes) does not go through glue Lua at all - it
    dials on its own, before AccountLogin_OnShow, and ignores the CVar.  This
    script deliberately passes no autologin arguments for that reason.

    Data\enUS\realmlist.wtf is deliberately left alone: Ascension ships it
    neutered (the literal 13 bytes "set realmlist", no value), so it cannot
    override anything, and not touching it keeps the client install closer
    to pristine.

    Config.wtf is treated as borrowed, not owned:
      * the first run copies it to Config.wtf.ascension-official and never
        overwrites that copy again - it is the record of the live service's
        realm, kept past the shutdown;
      * only the two realm lines are rewritten, so in-game video/sound/UI
        settings survive in both directions;
      * on client exit the two lines are put back from that copy, which
        leaves the official launcher working for as long as it still can.

    The client is started unelevated: Ascension.exe asks for administrator in
    its manifest, and the RunAsInvoker compat shim below declines that request
    so no UAC prompt appears.

    -Restore  puts the official realm lines back without launching anything
              (for when the client was killed rather than closed).
    -NoLaunch points Config.wtf at the local realm and stops there, for
              starting the client by hand afterwards.
#>
[CmdletBinding()]
param(
    [string]$RealmList = '127.0.0.1:3799',   # MUST include the shim's port 3799; bare 127.0.0.1 dials WoW-default 3724 and fails LOGIN_SERVER_DOWN
    # NOT cosmetic.  GetRealmName() (Ascension.exe 0x00510e00) returns this very
    # CVar, and GlueXML/CharacterCreate.lua gates the archetype creation flow on
    #     GetRealmName() == "Area 52 - Free-Pick"
    # so labelling the archive with a friendly name of its own silently switched
    # archetypes off.  The realm list served by shim3799.py advertises the same
    # string, which is also what the live client would have written here.
    [string]$RealmName = 'Area 52 - Free-Pick',
    [switch]$Restore,
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'

$client = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'client-ascension'
$exe    = Join-Path $client 'Ascension.exe'
$cfg    = Join-Path $client 'WTF\Config.wtf'
$backup = Join-Path $client 'WTF\Config.wtf.ascension-official'
$glue   = Join-Path $client 'Interface\GlueXML\AccountLogin.lua'
$log    = Join-Path $PSScriptRoot 'launch-client.log'

function Say([string]$m) {
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    Add-Content -LiteralPath $log -Value $line -Encoding utf8
}

function Get-Cvar([string]$path, [string]$name) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    foreach ($line in Get-Content -LiteralPath $path) {
        if ($line -match ('^\s*SET\s+{0}\s+"(.*)"\s*$' -f [regex]::Escape($name))) {
            return $Matches[1]
        }
    }
    return $null
}

function Set-Cvar([string]$path, [hashtable]$vars) {
    # Rewrite in place, line by line, so every unrelated setting keeps its
    # exact spelling.  A CVar the file does not have yet is appended.
    $lines = @(Get-Content -LiteralPath $path)
    $seen  = @{}
    $out = foreach ($line in $lines) {
        $hit = $null
        foreach ($k in $vars.Keys) {
            if ($line -match ('^\s*SET\s+{0}\s+' -f [regex]::Escape($k))) { $hit = $k; break }
        }
        if ($hit) { $seen[$hit] = $true; 'SET {0} "{1}"' -f $hit, $vars[$hit] }
        else      { $line }
    }
    $tail = foreach ($k in $vars.Keys) {
        if (-not $seen.ContainsKey($k)) { 'SET {0} "{1}"' -f $k, $vars[$k] }
    }
    # The client writes Config.wtf as BOM-less, LF-terminated ASCII; PowerShell's
    # Set-Content -Encoding utf8 would add a BOM and CRLFs, so write the bytes
    # directly and keep the file byte-shaped the way the client left it.
    $text = (@($out) + @($tail) | Where-Object { $null -ne $_ }) -join "`n"
    [System.IO.File]::WriteAllText($path, $text + "`n",
        (New-Object System.Text.UTF8Encoding($false)))
}

function Set-GlueRealm([string]$address) {
    # Rewrite the single ASCENSION_ARCHIVE_REALMLIST line in the loose glue
    # file.  An empty address makes AscensionArchive_ForceRealm() return
    # without touching anything, which is how the official realm is handed
    # back.  Absence of the file is not fatal - it just means the redirect is
    # not installed, so say so rather than failing the launch.
    if (-not (Test-Path -LiteralPath $glue)) {
        Say "WARNING - no loose glue at $glue; the client will use the official realm"
        return $false
    }
    $text = [System.IO.File]::ReadAllText($glue)
    $new  = [regex]::Replace($text,
        '(?m)^ASCENSION_ARCHIVE_REALMLIST\s*=\s*".*?"\s*;',
        ('ASCENSION_ARCHIVE_REALMLIST = "{0}";' -f $address))
    if ($new -eq $text) {
        # No change can mean two very different things and this used to report both
        # as the alarming one, which sent a debugging session chasing a redirect that
        # was working perfectly: either the marker line is missing (real problem) or
        # it already holds exactly this address (nothing to do). Tell them apart.
        if ($text -match '(?m)^ASCENSION_ARCHIVE_REALMLIST\s*=\s*"(.*?)"\s*;') {
            Say "glue realm already '$($Matches[1])' - left as is"
            return $true
        }
        Say "WARNING - ASCENSION_ARCHIVE_REALMLIST line not found in $glue"
        return $false
    }
    [System.IO.File]::WriteAllText($glue, $new,
        (New-Object System.Text.UTF8Encoding($false)))
    return $true
}

# One archive client at a time, and this is a hard stop rather than a warning.
# rpm_readk.read_k() scans EVERY Ascension.exe pid and keeps the first that looks
# live, so the shim and the world server can end up reading a DIFFERENT client's
# 40-byte session key than the one trying to log in. The second client then fails
# its digest and sits at "Connecting" forever, which looks exactly like a broken
# server. -Force is deliberately not offered: there is no case where two of these
# work.
if (-not $Restore -and -not $NoLaunch) {
    $live = @(Get-Process -Name 'Ascension' -ErrorAction SilentlyContinue)
    if ($live.Count -gt 0) {
        $ids = ($live | ForEach-Object { $_.Id }) -join ', '
        Say "ABORT - an archive client is already running (pid $ids)"
        Write-Warning ("An archive client is already running (pid {0}). " -f $ids +
            "Only one can hold the session key - drive that one, or close it first.")
        exit 1
    }
}

if (-not (Test-Path -LiteralPath $exe)) {
    Say "ABORT - no client at $exe"
    exit 1
}
if (-not (Test-Path -LiteralPath $cfg)) {
    Say "ABORT - no Config.wtf at $cfg"
    exit 1
}

# One-time snapshot of the official config.  Never refreshed: once the live
# service is gone this is the only surviving record of where it pointed.
if (-not (Test-Path -LiteralPath $backup)) {
    Copy-Item -LiteralPath $cfg -Destination $backup
    Say "backed up Config.wtf -> $(Split-Path $backup -Leaf)"
}

$officialList = Get-Cvar $backup 'realmList'
$officialName = Get-Cvar $backup 'realmName'
if (-not $officialList) { $officialList = '51.210.230.10' }

if ($Restore) {
    Set-Cvar $cfg @{ realmList = $officialList; realmName = $officialName }
    [void](Set-GlueRealm '')
    Say "restored official realm ($officialList)"
    exit 0
}

Set-Cvar $cfg @{ realmList = $RealmList; realmName = $RealmName }
if (Set-GlueRealm $RealmList) {
    Say "realmList -> $RealmList  (config + loose glue; official was $officialList)"
} else {
    Say "realmList -> $RealmList in config only - REDIRECT WILL NOT HOLD"
}

if ($NoLaunch) { exit 0 }

# Ascension.exe carries a manifest asking for requireAdministrator, so the
# ordinary Start-Process (which goes through ShellExecute) raises a UAC consent
# prompt every single launch.  RunAsInvoker tells the compat shim engine to
# ignore that request and run the client as the user who started it.  It is set
# on this process only - nothing is written to the registry and the client
# binary is untouched - and it disappears when this script exits.
#
# The client does not actually need the privileges: it writes only inside
# client-ascension (WTF, Cache, Logs), which the user owns.
#
# -NoNewWindow is the safety half of the pair.  It makes PowerShell use
# CreateProcess instead of ShellExecute, and CreateProcess cannot show a consent
# dialog: if the shim ever stops applying, the launch fails loudly with
# "requires elevation" (error 740) rather than quietly going back to prompting.
$env:__COMPAT_LAYER = 'RunAsInvoker'

# ERROR #132 experiment switch: set ASCENSION_ARCHIVE_NO_CLR=1 to launch with
# the .NET runtime blocked.
#
# KEEP THIS SWITCH, BUT IT IS NOT A FIX.  It was built to test a correlation
# that turned out to be a bystander, and it is worth keeping only so nobody
# spends another session re-deriving that.
#
# The correlation was real and looked strong: over 19 captured crash reports,
# the zone-in fault at EIP=CD0CA136/CD0CA176 with ECX=00403340 appeared if and
# only if clr.dll was loaded; every CLR-free report faulted somewhere else
# entirely (00749EEB, 005F4C51, 6E5D2920).  A 100 ms module timeline
# (tools/modwatch.py) for the 22:56 run showed world entry 22:56:08 -> mscoree
# + clr + mscorlib.ni + System.ni at 22:56:09 -> mscordacwks.dll (the .NET DAC,
# which only a crash reporter loads) at 22:56:11 -> WowError.exe.
#
# The 23:00 run settled it.  With this switch on, clr.dll never loaded (only
# mscoree.dll, which then failed to bind a runtime) and the client faulted at
# exactly CD0CA176 anyway, ~1 s after world entry, and still wrote a complete
# 846-line crash report.  The CLR is neither the cause nor the reporter; it is
# something the client tries to spin up around world entry that happens to be
# in flight when the real fault hits.  Do not re-open this line.
#
# The real chain is a hook trampoline -- see TROUBLESHOOTING.md entry (3).
#
# Both variables are set because the two hosting APIs consult different things:
# COMPLUS_Version is what the legacy CorBindToRuntimeEx(NULL) path reads, while
# COMPLUS_InstallRoot redirects the probe for a runtime directory and so also
# defeats the v4 ICLRMetaHost::GetRuntime path, which asks for an explicit
# version.  Nothing is written to disk and nothing in the client-ascension
# junction is touched - the variables die with this process.
if ($env:ASCENSION_ARCHIVE_NO_CLR) {
    $env:COMPLUS_Version = 'v9.9.99999'
    $env:COMPLUS_InstallRoot = 'C:\AzerothRealm\realms\ascension\no-such-runtime'
    Say 'CLR BLOCKED for this launch (COMPLUS_Version + COMPLUS_InstallRoot)'
}

try {
    $p = Start-Process -FilePath $exe -WorkingDirectory $client -NoNewWindow -PassThru
    Say "started Ascension.exe pid=$($p.Id) (unelevated, RunAsInvoker)"
    Wait-Process -Id $p.Id
    Say 'client exited'
}
finally {
    # The client rewrites Config.wtf on a clean exit, so this runs after it and
    # touches only the realm lines - whatever was changed in-game is kept.
    Set-Cvar $cfg @{ realmList = $officialList; realmName = $officialName }
    [void](Set-GlueRealm '')
    Say "restored official realm ($officialList)"
}
