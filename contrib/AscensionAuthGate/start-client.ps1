[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ClientRoot,
    [ValidateSet('coa','ascension')][string]$Mode = 'coa',
    [string]$ExpectedAuthserverPath,
    [switch]$NoLaunch
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Launch from a normal unelevated Windows session.' }
$ClientRoot = (Resolve-Path -LiteralPath $ClientRoot).Path.TrimEnd('\')
if ((Get-Item -LiteralPath $ClientRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Use the real client path, not a junction.' }
$verified = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'build\binary-verification.json') -Raw | ConvertFrom-Json
$hashes = @{
    'Ascension.exe'='5B26E33B2129737AF3A0C3164459F4C9B109398DAB921F76C6740A8746FBB929'
    'Extensions_orig.dll'='0F8D847B3ADC44A963606F0CD4F7938AD6FCD6F4D87FEAC3131C7153BDF3BB11'
    'Extensions.dll'=$verified.sha256
}
foreach ($name in $hashes.Keys) { if ((Get-FileHash -LiteralPath (Join-Path $ClientRoot $name)).Hash -ne $hashes[$name]) { throw "Client verification failed: $name" } }
# The bridge still reads the world key from a single Ascension process. Other
# WoW clients are unaffected; do not start competing Ascension copies.
if (@(Get-Process -Name Ascension -ErrorAction SilentlyContinue).Count) { throw 'An Ascension client is already running.' }
$listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
if ($listeners | Where-Object LocalPort -eq 3725) { throw 'Another process owns AuthGate port 3725.' }
foreach ($port in @(3724,8088,8086)) {
    if (-not ($listeners | Where-Object { $_.LocalPort -eq $port -and $_.LocalAddress -eq '127.0.0.1' })) { throw "Required local listener $port missing; start the intended realm first." }
}
if ($ExpectedAuthserverPath) {
    $auth = $listeners | Where-Object { $_.LocalPort -eq 3724 -and $_.LocalAddress -eq '127.0.0.1' } | Select-Object -First 1
    if ((Get-Process -Id $auth.OwningProcess).Path -ne $ExpectedAuthserverPath) { throw 'Authserver belongs to another realm; switch realms in the hub first.' }
}
foreach ($rel in @('WTF','Interface','Interface\GlueXML')) {
    if ((Get-Item -LiteralPath (Join-Path $ClientRoot $rel)).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing shared configuration directory: $rel" }
}
$cfg = Join-Path $ClientRoot 'WTF\Config.wtf'
$glue = Join-Path $ClientRoot 'Interface\GlueXML\AccountLogin.lua'
$cfgText = [IO.File]::ReadAllText($cfg)
$glueText = [IO.File]::ReadAllText($glue)
if ($glueText -notmatch '(?m)^ASCENSION_ARCHIVE_REALMLIST\s*=\s*".*?"\s*;') { throw 'Required archive GlueXML realm override is missing; install the documented archive UI first.' }
if ($NoLaunch) { Write-Output 'Verified client, local listeners, realm ownership and configuration boundaries.'; exit 0 }
function Atomic-Text([string]$path,[string]$text) {
    $temp = $path + '.authgate-' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try { [IO.File]::WriteAllText($temp,$text,[Text.UTF8Encoding]::new($false)); [IO.File]::Replace($temp,$path,[NullString]::Value) }
    finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}
$realmName = if ($Mode -eq 'coa') { "Vol'jin - Conquest of Azeroth" } else { 'Area 52 - Free-Pick' }
foreach ($pair in @(@('realmList','127.0.0.1:3725'),@('realmName',$realmName))) {
    $pattern = '(?m)^\s*SET\s+' + [regex]::Escape($pair[0]) + '\s+".*?"\s*$'
    $line = 'SET ' + $pair[0] + ' "' + $pair[1] + '"'
    if ($cfgText -match $pattern) { $cfgText = [regex]::Replace($cfgText,$pattern,$line) }
    else { $cfgText += "`n" + $line + "`n" }
}
$glueText = [regex]::Replace($glueText,'(?m)^ASCENSION_ARCHIVE_REALMLIST\s*=\s*".*?"\s*;','ASCENSION_ARCHIVE_REALMLIST = "127.0.0.1:3725";')
Atomic-Text $cfg $cfgText
Atomic-Text $glue $glueText
$priorCompat=$env:__COMPAT_LAYER
$priorMode=$env:ASCENSION_AUTHGATE_MODE
try {
    $env:__COMPAT_LAYER='RunAsInvoker'
    $env:ASCENSION_AUTHGATE_MODE=$Mode
    $clientProcess=Start-Process -FilePath (Join-Path $ClientRoot 'Ascension.exe') -WorkingDirectory $ClientRoot -PassThru
    Write-Output ("Started original Ascension client PID {0}, mode {1}, AuthGate 3725." -f $clientProcess.Id,$Mode)
} finally { $env:__COMPAT_LAYER=$priorCompat; $env:ASCENSION_AUTHGATE_MODE=$priorMode }
