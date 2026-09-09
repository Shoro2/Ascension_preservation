# wowin.ps1 - drive the Ascension WoW client (DirectInput-safe).
#   Actions (one per invocation):
#     -Action shot  -Out <png>                 capture the client window (CopyFromScreen)
#     -Action click -X <cx> -Y <cy>            left click at CLIENT coords
#     -Action type  -Text <str>                type a string (scan-code keybd_event)
#     -Action key   -Text <NAME>               tap one key: W S A D SPACE ESCAPE ENTER TAB etc.
#     -Action hold  -Text <NAME> -Ms <n>       hold a key for <n> ms (movement test)
#     -Action info                             print pid/hwnd/window rect
# Keyboard uses KEYEVENTF_SCANCODE so DirectInput (movement) receives it, unlike SendKeys.
param(
  [Parameter(Mandatory=$true)][int]$ProcId,
  [Parameter(Mandatory=$true)][ValidateSet('shot','click','type','key','hold','info','run')][string]$Action,
  [int]$X, [int]$Y, [string]$Text, [int]$Ms = 1000, [string]$Out,
  [ValidateSet('scan','vk','postmsg')][string]$Method = 'scan'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class W {
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, ref RECT r);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, ref RECT r);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, UIntPtr e);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint f, UIntPtr e);
  [DllImport("user32.dll")] public static extern uint MapVirtualKey(uint code, uint mapType);
  [DllImport("user32.dll")] public static extern short VkKeyScan(char ch);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, IntPtr pid);
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint from, uint to, bool attach);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  public const uint WM_KEYDOWN=0x100, WM_KEYUP=0x101, WM_CHAR=0x102;
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  public const uint MDOWN=0x02, MUP=0x04, KDOWN=0x00, KUP=0x02, SCAN=0x08, EXT=0x01;
}
'@
[W]::SetProcessDPIAware() | Out-Null

$p = Get-Process -Id $ProcId
$hwnd = $p.MainWindowHandle
if ($hwnd -eq [IntPtr]::Zero) { Write-Output "NOWINDOW pid=$ProcId"; exit 2 }

function Foreground {
  # Robust focus: AttachThreadInput to both the current-foreground thread and the
  # target thread defeats the Win32 foreground-lock that makes a bare
  # SetForegroundWindow silently no-op (which leaks keystrokes to another window).
  $fg = [W]::GetForegroundWindow()
  $tgtThread = [W]::GetWindowThreadProcessId($hwnd, [IntPtr]::Zero)
  $fgThread  = [W]::GetWindowThreadProcessId($fg,   [IntPtr]::Zero)
  $me = [W]::GetCurrentThreadId()
  [W]::AttachThreadInput($me, $tgtThread, $true) | Out-Null
  if ($fgThread -ne $tgtThread) { [W]::AttachThreadInput($me, $fgThread, $true) | Out-Null }
  [W]::ShowWindow($hwnd, 9) | Out-Null   # SW_RESTORE
  [W]::BringWindowToTop($hwnd) | Out-Null
  [W]::SetForegroundWindow($hwnd) | Out-Null
  Start-Sleep -Milliseconds 300
  if ($fgThread -ne $tgtThread) { [W]::AttachThreadInput($me, $fgThread, $false) | Out-Null }
  [W]::AttachThreadInput($me, $tgtThread, $false) | Out-Null
  # verify we actually own the foreground before returning
  $now = [W]::GetForegroundWindow()
  if ($now -ne $hwnd) { Write-Output ("WARN foreground not acquired (fg={0} want={1})" -f $now, $hwnd) }
  Start-Sleep -Milliseconds 150
}

# VK map for named keys and characters
function VkOf([string]$name) {
  switch ($name.ToUpper()) {
    'SPACE' { return 0x20 } 'ESCAPE' { return 0x1B } 'ESC' { return 0x1B }
    'ENTER' { return 0x0D } 'RETURN' { return 0x0D } 'TAB' { return 0x09 }
    'BACK' { return 0x08 } 'BACKSPACE' { return 0x08 }
    default {
      if ($name.Length -eq 1) {
        $c = [byte][char]([string]$name).ToUpper()
        return [int]$c
      }
      return 0
    }
  }
}
$EXTENDED = @(0x1B) # not really; kept simple

function KeyDown([int]$vk, [string]$m) {
  $scan = [W]::MapVirtualKey([uint32]$vk, 0)
  switch ($m) {
    'scan'    { [W]::keybd_event([byte]$vk, [byte]$scan, [W]::KDOWN -bor [W]::SCAN, [UIntPtr]::Zero) }
    'vk'      { [W]::keybd_event([byte]$vk, [byte]$scan, [W]::KDOWN, [UIntPtr]::Zero) }
    'postmsg' { $l = [IntPtr](1 -bor ($scan -shl 16)); [W]::PostMessage($hwnd, [W]::WM_KEYDOWN, [IntPtr]$vk, $l) | Out-Null }
  }
}
function KeyUp([int]$vk, [string]$m) {
  $scan = [W]::MapVirtualKey([uint32]$vk, 0)
  switch ($m) {
    'scan'    { [W]::keybd_event([byte]$vk, [byte]$scan, [W]::KUP -bor [W]::SCAN, [UIntPtr]::Zero) }
    'vk'      { [W]::keybd_event([byte]$vk, [byte]$scan, [W]::KUP, [UIntPtr]::Zero) }
    'postmsg' { $l = [IntPtr](1 -bor ($scan -shl 16) -bor 0xC0000000); [W]::PostMessage($hwnd, [W]::WM_KEYUP, [IntPtr]$vk, $l) | Out-Null }
  }
}
function TapVk([int]$vk, [int]$downMs = 40, [string]$m = 'scan') {
  KeyDown $vk $m
  Start-Sleep -Milliseconds $downMs
  KeyUp $vk $m
  Start-Sleep -Milliseconds 40
}

# Type an arbitrary character using VkKeyScan so symbols/shift are correct.
$VK_SHIFT = 0x10
function TypeChar([char]$ch, [string]$m = 'scan') {
  if ($ch -eq "`n") { TapVk 0x0D 25 $m; return }
  $r = [W]::VkKeyScan($ch)
  if ($r -eq -1) { return }
  $vk    = $r -band 0xFF
  $shift = ($r -band 0x100) -ne 0
  if ($shift) { KeyDown $VK_SHIFT $m; Start-Sleep -Milliseconds 8 }
  TapVk $vk 25 $m
  if ($shift) { KeyUp $VK_SHIFT $m; Start-Sleep -Milliseconds 8 }
}
function TypeString([string]$s, [string]$m = 'scan') {
  foreach ($ch in $s.ToCharArray()) { TypeChar $ch $m }
}

switch ($Action) {
  'info' {
    $r = New-Object W+RECT
    [W]::GetWindowRect($hwnd, [ref]$r) | Out-Null
    Write-Output ("PID=$ProcId HWND=$hwnd RECT=({0},{1})-({2},{3}) SIZE={4}x{5}" -f $r.L,$r.T,$r.R,$r.B,($r.R-$r.L),($r.B-$r.T))
  }
  'shot' {
    if (-not $Out) { $Out = "$env:TEMP\wowshot.png" }
    # Capture the CLIENT area so screenshot pixels map 1:1 to click coords.
    $cr = New-Object W+RECT
    [W]::GetClientRect($hwnd, [ref]$cr) | Out-Null
    $w = $cr.R - $cr.L; $h = $cr.B - $cr.T
    if ($w -le 0 -or $h -le 0) { Write-Output "BADRECT ${w}x${h}"; exit 3 }
    $org = New-Object W+POINT; $org.X = 0; $org.Y = 0
    [W]::ClientToScreen($hwnd, [ref]$org) | Out-Null
    $bmp = New-Object System.Drawing.Bitmap $w, $h
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($org.X, $org.Y, 0, 0, (New-Object System.Drawing.Size($w, $h)))
    $bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Output "SHOT $Out ${w}x${h} clientOrigin=($($org.X),$($org.Y))"
  }
  'click' {
    Foreground
    $pt = New-Object W+POINT; $pt.X = $X; $pt.Y = $Y
    [W]::ClientToScreen($hwnd, [ref]$pt) | Out-Null
    [W]::SetCursorPos($pt.X, $pt.Y) | Out-Null
    Start-Sleep -Milliseconds 80
    [W]::mouse_event([W]::MDOWN, 0,0,0,[UIntPtr]::Zero)
    Start-Sleep -Milliseconds 50
    [W]::mouse_event([W]::MUP, 0,0,0,[UIntPtr]::Zero)
    Write-Output "CLICK client=($X,$Y) screen=($($pt.X),$($pt.Y))"
  }
  'type' {
    Foreground
    TypeString $Text $Method
    Write-Output "TYPE len=$($Text.Length) method=$Method"
  }
  'run' {
    # Open chat (ENTER=OPENCHAT), type a slash command / Lua, submit with ENTER.
    # The open-tap is racy right after a fresh Foreground (the AttachThreadInput
    # dance can swallow the first key), so warm focus first, settle, THEN tap.
    Foreground
    Start-Sleep -Milliseconds 250     # let focus settle so the open-ENTER lands
    TapVk 0x0D 45 $Method             # open chat edit box
    Start-Sleep -Milliseconds 550     # wait for the edit box to actually appear
    TypeString $Text $Method          # e.g. "/run print(...)"
    Start-Sleep -Milliseconds 250
    TapVk 0x0D 45 $Method             # submit
    Write-Output "RUN len=$($Text.Length) method=$Method"
  }
  'key' {
    Foreground
    $vk = VkOf $Text
    if ($vk -eq 0) { Write-Output "BADKEY $Text"; exit 4 }
    TapVk $vk 60 $Method
    Write-Output "KEY $Text vk=$vk method=$Method"
  }
  'hold' {
    Foreground
    $vk = VkOf $Text
    if ($vk -eq 0) { Write-Output "BADKEY $Text"; exit 4 }
    KeyDown $vk $Method
    Start-Sleep -Milliseconds $Ms
    KeyUp $vk $Method
    Write-Output "HOLD $Text vk=$vk ${Ms}ms method=$Method"
  }
}
