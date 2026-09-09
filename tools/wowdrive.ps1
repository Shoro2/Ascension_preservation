# wowdrive.ps1 - single-process, multi-step driver for the Ascension client.
#   -Steps is an ordered list of "verb:arg" tokens, all executed in ONE process so
#   focus is acquired once and never re-raced between steps.
#     focus            bring the client window to the foreground (implicit before input)
#     sleep:<ms>       wait
#     key:<NAME>       tap a key (ENTER ESCAPE TAB SPACE BACK or a single char)
#     keyvk:<NAME>     tap a key using virtual-key (no KEYEVENTF_SCANCODE)
#     keymsg:<NAME>    tap a key via PostMessage WM_KEYDOWN/WM_KEYUP
#     type:<text>      type a string (scan codes)
#     typemsg:<text>   type a string via PostMessage WM_CHAR
#     click:<x>,<y>    left-click at CLIENT coords
#     shot:<path>      screenshot the client area
# Everything after the first ':' is the argument, so text may contain ':'.
param(
  [Parameter(Mandatory=$true)][int]$ProcId,
  [Parameter(Mandatory=$true)][string[]]$Steps
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class WD {
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
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
  public const uint MDOWN=0x02, MUP=0x04, KDOWN=0x00, KUP=0x02, SCAN=0x08;
}
'@
[WD]::SetProcessDPIAware() | Out-Null
$p = Get-Process -Id $ProcId
$hwnd = $p.MainWindowHandle
if ($hwnd -eq [IntPtr]::Zero) { Write-Output "NOWINDOW pid=$ProcId"; exit 2 }

function Focus {
  $fg = [WD]::GetForegroundWindow()
  if ($fg -eq $hwnd) { return $true }
  $t = [WD]::GetWindowThreadProcessId($hwnd, [IntPtr]::Zero)
  $f = [WD]::GetWindowThreadProcessId($fg,   [IntPtr]::Zero)
  $me = [WD]::GetCurrentThreadId()
  [WD]::AttachThreadInput($me, $t, $true) | Out-Null
  if ($f -ne $t) { [WD]::AttachThreadInput($me, $f, $true) | Out-Null }
  [WD]::ShowWindow($hwnd, 9) | Out-Null
  [WD]::BringWindowToTop($hwnd) | Out-Null
  [WD]::SetForegroundWindow($hwnd) | Out-Null
  Start-Sleep -Milliseconds 300
  if ($f -ne $t) { [WD]::AttachThreadInput($me, $f, $false) | Out-Null }
  [WD]::AttachThreadInput($me, $t, $false) | Out-Null
  Start-Sleep -Milliseconds 200
  return ([WD]::GetForegroundWindow() -eq $hwnd)
}

function VkOf([string]$name) {
  switch ($name.ToUpper()) {
    'SPACE'{return 0x20} 'ESCAPE'{return 0x1B} 'ESC'{return 0x1B}
    'ENTER'{return 0x0D} 'RETURN'{return 0x0D} 'TAB'{return 0x09}
    'BACK'{return 0x08} 'BACKSPACE'{return 0x08} 'LEFT'{return 0x25} 'RIGHT'{return 0x27}
    default { if ($name.Length -eq 1) { return [int][byte][char]([string]$name).ToUpper() } ; return 0 }
  }
}
function TapScan([int]$vk) {
  $s = [WD]::MapVirtualKey([uint32]$vk, 0)
  [WD]::keybd_event([byte]$vk, [byte]$s, [WD]::KDOWN -bor [WD]::SCAN, [UIntPtr]::Zero)
  Start-Sleep -Milliseconds 45
  [WD]::keybd_event([byte]$vk, [byte]$s, [WD]::KUP   -bor [WD]::SCAN, [UIntPtr]::Zero)
  Start-Sleep -Milliseconds 45
}
function TapVkOnly([int]$vk) {
  $s = [WD]::MapVirtualKey([uint32]$vk, 0)
  [WD]::keybd_event([byte]$vk, [byte]$s, [WD]::KDOWN, [UIntPtr]::Zero)
  Start-Sleep -Milliseconds 45
  [WD]::keybd_event([byte]$vk, [byte]$s, [WD]::KUP, [UIntPtr]::Zero)
  Start-Sleep -Milliseconds 45
}
function TapMsg([int]$vk) {
  $s = [WD]::MapVirtualKey([uint32]$vk, 0)
  $ld = [IntPtr](1 -bor ($s -shl 16))
  $lu = [IntPtr]([int64](1 -bor ($s -shl 16)) -bor 0xC0000000)
  [WD]::PostMessage($hwnd, [WD]::WM_KEYDOWN, [IntPtr]$vk, $ld) | Out-Null
  Start-Sleep -Milliseconds 45
  [WD]::PostMessage($hwnd, [WD]::WM_KEYUP, [IntPtr]$vk, $lu) | Out-Null
  Start-Sleep -Milliseconds 45
}
$VK_SHIFT = 0x10
function TypeStr([string]$s) {
  $shScan = [byte][WD]::MapVirtualKey(0x10, 0)
  foreach ($ch in $s.ToCharArray()) {
    if ($ch -eq [char]10) { TapScan 0x0D; continue }
    $r = [WD]::VkKeyScan($ch)
    if ($r -eq -1) { continue }
    $vk = $r -band 0xFF
    $sh = ($r -band 0x100) -ne 0
    $sc = [byte][WD]::MapVirtualKey([uint32]$vk, 0)
    if ($sh) { [WD]::keybd_event([byte]$VK_SHIFT, $shScan, [WD]::KDOWN -bor [WD]::SCAN, [UIntPtr]::Zero); Start-Sleep -Milliseconds 10 }
    [WD]::keybd_event([byte]$vk, $sc, [WD]::KDOWN -bor [WD]::SCAN, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 22
    [WD]::keybd_event([byte]$vk, $sc, [WD]::KUP -bor [WD]::SCAN, [UIntPtr]::Zero)
    if ($sh) { Start-Sleep -Milliseconds 10; [WD]::keybd_event([byte]$VK_SHIFT, $shScan, [WD]::KUP -bor [WD]::SCAN, [UIntPtr]::Zero) }
    Start-Sleep -Milliseconds 22
  }
}
function TypeMsgStr([string]$s) {
  foreach ($ch in $s.ToCharArray()) {
    [WD]::PostMessage($hwnd, [WD]::WM_CHAR, [IntPtr][int][char]$ch, [IntPtr]1) | Out-Null
    Start-Sleep -Milliseconds 15
  }
}
function Shot([string]$out) {
  $cr = New-Object WD+RECT
  [WD]::GetClientRect($hwnd, [ref]$cr) | Out-Null
  $w = $cr.R - $cr.L; $h = $cr.B - $cr.T
  $org = New-Object WD+POINT; $org.X = 0; $org.Y = 0
  [WD]::ClientToScreen($hwnd, [ref]$org) | Out-Null
  $bmp = New-Object System.Drawing.Bitmap $w, $h
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($org.X, $org.Y, 0, 0, (New-Object System.Drawing.Size($w, $h)))
  $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
  Write-Output "  shot -> $out (${w}x${h})"
}

$focused = $false
foreach ($step in $Steps) {
  $i = $step.IndexOf(':')
  if ($i -lt 0) { $verb = $step; $arg = '' } else { $verb = $step.Substring(0,$i); $arg = $step.Substring($i+1) }
  switch ($verb) {
    'focus'   { $ok = Focus; $focused = $true; Write-Output "  focus ok=$ok" }
    'sleep'   { Start-Sleep -Milliseconds ([int]$arg) }
    'shot'    { Shot $arg }
    'key'     { if (-not $focused) { Focus | Out-Null; $focused = $true }; $vk = VkOf $arg; if ($vk -eq 0) { Write-Output "  BADKEY $arg" } else { TapScan $vk; Write-Output "  key $arg" } }
    'keyvk'   { if (-not $focused) { Focus | Out-Null; $focused = $true }; $vk = VkOf $arg; TapVkOnly $vk; Write-Output "  keyvk $arg" }
    'keymsg'  { $vk = VkOf $arg; TapMsg $vk; Write-Output "  keymsg $arg" }
    'type'    { if (-not $focused) { Focus | Out-Null; $focused = $true }; TypeStr $arg; Write-Output "  type len=$($arg.Length)" }
    'typemsg' { TypeMsgStr $arg; Write-Output "  typemsg len=$($arg.Length)" }
    'click'   { if (-not $focused) { Focus | Out-Null; $focused = $true }
                $xy = $arg.Split(','); $pt = New-Object WD+POINT; $pt.X = [int]$xy[0]; $pt.Y = [int]$xy[1]
                [WD]::ClientToScreen($hwnd, [ref]$pt) | Out-Null
                [WD]::SetCursorPos($pt.X, $pt.Y) | Out-Null; Start-Sleep -Milliseconds 90
                [WD]::mouse_event([WD]::MDOWN,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 60
                [WD]::mouse_event([WD]::MUP,0,0,0,[UIntPtr]::Zero)
                Write-Output "  click $arg" }
    default   { Write-Output "  UNKNOWN STEP '$step'" }
  }
}
Write-Output "DONE"
