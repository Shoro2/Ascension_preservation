# ghostinput.ps1 - drive and watch the Ascension client WITHOUT stealing the
# real mouse, the keyboard focus, or foregrounding the window.  Everything goes
# through PostMessage to the client's HWND and PrintWindow for capture, so the
# physical cursor never moves and you can keep working in another window.
#
#   -Action key    -Text <NAME>        background key press (ENTER, ESCAPE, UP, ...)
#   -Action char   -Text <str>         background WM_CHAR text
#   -Action lua    -Text "<lua>"       run Lua in the world UI  (chat + /run)
#   -Action luaclick -Text <FrameName> "click" a named widget through its OnClick
#   -Action slash  -Text "/who ..."    open chat, type any slash line, send it
#   -Action shot   -Out <path>         capture the window even while occluded
#   -Action info                       hwnd / client size / real-cursor position
#   -Action click|rclick|move -X -Y    see the WARNING below -- rarely what you want
#
# ---------------------------------------------------------------------------
# WHAT ACTUALLY WORKS IN THE BACKGROUND, AND WHY
#
# KEYBOARD: yes.  WM_KEYDOWN/WM_KEYUP/WM_CHAR are consumed normally whether or
# not the window has focus, on the glue screens and in the world.
#
# MOUSE: no -- and not for want of trying.  WoW does not take the pointer
# position from the message it is handed; it polls the OS cursor.  Measured:
# post WM_MOUSEMOVE for client (100,100) with the real cursor parked elsewhere,
# then ask the game where its cursor is --
#     /run local x,y = GetCursorPosition() dprint(x, y)
# and it reports the REAL cursor, scaled by UIParent, every time.  A posted
# WM_LBUTTONDOWN therefore clicks whatever is under the physical pointer, not
# under the coordinates you passed.  click/rclick/move are kept for the case
# where the pointer already happens to be parked on the target (and they print
# where the real pointer is, so a mismatch is visible), but they are not a
# ghost mouse and cannot be made into one from outside the process.
#
# SO DRIVE IT LIKE THIS INSTEAD:
#   * glue screens (login / character select) are fully keyboard-navigable --
#       ENTER  = Login, then Enter World      UP / DOWN = change character
#       ESCAPE = back / cancel                TAB       = next field
#   * in the world, -Action lua is a better mouse than the mouse:
#       -Action lua      -Text 'ToggleCharacter("PaperDollFrame")'
#       -Action luaclick -Text 'GameMenuButtonLogout'
#     Anything the UI can do from a click, it can do from its OnClick handler.
#
# Keep a single -Action lua line SHORT.  The text goes in one WM_CHAR per
# character and a long line has been seen to arrive corrupted (which shows up
# as a red "UI Error" in chat, not as a failure here).  Split long work into
# several calls, or park it in a function in the loose FrameXML and call that.
#
# Output goes to the client's own Logs\LUA.txt via the global dprint(), so the
# read-back loop is: -Action lua ... then tail that file.  No screenshots, no
# transcription, no focus stealing.
#
# CAPTURE: PrintWindow(PW_RENDERFULLCONTENT) asks the window to redraw itself
# into our bitmap and works while it is behind other windows -- verified against
# this D3D client.  A D3D window is allowed to answer with an empty frame, so
# the result is sampled for "every pixel the same colour" and falls back to a
# screen-region grab if so.  -Method print never falls back, -Method screen
# always uses the region grab (which needs the window visible).
#
# The region grab is REFUSED (exit 3) when another process owns the pixel at the
# centre of our client area.  It captures the screen, not the window, so with a
# second game running on this machine it would otherwise hand back a convincing
# screenshot of the WRONG client.
param(
  [Parameter(Mandatory = $true)][int]$ProcId,
  [Parameter(Mandatory = $true)]
  [ValidateSet('key', 'hold', 'char', 'lua', 'luaclick', 'slash', 'shot', 'info', 'click', 'rclick', 'move')]
  [string]$Action,
  [int]$X, [int]$Y, [int]$Ms = 1000,
  [string]$Text,
  [string]$Out,
  [ValidateSet('auto', 'print', 'screen')][string]$Method = 'auto'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class G {
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern short VkKeyScan(char ch);
  [DllImport("user32.dll")] public static extern uint MapVirtualKey(uint code, uint mapType);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
  [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(POINT p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
  public const uint WM_MOUSEMOVE=0x0200, WM_LBUTTONDOWN=0x0201, WM_LBUTTONUP=0x0202;
  public const uint WM_RBUTTONDOWN=0x0204, WM_RBUTTONUP=0x0205;
  public const uint WM_KEYDOWN=0x0100, WM_KEYUP=0x0101, WM_CHAR=0x0102;
  public const int MK_LBUTTON=0x0001, MK_RBUTTON=0x0002;
  public const uint PW_RENDERFULLCONTENT=0x00000002;
}
'@
$p = Get-Process -Id $ProcId
$hwnd = $p.MainWindowHandle
if ($hwnd -eq [IntPtr]::Zero) { Write-Output "NOWINDOW pid=$ProcId"; exit 2 }

function LParam([int]$x, [int]$y) { return [IntPtr](($y -shl 16) -bor ($x -band 0xFFFF)) }

# client-area size and its screen origin (for the capture fallback and for
# reporting where the real pointer is in client coordinates)
$cr = New-Object G+RECT; [void][G]::GetClientRect($hwnd, [ref]$cr)
$org = New-Object G+POINT; [void][G]::ClientToScreen($hwnd, [ref]$org)
$cw = $cr.R - $cr.L; $ch = $cr.B - $cr.T
function RealCursorClient {
  $cp = New-Object G+POINT; [void][G]::GetCursorPos([ref]$cp)
  return "$($cp.X - $org.X),$($cp.Y - $org.Y)"
}

$VK = @{ ENTER = 0x0D; RETURN = 0x0D; ESCAPE = 0x1B; ESC = 0x1B; TAB = 0x09; SPACE = 0x20;
  BACKSPACE = 0x08; DELETE = 0x2E; UP = 0x26; DOWN = 0x28; LEFT = 0x25; RIGHT = 0x27;
  HOME = 0x24; END = 0x23; F1 = 0x70; F2 = 0x71; F3 = 0x72; F4 = 0x73; F5 = 0x74
}
function Send-Key([string]$name) {
  $vk = $VK[$name.ToUpper()]
  if (-not $vk) { $vk = [int]([G]::VkKeyScan($name[0]) -band 0xFF) }
  $scan = [G]::MapVirtualKey([uint32]$vk, 0)
  $down = [IntPtr]((1) -bor ($scan -shl 16))
  $up = [IntPtr]((1) -bor ($scan -shl 16) -bor (0xC0000000))
  [void][G]::PostMessage($hwnd, [G]::WM_KEYDOWN, [IntPtr]$vk, $down)
  Start-Sleep -Milliseconds 30
  [void][G]::PostMessage($hwnd, [G]::WM_KEYUP, [IntPtr]$vk, $up)
  return $vk
}
function Send-Hold([string]$name, [int]$ms) {
  # movement is the one thing -Action lua CANNOT do: MoveForwardStart() and the
  # rest are protected ("A macro script has been blocked from an action only
  # available to the Blizzard UI").  A held key is not -- WM_KEYDOWN starts the
  # move, WM_KEYUP ends it, and the client honours both while unfocused.
  # Windows would normally repeat WM_KEYDOWN while a key is held; WoW does not
  # need the repeats, but they are sent anyway so a dropped message cannot leave
  # the character running forever.
  $vk = $VK[$name.ToUpper()]
  if (-not $vk) { $vk = [int]([G]::VkKeyScan($name[0]) -band 0xFF) }
  $scan = [G]::MapVirtualKey([uint32]$vk, 0)
  $down = [IntPtr]((1) -bor ($scan -shl 16))
  $rept = [IntPtr]((1) -bor ($scan -shl 16) -bor (0x40000000))
  $up = [IntPtr]((1) -bor ($scan -shl 16) -bor (0xC0000000))
  [void][G]::PostMessage($hwnd, [G]::WM_KEYDOWN, [IntPtr]$vk, $down)
  $t = 0
  while ($t -lt $ms) {
    Start-Sleep -Milliseconds 50
    $t += 50
    [void][G]::PostMessage($hwnd, [G]::WM_KEYDOWN, [IntPtr]$vk, $rept)
  }
  [void][G]::PostMessage($hwnd, [G]::WM_KEYUP, [IntPtr]$vk, $up)
  return $vk
}
function Send-Text([string]$s) {
  foreach ($c in $s.ToCharArray()) {
    [void][G]::PostMessage($hwnd, [G]::WM_CHAR, [IntPtr][int][char]$c, [IntPtr]0)
    Start-Sleep -Milliseconds 15    # below ~10ms characters have been seen to drop
  }
}
function Send-Slash([string]$line) {
  # ENTER opens the chat edit box, the line goes in as WM_CHAR, ENTER sends it.
  [void](Send-Key 'ENTER')
  Start-Sleep -Milliseconds 300
  Send-Text $line
  Start-Sleep -Milliseconds 200
  [void](Send-Key 'ENTER')
}

switch ($Action) {
  'info' {
    $fg = [G]::GetForegroundWindow()
    Write-Output ("HWND={0} client={1}x{2} origin=({3},{4}) foreground={5} realCursorClient=({6})" -f
      $hwnd, $cw, $ch, $org.X, $org.Y, ($fg -eq $hwnd), (RealCursorClient))
  }
  'key' { $vk = Send-Key $Text; Write-Output "GHOSTKEY $Text (vk=$vk)" }
  'hold' { $vk = Send-Hold $Text $Ms; Write-Output "GHOSTHOLD $Text ${Ms}ms (vk=$vk)" }
  'char' { Send-Text $Text; Write-Output "GHOSTCHAR '$Text'" }
  'slash' { Send-Slash $Text; Write-Output "GHOSTSLASH '$Text'" }
  'lua' { Send-Slash ("/run " + $Text); Write-Output "GHOSTLUA '$Text'" }
  'luaclick' {
    # the real ghost click: go through the widget's own OnClick handler
    Send-Slash ("/run local f=_G['" + $Text + "'] if f and f.Click then f:Click() else dprint('luaclick: no " + $Text + "') end")
    Write-Output "GHOSTLUACLICK $Text"
  }
  'move' {
    [void][G]::PostMessage($hwnd, [G]::WM_MOUSEMOVE, [IntPtr]0, (LParam $X $Y))
    Write-Output "GHOSTMOVE ($X,$Y) -- NOTE: WoW ignores this, it polls the real cursor at ($(RealCursorClient))"
  }
  'click' {
    $lp = LParam $X $Y
    [void][G]::PostMessage($hwnd, [G]::WM_MOUSEMOVE, [IntPtr]0, $lp)
    Start-Sleep -Milliseconds 40
    [void][G]::PostMessage($hwnd, [G]::WM_LBUTTONDOWN, [IntPtr][G]::MK_LBUTTON, $lp)
    Start-Sleep -Milliseconds 50
    [void][G]::PostMessage($hwnd, [G]::WM_LBUTTONUP, [IntPtr]0, $lp)
    Write-Output "GHOSTCLICK ($X,$Y) -- lands at the REAL cursor ($(RealCursorClient)); use -Action lua/luaclick"
  }
  'rclick' {
    $lp = LParam $X $Y
    [void][G]::PostMessage($hwnd, [G]::WM_MOUSEMOVE, [IntPtr]0, $lp)
    Start-Sleep -Milliseconds 40
    [void][G]::PostMessage($hwnd, [G]::WM_RBUTTONDOWN, [IntPtr][G]::MK_RBUTTON, $lp)
    Start-Sleep -Milliseconds 50
    [void][G]::PostMessage($hwnd, [G]::WM_RBUTTONUP, [IntPtr]0, $lp)
    Write-Output "GHOSTRCLICK ($X,$Y) -- lands at the REAL cursor ($(RealCursorClient))"
  }
  'shot' {
    if (-not $Out) { throw "-Out <path> is required for -Action shot" }
    $wr = New-Object G+RECT; [void][G]::GetWindowRect($hwnd, [ref]$wr)
    $ww = $wr.R - $wr.L; $wh = $wr.B - $wr.T
    $used = 'print'
    $bmp = $null
    if ($Method -ne 'screen') {
      $full = New-Object System.Drawing.Bitmap($ww, $wh)
      $g = [System.Drawing.Graphics]::FromImage($full)
      $hdc = $g.GetHdc()
      $ok = [G]::PrintWindow($hwnd, $hdc, [G]::PW_RENDERFULLCONTENT)
      $g.ReleaseHdc($hdc); $g.Dispose()
      $insetX = $org.X - $wr.L; $insetY = $org.Y - $wr.T
      $rect = New-Object System.Drawing.Rectangle($insetX, $insetY, $cw, $ch)
      $bmp = $full.Clone($rect, $full.PixelFormat)
      $full.Dispose()
      # detect an empty frame by sampling a grid for any colour variation
      $first = $bmp.GetPixel(0, 0); $varied = $false
      $stepX = [Math]::Max(1, [int]($cw / 24)); $stepY = [Math]::Max(1, [int]($ch / 24))
      for ($sx = 0; $sx -lt $cw -and -not $varied; $sx += $stepX) {
        for ($sy = 0; $sy -lt $ch; $sy += $stepY) {
          if ($bmp.GetPixel($sx, $sy) -ne $first) { $varied = $true; break }
        }
      }
      if ((-not $ok -or -not $varied) -and $Method -eq 'auto') {
        $bmp.Dispose(); $bmp = $null; $used = 'screen(fallback)'
      }
      elseif (-not $varied) { $used = 'print(BLANK)' }
    }
    else { $used = 'screen' }
    if (-not $bmp) {
      # The fallback grabs a REGION OF THE SCREEN at the client's coordinates, so it
      # returns whatever is actually on top there.  With a second game running -- which
      # is now a normal thing, the archive shares this machine with a real realm -- that
      # is somebody else's window, and the capture would look like a plausible WoW
      # screenshot of the wrong client.  Refuse instead of lying: ask the OS who owns
      # the pixel at the middle of our client area, and bail unless it is us.
      $mid = New-Object G+POINT
      $mid.X = $org.X + [int]($cw / 2); $mid.Y = $org.Y + [int]($ch / 2)
      $top = [G]::WindowFromPoint($mid)
      $owner = 0; [void][G]::GetWindowThreadProcessId($top, [ref]$owner)
      if ($owner -ne $ProcId) {
        $name = (Get-Process -Id $owner -ErrorAction SilentlyContinue).ProcessName
        Write-Output ("SHOT FAILED occluded -- PrintWindow returned an empty frame and " +
          "the screen fallback would capture pid $owner ($name), not $ProcId. " +
          "Bring the client forward, or use -Method print to accept a blank frame.")
        exit 3
      }
      $bmp = New-Object System.Drawing.Bitmap($cw, $ch)
      $g = [System.Drawing.Graphics]::FromImage($bmp)
      $g.CopyFromScreen($org.X, $org.Y, 0, 0, (New-Object System.Drawing.Size($cw, $ch)))
      $g.Dispose()
    }
    $bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output ("SHOT {0} {1}x{2} via={3} origin=({4},{5})" -f $Out, $cw, $ch, $used, $org.X, $org.Y)
  }
}
