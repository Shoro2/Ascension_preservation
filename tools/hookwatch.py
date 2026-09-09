# -*- coding: utf-8 -*-
"""Read-only: watch the 5-byte hot-patch at 0x00403340 through an ERROR #132
signature-B crash.

The prediction being tested
---------------------------
Signature B always faults at EIP = 0xCD0CA136 or 0xCD0CA176 with ECX =
0x00403340, EDX = 0, EAX = &localfloat.  Those three registers are exactly what
the event dispatcher sets up immediately before its indirect call:

  00480B6C  mov edx,[ebx+0x0C]   ; -> EDX at crash
  00480B6F  mov eax,[ebp+0x10]   ; -> EAX at crash (&localfloat from 0047DC01)
  00480B72  mov ecx,[ebx+0x08]   ; -> ECX at crash = 00403340
  00480B77  call ecx

None of them is touched between there and the fault, and EIP != ECX, so
`call ecx` SUCCEEDED into 0x00403340 and we die within its first instruction.
0x00403340 is hot-patched by Extensions.dll with a 5-byte `E9 rel32`.

Now the arithmetic.  A jmp at 0x00403340 lands on 0x00403345 + rel32.  If the
top half of that rel32 were the 0xCC filler:

    target = 0x00403345 + 0xCCCC0000 + low16 = 0xCD0C3345 + low16

Every signature-B EIP starts 0xCD0C.  The two observed values need
low16 = 0x6DF1 (-> CD0CA136) and low16 = 0x6E31 (-> CD0CA176), which differ by
0x40 -- two neighbouring detours.  Because a module base is 64 KB aligned, the
low half of a correct rel32 does not depend on ASLR, which is exactly why the
fault address is a fixed constant across runs and across Extensions.dll bases.

So: at crash time the bytes at 0x00403340 should read

    E9 F1 6D CC CC ...      (-> CD0CA136)
    E9 31 6E CC CC ...      (-> CD0CA176)

instead of a healthy `E9 <rel32> CC CC` whose target lands inside
Extensions.dll.  If they do not, this reading is wrong -- the tool says so.

The client process stays alive after the fault (WowError.exe appears while
Ascension.exe is still running), so the post-mortem bytes are readable.

Nothing here writes.  OpenProcess asks for VM_READ|QUERY_INFORMATION only and
there is no WriteProcessMemory import (handoff s8).

  python tools\hookwatch.py <pid> [seconds=240] [interval=0.02]
"""
import ctypes
import ctypes.wintypes as w
import sys
import time

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

SITE = 0x00403340
NBYTES = 16
DISK = bytes.fromhex("558bec568b75086a00")  # first bytes of the unpatched fn

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = w.HANDLE
k32.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD), ("th32ModuleID", w.DWORD),
                ("th32ProcessID", w.DWORD), ("GlblcntUsage", w.DWORD),
                ("ProccntUsage", w.DWORD), ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                ("modBaseSize", w.DWORD), ("hModule", w.HMODULE),
                ("szModule", ctypes.c_char * 256), ("szExePath", ctypes.c_char * 260)]


def modules(pid):
    """{lowername: (base, size)} -- so a jmp target can be attributed."""
    out = {}
    snap = k32.CreateToolhelp32Snapshot(0x00000008 | 0x00000010, pid)  # MODULE|MODULE32
    if snap == -1:
        return out
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(me)
    ok = k32.Module32First(snap, ctypes.byref(me))
    while ok:
        out[me.szModule.decode("mbcs", "replace").lower()] = (
            ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value or 0, me.modBaseSize)
        ok = k32.Module32Next(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    return out


def attribute(mods, addr):
    for name, (base, size) in mods.items():
        if base <= addr < base + size:
            return "%s+%X" % (name, addr - base)
    return "UNMAPPED"


def decode(b, mods):
    """Explain the patch, if it is one."""
    if b[:len(DISK)] == DISK[:len(b)]:
        return "UNPATCHED (matches the on-disk prologue)"
    if b[0] == 0xE9:
        rel = int.from_bytes(b[1:5], "little", signed=True)
        tgt = (SITE + 5 + rel) & 0xFFFFFFFF
        tail = b[5:7].hex()
        note = ""
        if b[3] == 0xCC and b[4] == 0xCC:
            note = "  <<<< rel32 HIGH HALF IS CC FILLER -- THIS IS THE BUG"
        if tgt in (0xCD0CA136, 0xCD0CA176):
            note += "  <<<< EQUALS THE CRASH EIP"
        return "jmp %08X (%s) rel32=%08X tail=%s%s" % (
            tgt, attribute(mods, tgt), rel & 0xFFFFFFFF, tail, note)
    return "unrecognised"


def main():
    pid = int(sys.argv[1])
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 240.0
    iv = float(sys.argv[3]) if len(sys.argv) > 3 else 0.02

    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print("OpenProcess failed: %d" % ctypes.get_last_error())
        return 1
    print("polling %08X (%d bytes) in pid %d every %.0f ms for %.0fs" %
          (SITE, NBYTES, pid, iv * 1000, secs))
    sys.stdout.flush()

    mods = modules(pid)
    ext = mods.get("extensions.dll")
    if ext:
        print("Extensions.dll base=%08X size=%X" % ext)
    buf = (ctypes.c_char * NBYTES)()
    got = ctypes.c_size_t(0)
    t0 = time.time()
    last = None
    n = 0
    reads = 0
    while time.time() - t0 < secs:
        rc = w.DWORD(0)
        if not k32.GetExitCodeProcess(h, ctypes.byref(rc)) or rc.value != 259:
            print("[%7.3f] PROCESS EXITED (code %d) after %d reads" %
                  (time.time() - t0, rc.value, reads))
            break
        if k32.ReadProcessMemory(h, ctypes.c_void_p(SITE), buf, NBYTES,
                                 ctypes.byref(got)) and got.value == NBYTES:
            reads += 1
            cur = bytes(buf)
            if cur != last:
                n += 1
                if n == 2 and not mods.get("extensions.dll"):
                    mods = modules(pid)
                print("[%7.3f] #%d  %s  %s" %
                      (time.time() - t0, n, cur.hex(" "), decode(cur, mods)))
                sys.stdout.flush()
                last = cur
        time.sleep(iv)
    print("[%7.3f] done, %d distinct value(s) over %d reads" %
          (time.time() - t0, n, reads))
    if last is not None:
        print("FINAL %08X: %s" % (SITE, last.hex(" ")))
        print("FINAL decode: %s" % decode(last, mods))
    return 0


if __name__ == "__main__":
    sys.exit(main())
