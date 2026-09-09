# -*- coding: utf-8 -*-
"""Read-only: timestamp every DLL the client loads, to 100 ms.

Why this exists
---------------
Across 19 captured crash reports the wild-EIP zone-in fault (EIP=CD0CA136 /
CD0CA176, ECX=00403340) correlates 1:1 with the .NET CLR being present in the
module list -- every CD0CA1xx report has clr.dll + mscorlib.ni.dll, and every
report WITHOUT them faults somewhere else entirely (00749EEB, 005F4C51,
6E5D2920).  A vmgrow census then showed `image` stepping 128.3 -> 168.8 MB in
the same one-second sample as the fault.

One second is not enough resolution to tell the two possibilities apart:

  (a) the CLR loads at world entry, and its arrival is what breaks the
      event-6 dispatch -- the CLR is the CAUSE; or
  (b) the client's crash handler is managed, so the CLR is dragged in AFTER
      the fault purely to write the report -- the CLR is a CONSEQUENCE and the
      whole correlation is an artefact.

Those demand opposite fixes, so measure instead of guessing.  This polls the
module list at 100 ms and prints load order with timestamps, plus the moment
WowError.exe appears (the crash handler has finished writing its report by
then).  If mscoree/clr.dll land clearly BEFORE the client freezes, it is (a).
Whatever module loads immediately before mscoree.dll is the one that hosted
the runtime.

Strictly read-only: CreateToolhelp32Snapshot + OpenProcess for liveness only.
No WriteProcessMemory / VirtualAllocEx / VirtualProtectEx anywhere -- HANDOFF
section 8.  Note that a DEBUGGER must not be attached to this client: doing so
kills it at the login screen with ERROR #134.  Toolhelp is not a debugger.

    python tools/modwatch.py <pid> [seconds=240] [interval=0.1]
"""
import ctypes
import ctypes.wintypes as w
import sys
import time

TH32CS_SNAPMODULE = 0x08
TH32CS_SNAPMODULE32 = 0x10
TH32CS_SNAPPROCESS = 0x02
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
INVALID = ctypes.c_void_p(-1).value

k32 = ctypes.WinDLL("kernel32", use_last_error=True)


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD), ("th32ModuleID", w.DWORD),
                ("th32ProcessID", w.DWORD), ("GlblcntUsage", w.DWORD),
                ("ProccntUsage", w.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", w.DWORD), ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_char * 256),
                ("szExePath", ctypes.c_char * 260)]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD),
                ("th32ProcessID", w.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", w.DWORD), ("cntThreads", w.DWORD),
                ("th32ParentProcessID", w.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", w.DWORD), ("szExeFile", ctypes.c_char * 260)]


k32.CreateToolhelp32Snapshot.restype = w.HANDLE
k32.OpenProcess.restype = w.HANDLE


def modules(pid):
    """name -> (base, size).  Empty dict if the snapshot fails (process gone)."""
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                        pid)
    if snap == INVALID:
        return {}
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(me)
    out = {}
    if k32.Module32First(snap, ctypes.byref(me)):
        while True:
            base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value or 0
            out[me.szModule.decode("latin-1")] = (base, me.modBaseSize)
            if not k32.Module32Next(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return out


def find_proc(name_lower):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID:
        return 0
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(pe)
    found = 0
    if k32.Process32First(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.decode("latin-1").lower() == name_lower:
                found = pe.th32ProcessID
                break
            if not k32.Process32Next(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return found


def alive(pid):
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    code = w.DWORD(0)
    ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
    k32.CloseHandle(h)
    return bool(ok) and code.value == 259


# Anything in this set gets called out loudly in the log -- these are the
# modules that decide between hypothesis (a) and (b).
INTERESTING = ("mscoree.dll", "mscoreei.dll", "clr.dll", "clrjit.dll",
               "mscorlib.ni.dll", "system.ni.dll", "vcruntime140_clr0400.dll",
               "ucrtbase_clr0400.dll", "dbghelp.dll", "dbgcore.dll",
               "imagehlp.dll", "extensions.dll", "discord_game_sdk.dll")


def stamp(t0):
    return "%8.3fs %s" % (time.time() - t0, time.strftime("%H:%M:%S"))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    pid = int(sys.argv[1])
    limit = float(sys.argv[2]) if len(sys.argv) > 2 else 240.0
    every = float(sys.argv[3]) if len(sys.argv) > 3 else 0.1

    t0 = time.time()
    seen = {}
    first = modules(pid)
    seen.update(first)
    print("%s BASELINE: %d modules already loaded" % (stamp(t0), len(first)))
    sys.stdout.flush()

    wowerr = 0
    order = []
    while time.time() - t0 < limit:
        cur = modules(pid)
        if cur:
            for name, (base, size) in cur.items():
                if name not in seen:
                    seen[name] = (base, size)
                    order.append((time.time() - t0, name))
                    mark = " <<<<<" if name.lower() in INTERESTING else ""
                    print("%s LOAD  %-34s base=%08X %6.1f MB%s"
                          % (stamp(t0), name, base, size / 1048576.0, mark))
                    sys.stdout.flush()
            for name in list(seen):
                if name not in cur:
                    del seen[name]
                    print("%s UNLOAD %s" % (stamp(t0), name))
                    sys.stdout.flush()
        if not wowerr:
            wowerr = find_proc("wowerror.exe")
            if wowerr:
                print("%s *** WowError.exe APPEARED (pid %d) -- the client's "
                      "crash handler has written its report by now"
                      % (stamp(t0), wowerr))
                sys.stdout.flush()
        if not alive(pid):
            print("%s *** client process EXITED" % stamp(t0))
            break
        time.sleep(every)

    print("")
    print("=== load order (offset from watch start) ===")
    for t, name in order:
        mark = " <<<<<" if name.lower() in INTERESTING else ""
        print("  %8.3fs  %s%s" % (t, name, mark))


if __name__ == "__main__":
    main()
