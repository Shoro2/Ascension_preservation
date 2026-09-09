"""Read-only check: can we resolve Extensions.dll base in a running 32-bit
Ascension.exe from 64-bit Python?  No attach, no writes - purely diagnostic, to
learn whether base resolution (and thus the trace) needs an elevated shell."""
import ctypes, ctypes.wintypes as wt, sys, time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
DWORD, HANDLE, BOOL = wt.DWORD, wt.HANDLE, wt.BOOL

pid = int(sys.argv[1]) if len(sys.argv) > 1 else 16940

# --- method 1: Toolhelp SNAPMODULE32, with retries on ERROR_PARTIAL_COPY(299)
class ME32(ctypes.Structure):
    _fields_ = [("dwSize", DWORD), ("th32ModuleID", DWORD),
                ("th32ProcessID", DWORD), ("GlblcntUsage", DWORD),
                ("ProccntUsage", DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", DWORD), ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_char * 256),
                ("szExePath", ctypes.c_char * 260)]
k32.CreateToolhelp32Snapshot.restype = HANDLE
k32.Module32First.argtypes = [HANDLE, ctypes.POINTER(ME32)]
k32.Module32Next.argtypes = [HANDLE, ctypes.POINTER(ME32)]
INVALID = ctypes.c_void_p(-1).value

print("PID", pid)
for attempt in range(8):
    snap = k32.CreateToolhelp32Snapshot(0x8 | 0x10, pid)
    err = ctypes.get_last_error()
    if snap and snap != INVALID:
        me = ME32(); me.dwSize = ctypes.sizeof(me)
        names = []
        ok = k32.Module32First(snap, ctypes.byref(me))
        base = None
        while ok:
            nm = me.szModule.decode(errors="replace")
            names.append(nm)
            if nm.lower() == "extensions.dll":
                base = me.modBaseAddr
            ok = k32.Module32Next(snap, ctypes.byref(me))
        k32.CloseHandle(snap)
        print("  toolhelp attempt %d: %d modules; Extensions.dll base = %s"
              % (attempt, len(names), ("0x%08X" % base) if base else "NOT FOUND"))
        if base:
            print("  first modules:", ", ".join(names[:6]))
            break
    else:
        print("  toolhelp attempt %d: snapshot FAILED err=%d" % (attempt, err))
    time.sleep(0.3)

# --- method 2: OpenProcess + EnumProcessModulesEx(LIST_MODULES_32BIT)
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
print("OpenProcess ->", ("0x%X" % h) if h else "FAILED err=%d" % ctypes.get_last_error())
if h:
    arr = (ctypes.c_void_p * 1024)()
    needed = DWORD(0)
    LIST_MODULES_32BIT = 0x01
    ok = psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr),
                                    ctypes.byref(needed), LIST_MODULES_32BIT)
    if ok:
        n = needed.value // ctypes.sizeof(ctypes.c_void_p)
        print("  EnumProcessModulesEx: %d modules" % n)
        buf = ctypes.create_unicode_buffer(260)
        for i in range(n):
            psapi.GetModuleBaseNameW(h, arr[i], buf, 260)
            if buf.value.lower() == "extensions.dll":
                print("  Extensions.dll base = 0x%08X" % (arr[i] or 0))
    else:
        print("  EnumProcessModulesEx FAILED err=%d" % ctypes.get_last_error())
    k32.CloseHandle(h)
