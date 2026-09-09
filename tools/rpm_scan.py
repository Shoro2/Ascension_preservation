"""Read-only memory scan of the Ascension client for realm-list strings.

Same permission surface as rpm_readk.py: OpenProcess(PROCESS_VM_READ) + ReadProcessMemory
only -- no writes, no patching, no debugger. It enumerates committed readable regions
(VirtualQueryEx) and searches for the given realm strings so we can tell whether OUR
'[Ascension-Local]' realm made it into the client's parsed realm list (=> our wire format is
accepted, realm just hidden on the GM 'dev' page) or is absent (=> format rejected), and where
the 6 Ascension realms actually live (heap vs. image/hardcoded).

MUST run ELEVATED (the client is Administrator; medium integrity => OpenProcess err 5).
Usage:  python rpm_scan.py
"""
import ctypes, sys
from ctypes import wintypes as w

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
READABLE = {0x02, 0x04, 0x20, 0x40, 0x80}  # RO, RW, EXEC_R, EXEC_RW, EXEC_WC
INVALID = ctypes.c_void_p(-1).value

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

TH32CS_SNAPPROCESS = 0x2
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD),
                ("th32ProcessID", w.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", w.DWORD), ("cntThreads", w.DWORD),
                ("th32ParentProcessID", w.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", w.DWORD), ("szExeFile", ctypes.c_char * 260)]

class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", w.DWORD), ("__align", w.DWORD),
                ("RegionSize", ctypes.c_ulonglong), ("State", w.DWORD),
                ("Protect", w.DWORD), ("Type", w.DWORD), ("__align2", w.DWORD)]

def find_pids(exe=b"ascension.exe"):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID: return []
    out = []
    try:
        pe = PROCESSENTRY32(); pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if not k32.Process32First(snap, ctypes.byref(pe)): return []
        while True:
            if pe.szExeFile.lower() == exe:
                out.append(pe.th32ProcessID)
            if not k32.Process32Next(snap, ctypes.byref(pe)): break
    finally:
        k32.CloseHandle(snap)
    return out

def scan(pid, targets):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        print("  OpenProcess failed err=%d (run ELEVATED)" % ctypes.get_last_error()); return
    VirtualQueryEx = k32.VirtualQueryEx
    VirtualQueryEx.restype = ctypes.c_size_t
    Read = k32.ReadProcessMemory
    hits = {name: [] for name, _ in targets}
    addr = 0x10000
    limit = 0x7FFF0000
    mbi = MEMORY_BASIC_INFORMATION64()
    total_read = 0
    while addr < limit:
        r = VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if r == 0:
            addr += 0x1000; continue
        base = mbi.BaseAddress; size = int(mbi.RegionSize)
        nxt = base + size
        prot = mbi.Protect & 0xFF
        ok = (mbi.State == MEM_COMMIT and prot in READABLE
              and not (mbi.Protect & PAGE_GUARD))
        if ok and size and size <= 0x8000000:
            buf = (ctypes.c_char * size)()
            got = ctypes.c_size_t(0)
            if Read(h, ctypes.c_void_p(base), buf, size, ctypes.byref(got)) and got.value:
                data = bytes(buf[:got.value]); total_read += got.value
                for name, pat in targets:
                    start = 0
                    while True:
                        j = data.find(pat, start)
                        if j < 0: break
                        ctx = data[max(0, j-4):j+len(pat)+48]
                        hits[name].append((base + j, ctx))
                        start = j + 1
                        if len(hits[name]) > 40: break
        if nxt <= addr: addr += 0x1000
        else: addr = nxt
    k32.CloseHandle(h)
    print("  scanned ~%.0f MB of committed memory" % (total_read / 1e6))
    for name, _ in targets:
        hl = hits[name]
        print("\n  [%s]  %d hit(s)" % (name, len(hl)))
        for a, ctx in hl[:10]:
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in ctx)
            print("     0x%08x  %s" % (a, printable))
        if len(hl) > 10:
            print("     ... +%d more" % (len(hl) - 10))

def main():
    # ASCII + UTF-16LE forms of each realm string
    raw = ["[Ascension-Local]", "Ascension Archive", "Free-Pick", "Free Pick",
           "Conquest of Azeroth", "Rexxar", "Vol'jin", "Area 52",
           "127.0.0.1:8085", "127.0.0.1:3799", "127.0.0.1", "logon.ascension"]
    targets = []
    for s in raw:
        targets.append((s + " (A)", s.encode("latin1")))
        targets.append((s + " (W)", s.encode("utf-16-le")))
    pids = find_pids()
    print("Ascension.exe PIDs:", pids or "NONE (client not running)")
    for pid in pids:
        print("\n=== pid %d ===" % pid)
        scan(pid, targets)

if __name__ == "__main__":
    main()
