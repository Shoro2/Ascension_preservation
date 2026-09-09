# -*- coding: utf-8 -*-
"""Read-only: WHERE is a 32-bit client's address space going?

vmwalk.py answers "how much is left"; this answers "who took it".  Regions are
grouped by AllocationBase (one VirtualAlloc/mapping = one group) so a single
600 MB reservation does not show up as 300 anonymous 2 MB rows.

Strictly read-only -- PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only, and no
WriteProcessMemory / VirtualAllocEx / VirtualProtectEx import exists in this
file (HANDOFF section 8).

    python tools/vmtop.py <pid> [topN]
"""
import ctypes
import ctypes.wintypes as w
import sys

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT, MEM_RESERVE, MEM_FREE = 0x1000, 0x2000, 0x10000
MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE = 0x1000000, 0x40000, 0x20000
USER_LIMIT = 0xFFFF0000

k32 = ctypes.WinDLL("kernel32", use_last_error=True)


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong),
                ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", w.DWORD), ("__a1", w.DWORD),
                ("RegionSize", ctypes.c_ulonglong),
                ("State", w.DWORD), ("Protect", w.DWORD),
                ("Type", w.DWORD), ("__a2", w.DWORD)]


k32.OpenProcess.restype = w.HANDLE
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_ulonglong,
                               ctypes.POINTER(MBI), ctypes.c_size_t]


_PSAPI = None
for _dll in ("psapi", "kernel32"):
    try:
        _cand = ctypes.WinDLL(_dll, use_last_error=True)
        _fn = _cand.GetMappedFileNameW
        _fn.restype = w.DWORD
        _fn.argtypes = [w.HANDLE, ctypes.c_ulonglong,
                        ctypes.c_wchar_p, w.DWORD]
        _PSAPI = _fn
        break
    except AttributeError:
        continue


def mapped_name(h, addr):
    """Best-effort backing file for a mapped/image region ('' if anonymous).

    GetMappedFileNameW lives in psapi.dll (kernel32 only re-exports it on some
    builds), so it is resolved once, from whichever module actually has it.
    """
    if _PSAPI is None:
        return ""
    buf = ctypes.create_unicode_buffer(512)
    n = _PSAPI(h, ctypes.c_ulonglong(addr), buf, 512)
    return buf.value if n else ""


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    pid = int(sys.argv[1])
    topn = int(sys.argv[2]) if len(sys.argv) > 2 else 25

    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        sys.exit("OpenProcess(%d) failed: %d" % (pid, ctypes.get_last_error()))

    groups = {}          # AllocationBase -> [committed, reserved, type, nregions]
    tot_c = tot_r = 0
    addr = 0
    mbi = MBI()
    while addr < USER_LIMIT:
        if not k32.VirtualQueryEx(h, ctypes.c_ulonglong(addr),
                                  ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = int(mbi.RegionSize)
        if size <= 0:
            break
        if mbi.State != MEM_FREE:
            ab = int(mbi.AllocationBase) or int(mbi.BaseAddress)
            g = groups.setdefault(ab, [0, 0, int(mbi.Type), 0])
            g[3] += 1
            if mbi.State == MEM_COMMIT:
                g[0] += size
                tot_c += size
            else:
                g[1] += size
                tot_r += size
        addr += size

    mb = 1024.0 * 1024.0
    tname = {MEM_IMAGE: "IMAGE", MEM_MAPPED: "MAPPED", MEM_PRIVATE: "PRIVATE"}
    rows = sorted(groups.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))

    print("pid %d  committed %.1f MB  reserved %.1f MB  groups %d"
          % (pid, tot_c / mb, tot_r / mb, len(groups)))
    print("%-12s %10s %10s  %-8s %6s  %s"
          % ("allocbase", "commit MB", "resv MB", "type", "regs", "backing file"))
    for ab, (c, r, t, n) in rows[:topn]:
        name = ""
        if t in (MEM_IMAGE, MEM_MAPPED):
            name = mapped_name(h, ab)
            if name:
                name = name.split("\\")[-1]
        print("0x%08X   %10.1f %10.1f  %-8s %6d  %s"
              % (ab, c / mb, r / mb, tname.get(t, str(t)), n, name))

    # How much of the total is anonymous PRIVATE, and how is it distributed?
    priv = [(c + r, n) for (c, r, t, n) in groups.values() if t == MEM_PRIVATE]
    if priv:
        tot = sum(p[0] for p in priv) / mb
        big = sum(p[0] for p in priv if p[0] >= 16 * 1024 * 1024) / mb
        print("\nPRIVATE total %.1f MB in %d groups; %.1f MB of that is in "
              "groups >= 16 MB, %.1f MB is scattered in smaller ones."
              % (tot, len(priv), big, tot - big))


if __name__ == "__main__":
    main()
