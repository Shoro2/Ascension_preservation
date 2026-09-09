# -*- coding: utf-8 -*-
"""Read-only: WHO grows the client's address space, and WHEN?

vmwalk.py answers "how much is left".  vmtop.py answers "who holds it, right
now".  Neither answers the question the ERROR #132 zone-in crash actually
poses, which is *when* the low 2 GB fills and *which allocation* fills it.

The measured shape of the failure:

    21:09:23  commit 1593 MB  private 1453  lo_free 327.4  lo_largest 132.0
    21:09:32  commit 1921 MB  private 1740  lo_free  41.7  lo_largest   5.6
    21:09:33  commit 1952 MB  private 1750  lo_free  36.8  lo_largest   1.6  <- death

so ~300 MB arrives in the ~10 s of world entry and takes the largest usable
low hole from 132 MB to 1.6 MB.  Something in that 300 MB is the disease.
Note also that `image` steps 128.3 -> 168.8 MB in the same second, which is
the .NET CLR + its NGEN images arriving, and `hi_commit` steps 0.2 -> 53.0 MB,
i.e. the process starts using the half above 2 GB for the first time at
exactly the moment it dies with EIP in that half.

This snapshots every region, grouped by AllocationBase, on an interval, and at
the end reports the deltas: what was new, what grew, on which side of the 2 GB
line, and which snapshot the low half collapsed in.

Strictly read-only: PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only.  There is
deliberately no WriteProcessMemory / VirtualAllocEx / VirtualProtectEx import
anywhere in this file -- see HANDOFF section 8.

    python tools/vmgrow.py <pid> [interval=0.5] [maxsec=300]
"""
import ctypes
import ctypes.wintypes as w
import sys
import time

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT, MEM_RESERVE, MEM_FREE = 0x1000, 0x2000, 0x10000
MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE = 0x1000000, 0x40000, 0x20000
USER_LIMIT = 0xFFFF0000
SPLIT = 0x80000000
MB = 1024.0 * 1024.0

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

# GetMappedFileNameW lives in psapi.dll; kernel32 only re-exports it on some
# builds, so resolve it from whichever module actually has it (same dance as
# vmtop.py).
_GMFN = None
for _dll in ("psapi", "kernel32"):
    try:
        _c = ctypes.WinDLL(_dll, use_last_error=True)
        _f = _c.GetMappedFileNameW
        _f.restype = w.DWORD
        _f.argtypes = [w.HANDLE, ctypes.c_ulonglong, ctypes.c_wchar_p, w.DWORD]
        _GMFN = _f
        break
    except AttributeError:
        continue


def mapped_name(h, addr):
    if _GMFN is None:
        return ""
    buf = ctypes.create_unicode_buffer(512)
    if not _GMFN(h, ctypes.c_ulonglong(addr), buf, 512):
        return ""
    return buf.value.rsplit(chr(92), 1)[-1]


def snapshot(h):
    """One full walk.  Returns (groups, summary).

    groups: allocbase -> [commit, reserve, type, nregions, execprot]
    Executable protections are tracked separately because a JIT / hook
    trampoline heap is exactly a PRIVATE group with PAGE_EXECUTE_* on it, and
    that is the kind of allocation the crash implicates.
    """
    groups = {}
    s = {"commit": 0, "reserve": 0, "free": 0, "image": 0, "mapped": 0,
         "private": 0, "lo_free": 0, "lo_largest": 0, "hi_free": 0,
         "hi_commit": 0, "exec_priv": 0}
    addr = 0
    mbi = MBI()
    while addr < USER_LIMIT:
        if not k32.VirtualQueryEx(h, ctypes.c_ulonglong(addr),
                                  ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = int(mbi.RegionSize)
        if size <= 0:
            break
        state, typ, prot = mbi.State, int(mbi.Type), int(mbi.Protect)
        if state == MEM_FREE:
            s["free"] += size
            lo_len = max(0, min(addr + size, SPLIT) - addr)
            hi_len = max(0, (addr + size) - max(addr, SPLIT))
            s["lo_free"] += lo_len
            s["hi_free"] += hi_len
            if lo_len > s["lo_largest"]:
                s["lo_largest"] = lo_len
        else:
            ab = int(mbi.AllocationBase) or addr
            g = groups.setdefault(ab, [0, 0, typ, 0, 0])
            g[3] += 1
            if prot & 0xF0:                      # any PAGE_EXECUTE_*
                g[4] |= prot
            if state == MEM_COMMIT:
                g[0] += size
                s["commit"] += size
                if addr >= SPLIT:
                    s["hi_commit"] += size
                if typ == MEM_IMAGE:
                    s["image"] += size
                elif typ == MEM_MAPPED:
                    s["mapped"] += size
                else:
                    s["private"] += size
                    if prot & 0xF0:
                        s["exec_priv"] += size
            else:
                g[1] += size
                s["reserve"] += size
        addr += size
    return groups, s


def alive(h):
    code = w.DWORD(0)
    if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
        return False
    return code.value == 259


TNAME = {MEM_IMAGE: "IMAGE", MEM_MAPPED: "MAPPED", MEM_PRIVATE: "PRIVATE"}


def report(h, shots):
    if len(shots) < 2:
        print("not enough snapshots to diff")
        return
    print("")
    print("=== TIMELINE (MB) ===")
    print("%-9s %9s %9s %9s %9s %9s %9s %9s"
          % ("time", "commit", "private", "image", "lo_free", "lo_lgst",
             "hi_cmt", "xpriv"))
    prev_lo = None
    collapse = None
    for i, (t, _g, s) in enumerate(shots):
        print("%-9s %9.1f %9.1f %9.1f %9.1f %9.1f %9.1f %9.1f"
              % (t, s["commit"] / MB, s["private"] / MB, s["image"] / MB,
                 s["lo_free"] / MB, s["lo_largest"] / MB,
                 s["hi_commit"] / MB, s["exec_priv"] / MB))
        if collapse is None and prev_lo is not None:
            if prev_lo >= 16 * 1024 * 1024 > s["lo_largest"]:
                collapse = i
        prev_lo = s["lo_largest"]

    def diff(a_idx, b_idx, title):
        ga = shots[a_idx][1]
        tb, gb = shots[b_idx][0], shots[b_idx][1]
        print("")
        print("=== %s : %s -> %s ===" % (title, shots[a_idx][0], tb))
        rows = []
        for ab, g in gb.items():
            old = ga.get(ab)
            d = (g[0] + g[1]) - ((old[0] + old[1]) if old else 0)
            if d > 256 * 1024:
                rows.append((d, ab, g, old is None))
        rows.sort(reverse=True)
        if not rows:
            print("  (nothing grew by more than 256 KB)")
            return
        print("  %-12s %9s %-8s %-5s %-5s %s"
              % ("allocbase", "delta MB", "type", "half", "X", "backing"))
        for d, ab, g, isnew in rows[:30]:
            name = ""
            if g[2] in (MEM_IMAGE, MEM_MAPPED):
                name = mapped_name(h, ab)
            print("  0x%08X %9.1f %-8s %-5s %-5s %s%s"
                  % (ab, d / MB, TNAME.get(g[2], str(g[2])),
                     "HIGH" if ab >= SPLIT else "low",
                     "EXEC" if g[4] else "", "NEW " if isnew else "", name))

    diff(0, len(shots) - 1, "TOTAL GROWTH (first -> last)")
    if collapse:
        diff(collapse - 1, collapse, "THE SNAPSHOT THE LOW HALF COLLAPSED IN")
    else:
        print("")
        print("(the low half never dropped below a 16 MB largest hole here)")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    pid = int(sys.argv[1])
    every = float(sys.argv[2]) if len(sys.argv) > 2 else 0.5
    maxsec = float(sys.argv[3]) if len(sys.argv) > 3 else 300.0

    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        sys.exit("OpenProcess(%d) failed: %d" % (pid, ctypes.get_last_error()))

    shots = []
    t0 = time.time()
    print("watching pid %d every %.2fs" % (pid, every))
    sys.stdout.flush()
    while time.time() - t0 < maxsec:
        g, s = snapshot(h)
        shots.append((time.strftime("%H:%M:%S"), g, s))
        if not alive(h):
            print("# process exited after %d snapshot(s)" % len(shots))
            break
        time.sleep(every)
    report(h, shots)


if __name__ == "__main__":
    main()
