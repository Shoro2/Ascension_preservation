# -*- coding: utf-8 -*-
"""Read-only address-space census of a 32-bit client process.

Why this exists
---------------
`ERROR #132` cause (3) -- the zone-in access violation on a *varying* garbage
pointer -- looks exactly like an unchecked allocation failure: the client asks
for memory, gets NULL/junk back, stores it in a callback slot and later CALLs
it.  The crash reports show it living at 1.76-1.83 GB.

There is a contradiction to resolve here, and it decides the whole fix:
Ascension.exe DOES carry IMAGE_FILE_LARGE_ADDRESS_AWARE (Characteristics
0x0123), so on 64-bit Windows it should get ~4 GB -- but the client's own crash
report prints `Max App Address: 0x7FFEFFFF`, i.e. 2 GB.  Only one of those can
be true of the running process, so this walks the FULL range and reports the
two halves separately instead of assuming either answer.

The number that actually decides whether an allocation fails is not "how much
is committed" but **the largest contiguous FREE block**.  A process can be at
"only" 1.7 GB and still fail a 32 MB request if the remaining 300 MB is
shredded into small holes.  This walks VirtualQueryEx and reports exactly that.

Strictly read-only: opens PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only.
There is deliberately no WriteProcessMemory / VirtualAllocEx / VirtualProtectEx
import anywhere in this file -- see HANDOFF section 8.

Usage
-----
    python tools/vmwalk.py <pid>                one census, human readable
    python tools/vmwalk.py <pid> --csv          one line, machine readable
    python tools/vmwalk.py <pid> --watch [sec]  census every <sec> (default 1)
                                                until the process exits
"""
import ctypes
import ctypes.wintypes as w
import sys
import time

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

k32 = ctypes.WinDLL("kernel32", use_last_error=True)


class MBI(ctypes.Structure):
    """MEMORY_BASIC_INFORMATION as a 64-bit caller sees it (48 bytes).

    We are a 64-bit python querying a WOW64 target, so this is the 64-bit
    layout even though every address that comes back fits in 32 bits.
    """
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", w.DWORD),
        ("__alignment1", w.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", w.DWORD),
        ("Protect", w.DWORD),
        ("Type", w.DWORD),
        ("__alignment2", w.DWORD),
    ]


k32.OpenProcess.restype = w.HANDLE
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_ulonglong,
                               ctypes.POINTER(MBI), ctypes.c_size_t]

# Walk the FULL 32-bit range, not just the low 2 GB.  Ascension.exe HAS the
# IMAGE_FILE_LARGE_ADDRESS_AWARE bit set (Characteristics 0x0123), so on 64-bit
# Windows it is entitled to ~4 GB -- yet its own crash report prints
# "Max App Address: 0x7FFEFFFF" (2 GB).  Stopping the walk at 2 GB cannot tell
# those two worlds apart and silently manufactures a "full address space".
# Account for the halves separately so the answer is unambiguous.
USER_LIMIT = 0xFFFF0000
SPLIT = 0x80000000


def census(h):
    """Walk the whole user address range once.  Returns a dict of MB figures."""
    out = {"commit": 0, "reserve": 0, "free": 0,
           "image": 0, "mapped": 0, "private": 0,
           "largest_free": 0, "free_blocks": 0, "regions": 0,
           "lo_free": 0, "hi_free": 0, "hi_commit": 0, "lo_largest": 0}
    addr = 0
    mbi = MBI()
    while addr < USER_LIMIT:
        got = k32.VirtualQueryEx(h, ctypes.c_ulonglong(addr),
                                 ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not got:
            break
        size = int(mbi.RegionSize)
        if size <= 0:
            break
        out["regions"] += 1
        if mbi.State == MEM_FREE:
            out["free"] += size
            out["free_blocks"] += 1
            if size > out["largest_free"]:
                out["largest_free"] = size
            # A single FREE region can straddle the 2 GB line -- the very first
            # census printed lo_free 2984 MB, which is impossible for a 2 GB
            # half.  Credit each half only the bytes that actually fall in it,
            # and size the "largest hole" the allocator could use below 2 GB
            # from the CLIPPED length, not the whole region.
            lo = max(addr, 0)
            hi = addr + size
            lo_len = max(0, min(hi, SPLIT) - lo)
            hi_len = max(0, hi - max(lo, SPLIT))
            if lo_len:
                out["lo_free"] += lo_len
                if lo_len > out["lo_largest"]:
                    out["lo_largest"] = lo_len
            if hi_len:
                out["hi_free"] += hi_len
        elif mbi.State == MEM_COMMIT:
            out["commit"] += size
            if addr >= SPLIT:
                out["hi_commit"] += size
            if mbi.Type == MEM_IMAGE:
                out["image"] += size
            elif mbi.Type == MEM_MAPPED:
                out["mapped"] += size
            else:
                out["private"] += size
        elif mbi.State == MEM_RESERVE:
            out["reserve"] += size
        addr += size
    for k in ("commit", "reserve", "free", "image", "mapped", "private",
              "largest_free", "lo_free", "hi_free", "hi_commit", "lo_largest"):
        out[k] = out[k] / (1024.0 * 1024.0)
    return out


def alive(h):
    code = w.DWORD(0)
    if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
        return False
    return code.value == 259          # STILL_ACTIVE


COLS = ("commit", "reserve", "free", "largest_free",
        "image", "mapped", "private", "free_blocks", "regions",
        "lo_free", "lo_largest", "hi_free", "hi_commit")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    pid = int(sys.argv[1])
    rest = sys.argv[2:]
    watch = "--watch" in rest
    csv = "--csv" in rest or watch
    every = 1.0
    for a in rest:
        if a not in ("--watch", "--csv"):
            every = float(a)

    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        False, pid)
    if not h:
        sys.exit("OpenProcess(%d) failed: %d" % (pid, ctypes.get_last_error()))

    if csv:
        print("time," + ",".join(COLS))
        sys.stdout.flush()

    while True:
        c = census(h)
        if csv:
            print("%s,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%d,%d,%.1f,%.1f,%.1f,%.1f"
                  % (time.strftime("%H:%M:%S"), c["commit"], c["reserve"],
                     c["free"], c["largest_free"], c["image"], c["mapped"],
                     c["private"], c["free_blocks"], c["regions"],
                     c["lo_free"], c["lo_largest"], c["hi_free"],
                     c["hi_commit"]))
        else:
            print("pid %d address-space census" % pid)
            print("  committed      %8.1f MB   (image %.1f / mapped %.1f / private %.1f)"
                  % (c["commit"], c["image"], c["mapped"], c["private"]))
            print("  reserved       %8.1f MB" % c["reserve"])
            print("  free           %8.1f MB   in %d block(s)"
                  % (c["free"], c["free_blocks"]))
            print("  LARGEST FREE   %8.1f MB   <-- an allocation bigger than this fails"
                  % c["largest_free"])
            print("  --- is the process really capped at 2 GB? ---")
            print("  below 2 GB     free %8.1f MB, largest hole %.1f MB"
                  % (c["lo_free"], c["lo_largest"]))
            print("  above 2 GB     free %8.1f MB, committed %.1f MB"
                  % (c["hi_free"], c["hi_commit"]))
            if c["hi_free"] < 1.0 and c["hi_commit"] < 1.0:
                print("  VERDICT: nothing above 2 GB at all -> LAA is NOT in effect,"
                      " the process is capped at 2 GB.")
            elif c["hi_commit"] > 1.0:
                print("  VERDICT: the client IS allocating above 2 GB -> LAA is live,"
                      " so a full low half is not the ceiling.")
            else:
                print("  VERDICT: high half is free but unused -> LAA is available;"
                      " exhaustion of the low half alone should not be fatal.")
        sys.stdout.flush()
        if not watch:
            break
        if not alive(h):
            print("# process exited")
            break
        time.sleep(every)


if __name__ == "__main__":
    main()
