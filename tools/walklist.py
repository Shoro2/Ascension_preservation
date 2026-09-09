# -*- coding: utf-8 -*-
r"""Read-only walk of the Extensions.dll callback list the 0x00403340 hook iterates.

The hook installed over Ascension.exe!0x00403340 is:
    edi = [0x6EC629D0]; esi = [edi]
    while esi != edi: call [esi+8]; esi = [esi]
-- a circular list whose head doubles as the sentinel.  ERROR #132 cause (3) is a
`call eax` in that loop with a garbage callback, so print every node and say which
module its callback lands in.  A node whose [+8] is in no module is the crash.

  python tools\walklist.py <pid> [headVA] [--watch]

--watch re-reads every 200ms until the process dies, printing only when the list
changes or a bad callback appears -- the crash is ~1s after world entry, so a
one-shot read almost always misses it.
"""
import ctypes, ctypes.wintypes as w, subprocess, sys, struct, time

argv = [a for a in sys.argv[1:] if not a.startswith("--")]
WATCH = "--watch" in sys.argv
pid = int(argv[0])
HEAD_PTR = int(argv[1], 16) if len(argv) > 1 else 0x6EC629D0

PROCESS_VM_READ, PROCESS_QUERY_INFORMATION = 0x0010, 0x0400
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = w.HANDLE
k32.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not h:
    sys.exit("OpenProcess(%d) failed: %d" % (pid, ctypes.get_last_error()))

def u32(va):
    b = ctypes.create_string_buffer(4); got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, w.LPCVOID(va), b, 4, ctypes.byref(got)):
        return None
    return struct.unpack("<I", b.raw)[0] if got.value == 4 else None

# NOTE 2026-09-02: this used to format with '{0}\`t{1}...'.  A backtick is NOT an
# escape inside a PowerShell SINGLE-quoted string, so every line came back with a
# literal "`t" in it, the split found one field, `mods` stayed EMPTY, and where()
# then labelled all 16 callbacks "*** NOT IN ANY MODULE ***" -- which reads as a
# real finding about unmapped code and is not one.  '|' needs no escaping and
# cannot occur in a module name.
mods = []
ps = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
    "Get-Process -Id %d | %%{$_.Modules} | %%{'{0}|{1}|{2}' -f "
    "$_.ModuleName,$_.BaseAddress.ToInt64(),$_.ModuleMemorySize}" % pid],
    capture_output=True, text=True).stdout
for line in ps.splitlines():
    p = line.strip().split("|")
    if len(p) == 3:
        try: mods.append((int(p[1]), int(p[1]) + int(p[2]), p[0]))
        except ValueError: pass
mods.sort()
if not mods:
    print("WARNING: the module list is EMPTY -- every address below will read as "
          "'NOT IN ANY MODULE'.  That is this tool failing, not a finding.")

def where(va):
    if not va:
        return "NULL"
    for lo, hi, nm in mods:
        if lo <= va < hi:
            return "%s+0x%X" % (nm, va - lo)
    return "*** NOT IN ANY MODULE ***"

def snapshot():
    head = u32(HEAD_PTR)
    if not head:
        return None, []
    nodes, node, seen = [], u32(head), set()
    while node and node != head and len(nodes) < 4000:
        if node in seen:
            nodes.append((node, None, "CYCLE")); break
        seen.add(node)
        cb = u32(node + 8)
        nodes.append((node, cb, where(cb or 0)))
        node = u32(node)
    return head, nodes

def report(head, nodes, why):
    bad = [n for n in nodes if "NOT IN ANY" in n[2] or n[2] in ("NULL", "CYCLE")]
    print("[%s] %s: head=0x%08X  %d node(s), %d bad"
          % (time.strftime("%H:%M:%S"), why, head or 0, len(nodes), len(bad)))
    for i, (node, cb, tag) in enumerate(nodes):
        mark = "   <<<<<< BAD" if (node, cb, tag) in bad else ""
        if len(nodes) <= 40 or mark:
            print("   [%3d] node=0x%08X cb=0x%08X %s%s" % (i, node, cb or 0, tag, mark))
    sys.stdout.flush()

if not WATCH:
    head, nodes = snapshot()
    report(head, nodes, "one-shot")
else:
    print("watching pid %d (head ptr 0x%08X); ctrl-c or process exit ends it"
          % (pid, HEAD_PTR)); sys.stdout.flush()
    last = None
    while True:
        if u32(0x00400000) is None:            # process gone
            print("[%s] process exited" % time.strftime("%H:%M:%S")); break
        head, nodes = snapshot()
        key = (head, tuple((n, c) for n, c, _ in nodes))
        if key != last:
            report(head, nodes, "changed")
            last = key
        time.sleep(0.2)
k32.CloseHandle(h)
